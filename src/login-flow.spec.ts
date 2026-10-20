import { createServer } from 'node:http';
import { type AddressInfo } from 'node:net';

import { Logger } from '@nestjs/common';
import { type Request, type Response } from 'express';
import { decodeProtectedHeader, EncryptJWT } from 'jose';

import { configOf } from './__spec__/fake-config';
import {
  LOGIN_CALLBACK_PATH as CALLBACK_PATH,
  LOGIN_CLIENT_ID as CLIENT_ID,
  LOGIN_ENTRY as ENTRY,
  LOGIN_OPTIONS as OPTIONS,
  LOGIN_STATE_SECRET as SECRET,
  loginEnv,
} from './__spec__/login-fixture';
import { type DeploymentProfile } from './deployment-profile';
import { discoveryUrl, LoginDiscovery } from './login-discovery';
import { type SignetLoginEntry } from './login-entry';
import { SignetLoginError, SignetLoginFailureEnum } from './login-error';
import { SignetLoginFlow } from './login-flow';
import { codeChallenge, loginStateKey } from './login-state';
import { type SignetIntegrationOptions } from './options';
import {
  startTestAuthorizationServer,
  type TestAuthorizationServer,
  type TokenEndpointScript,
} from './testing/authorization-server';
import {
  FIXTURE_DEVELOPMENT_PROFILE,
  FIXTURE_OPTIONS,
} from './testing/fixture';
import { startTestIssuer } from './testing/signet-token';

const PRODUCTION_PROFILE: DeploymentProfile = {
  canonicalResource: 'https://acme.example/mcp',
  environment: 'production',
  host: 'acme.example',
  namespace: 'acme-production',
};

const HTTPS_DISCOVERY = (issuer: string) => ({
  document: {
    authorization_endpoint: 'https://idp.example/oauth2/auth',
    issuer,
    token_endpoint: 'https://idp.example/oauth2/token',
  },
});

describe('SignetLoginFlow', () => {
  let server: TestAuthorizationServer;
  let warn: jest.SpyInstance;
  let logger: Logger;

  beforeAll(async () => {
    server = await startTestAuthorizationServer({ clientId: CLIENT_ID });
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    logger = new Logger('spec');
    jest.spyOn(logger, 'log').mockImplementation();
    warn = jest.spyOn(logger, 'warn').mockImplementation();
    server.reset();
  });

  const build = (
    input: {
      discoveryMs?: number;
      entry?: SignetLoginEntry;
      env?: Record<string, string | undefined>;
      options?: SignetIntegrationOptions;
      profile?: DeploymentProfile;
      tokenMs?: number;
    } = {},
  ) =>
    new SignetLoginFlow(
      input.entry ?? ENTRY,
      configOf(loginEnv(server, input.env)),
      { profile: input.profile ?? FIXTURE_DEVELOPMENT_PROFILE },
      input.options ?? OPTIONS,
      logger,
      {
        discoveryMs: input.discoveryMs ?? 2_000,
        tokenMs: input.tokenMs ?? 2_000,
      },
    );

  // begin() against a fake Express response: the authorization URL (or the
  // refusal) and every Set-Cookie it appended.
  const attemptBegin = async (
    flow: SignetLoginFlow,
    headers: Record<string, string> = {},
  ) => {
    const setCookie: string[] = [];
    const response = {
      append: (name: string, value: string) => {
        expect(name).toBe('Set-Cookie');
        setCookie.push(value);
      },
      req: { headers, ip: '127.0.0.1', path: '/auth/signet' },
    } as unknown as Response;
    const outcome = await flow.begin(response).then(
      (url) => ({ url }),
      (error: unknown) => ({ error }),
    );
    return { ...outcome, setCookie };
  };

  const begin = async (
    flow: SignetLoginFlow,
    headers: Record<string, string> = {},
  ) => {
    const attempt = await attemptBegin(flow, headers);
    if ('error' in attempt) throw attempt.error;
    expect(attempt.setCookie).toHaveLength(1);
    const setCookie = attempt.setCookie[0];
    return { cookie: setCookie.split(';')[0], setCookie, url: attempt.url };
  };

  // The browser arriving at the callback: the IdP's redirect URL, and the
  // cookie it carries.
  const callback = (
    redirectUrl: string,
    cookie?: string,
    query?: Record<string, unknown>,
  ) => {
    const url = new URL(redirectUrl);
    const cleared: string[] = [];
    const request = {
      headers: cookie === undefined ? {} : { cookie },
      ip: '127.0.0.1',
      path: url.pathname,
      query: query ?? Object.fromEntries(url.searchParams),
      res: { append: (_: string, value: string) => cleared.push(value) },
    } as unknown as Request;
    return { cleared, request };
  };

  const rejection = async (promise: Promise<unknown>) => {
    const error: unknown = await promise.then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(SignetLoginError);
    return (error as SignetLoginError).reason;
  };

  const loggedLines = () =>
    warn.mock.calls.map(([line]) => String(line)).join('\n');

  // A cookie sealed with this secret but not by sealLoginState: what only a
  // holder of the key could produce, for the shape checks.
  const sealRaw = (payload: Record<string, unknown>, withExp = true) => {
    const jwt = new EncryptJWT(payload).setProtectedHeader({
      alg: 'dir',
      enc: 'A256GCM',
    });
    return (withExp ? jwt.setExpirationTime('5m') : jwt).encrypt(
      loginStateKey(SECRET, 'spec'),
    );
  };

  describe('begin', () => {
    it('builds the authorization request: code, PKCE S256, the exact redirect URI, the scopes and ONE resource', async () => {
      const { url } = await begin(build());
      const query = new URL(url).searchParams;
      expect(url.startsWith(`${server.issuer}/oauth2/auth?`)).toBe(true);
      expect(query.get('response_type')).toBe('code');
      expect(query.get('client_id')).toBe(CLIENT_ID);
      expect(query.get('redirect_uri')).toBe(ENTRY.redirectUris.development);
      expect(query.get('scope')).toBe('openid acme:access');
      expect(query.getAll('resource')).toEqual([
        FIXTURE_DEVELOPMENT_PROFILE.canonicalResource,
      ]);
      expect(query.get('code_challenge_method')).toBe('S256');
      expect(query.get('code_challenge')).toMatch(/^[\w-]{43}$/);
      expect(query.get('state')).toMatch(/^[\w-]{43}$/);
    });

    it('asks for the entry’s scopes plus the admission scope, once', async () => {
      const { url } = await begin(
        build({
          entry: { ...ENTRY, scopes: ['openid', 'acme:access', 'email'] },
        }),
      );
      expect(new URL(url).searchParams.get('scope')).toBe(
        'openid acme:access email',
      );
    });

    it('takes nothing from the request: a forged Host leaves the URL’s redirect URI alone', async () => {
      const { url } = await begin(build(), {
        host: 'evil.example',
        'x-forwarded-host': 'evil.example',
      });
      expect(new URL(url).searchParams.get('redirect_uri')).toBe(
        ENTRY.redirectUris.development,
      );
    });

    it('sets an encrypted, HttpOnly, Lax state cookie scoped to the callback path', async () => {
      const { setCookie, url } = await begin(build());
      const [pair, ...attributes] = setCookie.split('; ');
      const name = pair.slice(0, pair.indexOf('='));
      const value = pair.slice(pair.indexOf('=') + 1);
      expect(name).toBe('signet_login.acme-login');
      expect(attributes).toEqual([
        `Path=${CALLBACK_PATH}`,
        'Max-Age=600',
        'HttpOnly',
        'SameSite=Lax',
      ]);
      expect(decodeProtectedHeader(value)).toEqual({
        alg: 'dir',
        enc: 'A256GCM',
      });
      // Encrypted: nothing of the login is readable in it.
      expect(value).not.toContain(new URL(url).searchParams.get('state'));
    });

    it('marks the cookie Secure for an https redirect URI, and its clearing too', async () => {
      server.overrideDiscovery(HTTPS_DISCOVERY(server.issuer));
      const flow = build({ profile: PRODUCTION_PROFILE });
      const { setCookie } = await begin(flow);
      expect(setCookie).toContain(`Path=${CALLBACK_PATH}`);
      expect(setCookie.endsWith('; Secure')).toBe(true);
      const { cleared, request } = callback(
        `https://acme.example${CALLBACK_PATH}?error=access_denied&state=x`,
      );
      await rejection(flow.complete(request));
      expect(cleared[0].endsWith('; Secure')).toBe(true);
    });

    it('sets no cookie when discovery fails', async () => {
      server.overrideDiscovery({ status: 503 });
      const attempt = await attemptBegin(build());
      expect('error' in attempt && attempt.error).toBeInstanceOf(
        SignetLoginError,
      );
      expect(attempt.setCookie).toEqual([]);
    });

    it('sets no cookie when the flag is off', async () => {
      const attempt = await attemptBegin(
        build({ env: { ACME_SIGNET_ENABLED: 'false' } }),
      );
      expect('error' in attempt && attempt.error).toBeInstanceOf(
        SignetLoginError,
      );
      expect(attempt.setCookie).toEqual([]);
    });
  });

  describe('complete', () => {
    it('exchanges the code with the PKCE verifier and returns the access token’s verified identity and the ID token’s claims', async () => {
      const flow = build();
      const { cookie, url } = await begin(flow);
      const back = server.authorize(url, {
        claims: { erp: 'e-1' },
        idTokenClaims: { email: 'someone@example.com', email_verified: true },
        subject: 'person-1',
      });
      const { identity, login } = await flow.complete(
        callback(back, cookie).request,
      );
      expect(identity).toMatchObject({
        claims: { erp: 'e-1' },
        clientId: CLIENT_ID,
        scopes: ['openid', 'acme:access'],
        subject: 'person-1',
      });
      // The ID token's claims beside the identity, not mixed into it.
      expect(login.idTokenClaims).toMatchObject({
        aud: [CLIENT_ID],
        email: 'someone@example.com',
        email_verified: true,
        sub: 'person-1',
      });
      expect(Object.isFrozen(login.idTokenClaims)).toBe(true);
      expect(identity.claims).not.toHaveProperty('email');
      const [sent] = server.tokenRequests().slice(-1);
      expect(sent).toMatchObject({
        client_id: CLIENT_ID,
        grant_type: 'authorization_code',
        redirect_uri: ENTRY.redirectUris.development,
      });
      // The verifier is the one whose S256 the authorization request sent:
      // checked here, not left to the test server.
      expect(codeChallenge(sent.code_verifier)).toBe(
        new URL(url).searchParams.get('code_challenge'),
      );
    });

    it('clears the state cookie on the callback, on the same path', async () => {
      const flow = build();
      const { cookie, url } = await begin(flow);
      const { cleared, request } = callback(server.authorize(url), cookie);
      await flow.complete(request);
      expect(cleared).toEqual([
        `signet_login.acme-login=; Path=${CALLBACK_PATH}; Max-Age=0; HttpOnly; SameSite=Lax`,
      ]);
    });

    it('clears it on a refusal too', async () => {
      const flow = build();
      const { cookie, url } = await begin(flow);
      const { cleared, request } = callback(server.deny(url), cookie);
      await rejection(flow.complete(request));
      expect(cleared).toHaveLength(1);
    });

    it('answers CANCELLED for access_denied and IDP_ERROR for any other error, once the state checks out', async () => {
      const flow = build();
      const first = await begin(flow);
      expect(
        await rejection(
          flow.complete(callback(server.deny(first.url), first.cookie).request),
        ),
      ).toBe(SignetLoginFailureEnum.CANCELLED);
      const second = await begin(flow);
      expect(
        await rejection(
          flow.complete(
            callback(server.deny(second.url, 'server_error'), second.cookie)
              .request,
          ),
        ),
      ).toBe(SignetLoginFailureEnum.IDP_ERROR);
      expect(loggedLines()).toContain(
        'metric=signet_login_rejected reason=idp_error detail=server_error entry=acme-login',
      );
    });

    it('checks the state before reading an error: a forged error=access_denied is STATE_INVALID, not CANCELLED', async () => {
      const flow = build();
      const { cookie } = await begin(flow);
      expect(
        await rejection(
          flow.complete(
            callback(
              `http://localhost:3000${CALLBACK_PATH}?error=access_denied&state=forged`,
              cookie,
            ).request,
          ),
        ),
      ).toBe(SignetLoginFailureEnum.STATE_INVALID);
      expect(
        await rejection(
          flow.complete(
            callback(
              `http://localhost:3000${CALLBACK_PATH}?error=access_denied`,
            ).request,
          ),
        ),
      ).toBe(SignetLoginFailureEnum.STATE_INVALID);
      expect(loggedLines()).not.toContain('reason=cancelled');
    });

    it('answers IDP_ERROR for a redirect with neither code nor error', async () => {
      const flow = build();
      const { cookie, url } = await begin(flow);
      const back = new URL(server.authorize(url));
      back.searchParams.delete('code');
      expect(
        await rejection(
          flow.complete(callback(back.toString(), cookie).request),
        ),
      ).toBe(SignetLoginFailureEnum.IDP_ERROR);
    });

    it('keeps the IdP’s error from forging fields, and clips it', async () => {
      const flow = build();
      const first = await begin(flow);
      await rejection(
        flow.complete(
          callback(
            server.deny(first.url, 'x reason=cancelled\nmetric=forged'),
            first.cookie,
          ).request,
        ),
      );
      expect(loggedLines()).toContain(
        'detail=x_reason_cancelled_metric_forged ',
      );
      const second = await begin(flow);
      await rejection(
        flow.complete(
          callback(server.deny(second.url, 'e'.repeat(150)), second.cookie)
            .request,
        ),
      );
      expect(loggedLines()).toContain(`detail=${'e'.repeat(100)}…(truncated)`);
    });

    describe('state', () => {
      it('refuses a state that does not match the cookie’s, before calling the token endpoint', async () => {
        const flow = build();
        const { cookie, url } = await begin(flow);
        const back = new URL(server.authorize(url));
        back.searchParams.set('state', 'someone-elses-state');
        expect(
          await rejection(
            flow.complete(callback(back.toString(), cookie).request),
          ),
        ).toBe(SignetLoginFailureEnum.STATE_INVALID);
        expect(server.tokenRequests()).toHaveLength(0);
        expect(loggedLines()).toContain('reason=state_invalid detail=state ');
      });

      it('names a missing cookie cookie_missing', async () => {
        const flow = build();
        const { url } = await begin(flow);
        expect(
          await rejection(
            flow.complete(callback(server.authorize(url)).request),
          ),
        ).toBe(SignetLoginFailureEnum.STATE_INVALID);
        expect(loggedLines()).toContain('detail=cookie_missing ');
      });

      it('names a tampered cookie unopenable', async () => {
        const flow = build();
        const { cookie, url } = await begin(flow);
        // The second-to-last character, replaced by one it is not: the
        // last carries padding bits a change might not touch.
        const flipped =
          cookie.slice(0, -2) +
          (cookie.at(-2) === 'A' ? 'B' : 'A') +
          cookie.slice(-1);
        expect(
          await rejection(
            flow.complete(callback(server.authorize(url), flipped).request),
          ),
        ).toBe(SignetLoginFailureEnum.STATE_INVALID);
        expect(loggedLines()).toContain('detail=unopenable ');
      });

      it('names a cookie sealed under another secret unopenable -- what replicas with different secrets would show', async () => {
        const other = build({
          env: { ACME_LOGIN_STATE_SECRET: 'another-secret-also-32-bytes-long' },
        });
        const { cookie, url } = await begin(other);
        expect(
          await rejection(
            build().complete(callback(server.authorize(url), cookie).request),
          ),
        ).toBe(SignetLoginFailureEnum.STATE_INVALID);
        expect(loggedLines()).toContain('detail=unopenable ');
      });

      it('names a state issued for another entry, even under this entry’s cookie name, entry', async () => {
        const other = build({ entry: { ...ENTRY, name: 'other-login' } });
        const { cookie, url } = await begin(other);
        const renamed = cookie.replace(
          'signet_login.other-login=',
          'signet_login.acme-login=',
        );
        expect(
          await rejection(
            build().complete(callback(server.authorize(url), renamed).request),
          ),
        ).toBe(SignetLoginFailureEnum.STATE_INVALID);
        expect(loggedLines()).toContain('reason=state_invalid detail=entry ');
      });

      it('names a state older than LOGIN_STATE_TTL_S expired', async () => {
        const flow = build();
        const { cookie, url } = await begin(flow);
        const back = server.authorize(url);
        // Date only: jose reads the clock through new Date().
        jest.useFakeTimers({
          doNotFake: [
            'clearImmediate',
            'clearInterval',
            'clearTimeout',
            'hrtime',
            'nextTick',
            'performance',
            'queueMicrotask',
            'setImmediate',
            'setInterval',
            'setTimeout',
          ],
          now: Date.now() + 11 * 60_000,
        });
        try {
          expect(
            await rejection(flow.complete(callback(back, cookie).request)),
          ).toBe(SignetLoginFailureEnum.STATE_INVALID);
        } finally {
          jest.useRealTimers();
        }
        expect(loggedLines()).toContain('reason=state_invalid detail=expired ');
      });

      it.each([
        ['without the state fields', { entry: 'acme-login' }, true],
        [
          'with a field of the wrong type',
          { entry: 1, state: 's', verifier: 'v' },
          true,
        ],
        [
          'without exp',
          { entry: 'acme-login', state: 's', verifier: 'v' },
          false,
        ],
      ])('names an opened value %s malformed', async (_, payload, withExp) => {
        const sealed = await sealRaw(payload, withExp);
        expect(
          await rejection(
            build().complete(
              callback(
                `http://localhost:3000${CALLBACK_PATH}?code=c&state=s`,
                `signet_login.acme-login=${sealed}`,
              ).request,
            ),
          ),
        ).toBe(SignetLoginFailureEnum.STATE_INVALID);
        expect(loggedLines()).toContain('detail=malformed ');
      });

      it('refuses a repeated state parameter', async () => {
        const flow = build();
        const { cookie, url } = await begin(flow);
        const back = new URL(server.authorize(url));
        const state = back.searchParams.get('state');
        const { request } = callback(back.toString(), cookie, {
          code: back.searchParams.get('code'),
          state: [state, state],
        });
        expect(await rejection(flow.complete(request))).toBe(
          SignetLoginFailureEnum.STATE_INVALID,
        );
      });

      it.each([
        ['after', (stale: string, current: string) => `${stale}; ${current}`],
        // What a browser sends: the longer path first (RFC 6265 §5.4).
        ['before', (stale: string, current: string) => `${current}; ${stale}`],
      ])(
        'accepts the current state with a stale cookie of the same name sent %s it',
        async (_, order) => {
          const flow = build();
          const stale = await begin(flow);
          const { cookie, url } = await begin(flow);
          const { identity } = await flow.complete(
            callback(server.authorize(url), order(stale.cookie, cookie))
              .request,
          );
          expect(identity.subject).toBe('test-user');
        },
      );
      it.each([
        ['after', (bad: string, current: string) => `${bad}; ${current}`],
        ['before', (bad: string, current: string) => `${current}; ${bad}`],
      ])(
        'tries every value: an unopenable cookie of the same name sent %s the current one does not end the login',
        async (_, order) => {
          const leftover = build({
            env: {
              ACME_LOGIN_STATE_SECRET: 'the-secret-before-a-rotation-32b!',
            },
          });
          const bad = (await begin(leftover)).cookie;
          const flow = build();
          const { cookie, url } = await begin(flow);
          const { identity } = await flow.complete(
            callback(server.authorize(url), order(bad, cookie)).request,
          );
          expect(identity.subject).toBe('test-user');
        },
      );

      it.each([
        ['expired first', true, 'expired'],
        ['unopenable first', false, 'unopenable'],
      ])(
        'names the first failure when no value opens (%s)',
        async (_, expiredFirst, detail) => {
          const expired = await new EncryptJWT({
            entry: 'acme-login',
            state: 's',
            verifier: 'v',
          })
            .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
            .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
            .encrypt(loginStateKey(SECRET, 'spec'));
          const values = [
            `signet_login.acme-login=${expired}`,
            'signet_login.acme-login=garbage',
          ];
          if (!expiredFirst) values.reverse();
          expect(
            await rejection(
              build().complete(
                callback(
                  `http://localhost:3000${CALLBACK_PATH}?code=c&state=s`,
                  values.join('; '),
                ).request,
              ),
            ),
          ).toBe(SignetLoginFailureEnum.STATE_INVALID);
          expect(loggedLines()).toContain(`detail=${detail} `);
        },
      );
    });

    describe('token exchange', () => {
      const exchangeFails = async (
        script: TokenEndpointScript,
        tokenMs?: number,
      ) => {
        const flow = build({ tokenMs });
        const { cookie, url } = await begin(flow);
        const back = server.authorize(url);
        server.scriptTokenEndpoint(script);
        return rejection(flow.complete(callback(back, cookie).request));
      };

      it('answers TOKEN_EXCHANGE_FAILED for an OAuth error, logging the status and the error code only', async () => {
        expect(
          await exchangeFails({ error: 'invalid_grant', status: 400 }),
        ).toBe(SignetLoginFailureEnum.TOKEN_EXCHANGE_FAILED);
        expect(loggedLines()).toContain(
          'reason=token_exchange_failed detail=status_400:invalid_grant',
        );
      });

      it('answers TOKEN_EXCHANGE_FAILED for a 5xx without an OAuth error', async () => {
        expect(await exchangeFails({ status: 503 })).toBe(
          SignetLoginFailureEnum.TOKEN_EXCHANGE_FAILED,
        );
        expect(loggedLines()).toContain('detail=status_503:none');
      });

      it('answers TOKEN_EXCHANGE_FAILED for a 200 without an access token', async () => {
        expect(await exchangeFails({ body: { token_type: 'bearer' } })).toBe(
          SignetLoginFailureEnum.TOKEN_EXCHANGE_FAILED,
        );
        expect(loggedLines()).toContain('detail=access_token_missing');
      });

      it('names a proxy’s HTML 502 by its status, no OAuth error', async () => {
        expect(
          await exchangeFails({ raw: '<html>bad gateway</html>', status: 502 }),
        ).toBe(SignetLoginFailureEnum.TOKEN_EXCHANGE_FAILED);
        expect(loggedLines()).toContain('detail=status_502:none ');
      });

      it.each([null, [], 'a string', 42])(
        'treats a 200 whose JSON body is %j, not an object, as a missing token -- a 401, not a crash',
        async (body) => {
          expect(await exchangeFails({ body })).toBe(
            SignetLoginFailureEnum.TOKEN_EXCHANGE_FAILED,
          );
          expect(loggedLines()).toContain('detail=access_token_missing ');
        },
      );

      it('names a 200 whose body is not JSON body_not_json', async () => {
        expect(await exchangeFails({ body: undefined })).toBe(
          SignetLoginFailureEnum.TOKEN_EXCHANGE_FAILED,
        );
        expect(loggedLines()).toContain('detail=body_not_json');
      });

      it('gives up on a token endpoint that does not answer', async () => {
        expect(await exchangeFails({ hang: true }, 200)).toBe(
          SignetLoginFailureEnum.TOKEN_EXCHANGE_FAILED,
        );
        expect(loggedLines()).toContain('detail=TimeoutError');
      });

      it('gives up on a body that stalls after the headers, as a transport failure', async () => {
        expect(await exchangeFails({ hang: 'body' }, 200)).toBe(
          SignetLoginFailureEnum.TOKEN_EXCHANGE_FAILED,
        );
        expect(loggedLines()).toContain('detail=TimeoutError');
      });

      it('does not follow a redirect: the code and verifier go nowhere else', async () => {
        let elsewhere = 0;
        const sink = createServer((_, response) => {
          elsewhere += 1;
          response.end();
        });
        await new Promise<void>((resolve) =>
          sink.listen(0, '127.0.0.1', resolve),
        );
        const { port } = sink.address() as AddressInfo;
        try {
          expect(
            await exchangeFails({
              location: `http://127.0.0.1:${port}/steal`,
              status: 307,
            }),
          ).toBe(SignetLoginFailureEnum.TOKEN_EXCHANGE_FAILED);
          expect(elsewhere).toBe(0);
          // A cause label after the name (TypeError:Error on Node 22's
          // undici): the refusal is told apart from a bare TypeError.
          expect(loggedLines()).toMatch(/detail=TypeError:\S+ /);
        } finally {
          await new Promise<void>((resolve) => sink.close(() => resolve()));
        }
      });

      it('refuses a code the server already redeemed', async () => {
        const flow = build();
        const { cookie, url } = await begin(flow);
        const back = server.authorize(url);
        await flow.complete(callback(back, cookie).request);
        // Same callback, same cookie value -- what a replay would present.
        expect(
          await rejection(flow.complete(callback(back, cookie).request)),
        ).toBe(SignetLoginFailureEnum.TOKEN_EXCHANGE_FAILED);
      });
    });

    describe('the token', () => {
      const withToken = async (accessToken: string) => {
        const flow = build();
        const { cookie, url } = await begin(flow);
        const back = server.authorize(url);
        server.scriptTokenEndpoint({ body: { access_token: accessToken } });
        return rejection(flow.complete(callback(back, cookie).request));
      };

      it('answers TOKEN_REJECTED for a token the verifier refuses, with the verifier’s reason in the log', async () => {
        expect(await withToken('not-a-jwt')).toBe(
          SignetLoginFailureEnum.TOKEN_REJECTED,
        );
        expect(loggedLines()).toContain(
          'reason=token_rejected detail=ERR_JWS_INVALID',
        );
      });

      it('answers TOKEN_REJECTED for a valid token issued to another client', async () => {
        const token = await server.sign({
          aud: [FIXTURE_DEVELOPMENT_PROFILE.canonicalResource],
          client_id: 'someone-else',
          iss: server.issuer,
          scp: ['openid', 'acme:access'],
          sub: 'person-1',
        });
        expect(await withToken(token)).toBe(
          SignetLoginFailureEnum.TOKEN_REJECTED,
        );
        expect(loggedLines()).toContain('detail=client_id_mismatch');
      });

      it('checks the access token before the ID token', async () => {
        expect(await withToken('not-a-jwt')).toBe(
          SignetLoginFailureEnum.TOKEN_REJECTED,
        );
        expect(loggedLines()).not.toContain('id_token');
      });

      it('answers ADMISSION_SCOPE_NOT_GRANTED when the user did not grant the admission scope', async () => {
        const flow = build();
        const { cookie, url } = await begin(flow);
        const back = server.authorize(url, { scopes: ['openid'] });
        expect(
          await rejection(flow.complete(callback(back, cookie).request)),
        ).toBe(SignetLoginFailureEnum.ADMISSION_SCOPE_NOT_GRANTED);
      });
    });

    describe('the ID token', () => {
      const SUBJECT = 'person-1';
      const accessToken = () =>
        server.sign({
          aud: [FIXTURE_DEVELOPMENT_PROFILE.canonicalResource],
          client_id: CLIENT_ID,
          iss: server.issuer,
          scp: ['openid', 'acme:access'],
          sub: SUBJECT,
        });
      const idTokenPayload = (overrides: Record<string, unknown> = {}) => ({
        aud: CLIENT_ID,
        iss: server.issuer,
        sub: SUBJECT,
        ...overrides,
      });

      // A real begin() and authorize(), then the token endpoint scripted to
      // answer with these fields beside a valid access token.
      const completeWith = async (fields: Record<string, unknown>) => {
        const flow = build();
        const { cookie, url } = await begin(flow);
        const back = server.authorize(url);
        server.scriptTokenEndpoint({
          body: { access_token: await accessToken(), ...fields },
        });
        return flow.complete(callback(back, cookie).request);
      };

      const refused = async (fields: Record<string, unknown>) => {
        expect(await rejection(completeWith(fields))).toBe(
          SignetLoginFailureEnum.TOKEN_REJECTED,
        );
        return loggedLines();
      };

      it.each([
        ['absent', {}],
        ['empty', { id_token: '' }],
        ['not a string', { id_token: 42 }],
      ])(
        'answers TOKEN_REJECTED when the ID token is %s: openid was asked for',
        async (_, fields) => {
          expect(await refused(fields)).toContain(
            'reason=token_rejected detail=id_token_missing',
          );
        },
      );

      it('answers TOKEN_REJECTED for an ID token about someone else', async () => {
        const idToken = await server.sign(
          idTokenPayload({ sub: 'someone-else' }),
        );
        expect(await refused({ id_token: idToken })).toContain(
          'detail=id_token_subject_mismatch',
        );
      });

      it.each([
        ['issued to another client', { aud: 'someone-else' }],
        ['issued to no client', { aud: undefined }],
        [
          'that is really an access token',
          { aud: [FIXTURE_DEVELOPMENT_PROFILE.canonicalResource] },
        ],
        ['from another issuer', { iss: 'https://someone-else.example' }],
      ])('answers TOKEN_REJECTED for an ID token %s', async (_, overrides) => {
        const idToken = await server.sign(idTokenPayload(overrides));
        expect(await refused({ id_token: idToken })).toContain(
          'detail=id_token:ERR_JWT_CLAIM_VALIDATION_FAILED',
        );
      });

      it('answers TOKEN_REJECTED for an expired ID token', async () => {
        const idToken = await server.sign(
          idTokenPayload({ exp: Math.floor(Date.now() / 1000) - 3_600 }),
        );
        expect(await refused({ id_token: idToken })).toContain(
          'detail=id_token:ERR_JWT_EXPIRED',
        );
      });

      it('answers TOKEN_REJECTED for an ID token signed by a key the issuer does not publish', async () => {
        const stranger = await startTestIssuer();
        try {
          const idToken = await stranger.sign(idTokenPayload());
          expect(await refused({ id_token: idToken })).toContain(
            'detail=id_token:ERR_JWS_SIGNATURE_VERIFICATION_FAILED',
          );
        } finally {
          await stranger.close();
        }
      });

      it.each([
        ['the client as a string', CLIENT_ID],
        ['the client alone in an array', [CLIENT_ID]],
      ])('accepts an ID token whose aud is %s', async (_, aud) => {
        const idToken = await server.sign(idTokenPayload({ aud }));
        const { login } = await completeWith({ id_token: idToken });
        expect(login.idTokenClaims.aud).toEqual(aud);
      });

      it.each([
        ['without azp', {}],
        ['even with azp naming this client', { azp: CLIENT_ID }],
      ])(
        'answers TOKEN_REJECTED for an ID token for this client and another, %s',
        async (_, overrides) => {
          const idToken = await server.sign(
            idTokenPayload({ aud: [CLIENT_ID, 'someone-else'], ...overrides }),
          );
          expect(await refused({ id_token: idToken })).toContain(
            'detail=id_token:ERR_JWT_EXTRA_AUDIENCE',
          );
        },
      );

      it('answers TOKEN_REJECTED for an ID token whose azp names another client', async () => {
        const idToken = await server.sign(
          idTokenPayload({ azp: 'someone-else' }),
        );
        expect(await refused({ id_token: idToken })).toContain(
          'detail=id_token:ERR_JWT_AZP_MISMATCH',
        );
      });

      it.each([
        ['an empty sub', { sub: '' }, 'ERR_JWT_NO_SUB'],
        ['no exp', { exp: undefined }, 'ERR_JWT_NO_EXP'],
      ])(
        'answers TOKEN_REJECTED for an ID token with %s',
        async (_, overrides, reason) => {
          const idToken = await server.sign(idTokenPayload(overrides));
          expect(await refused({ id_token: idToken })).toContain(
            `detail=id_token:${reason}`,
          );
        },
      );
    });

    it('logs no code, no state and no query string', async () => {
      const flow = build();
      const { cookie, url } = await begin(flow);
      const back = new URL(server.authorize(url));
      server.scriptTokenEndpoint({ error: 'invalid_grant', status: 400 });
      await rejection(flow.complete(callback(back.toString(), cookie).request));
      const lines = loggedLines();
      expect(lines).toContain(`route=${CALLBACK_PATH}`);
      expect(lines).not.toContain(back.searchParams.get('code'));
      expect(lines).not.toContain(back.searchParams.get('state'));
      expect(lines).not.toContain('?');
    });
  });

  describe('discovery', () => {
    const discoveryFails = async (flow = build()) => {
      expect(await rejection(begin(flow))).toBe(
        SignetLoginFailureEnum.DISCOVERY_FAILED,
      );
    };

    it('refuses a document for another issuer, and does not cache the failure', async () => {
      const flow = build();
      server.overrideDiscovery({
        document: {
          authorization_endpoint: `${server.issuer}/oauth2/auth`,
          issuer: 'https://someone-else.example',
          token_endpoint: `${server.issuer}/oauth2/token`,
        },
      });
      await discoveryFails(flow);
      expect(loggedLines()).toContain(
        'reason=discovery_failed detail=issuer_mismatch',
      );
      server.overrideDiscovery(null);
      const { url } = await begin(flow);
      expect(url.startsWith(`${server.issuer}/oauth2/auth?`)).toBe(true);
    });

    it('caches a success: one fetch for the life of the flow', async () => {
      const flow = build();
      await begin(flow);
      server.overrideDiscovery({ status: 503 });
      await begin(flow);
      expect(server.discoveryRequests()).toBe(1);
    });

    it('makes one fetch for logins that start together', async () => {
      const flow = build();
      await Promise.all([begin(flow), begin(flow), begin(flow)]);
      expect(server.discoveryRequests()).toBe(1);
    });

    it('refuses an http authorization endpoint outside development', async () => {
      await discoveryFails(build({ profile: PRODUCTION_PROFILE }));
      expect(loggedLines()).toContain(
        'detail=authorization_endpoint_not_https',
      );
    });

    it('refuses an http token endpoint outside development, the authorization endpoint being https', async () => {
      server.overrideDiscovery({
        document: {
          authorization_endpoint: 'https://idp.example/oauth2/auth',
          issuer: server.issuer,
          token_endpoint: 'http://idp.example/oauth2/token',
        },
      });
      await discoveryFails(build({ profile: PRODUCTION_PROFILE }));
      expect(loggedLines()).toContain('detail=token_endpoint_not_https');
    });

    it.each([
      [42, 'authorization_endpoint_missing'],
      ['not a url', 'authorization_endpoint_invalid'],
    ])(
      'refuses an authorization_endpoint of %j as %s',
      async (value, detail) => {
        server.overrideDiscovery({
          document: {
            authorization_endpoint: value,
            issuer: server.issuer,
            token_endpoint: `${server.issuer}/oauth2/token`,
          },
        });
        await discoveryFails();
        expect(loggedLines()).toContain(`detail=${detail} `);
      },
    );

    it('names a non-200 status', async () => {
      server.overrideDiscovery({ status: 503 });
      await discoveryFails();
      expect(loggedLines()).toContain('detail=status_503 ');
    });

    it('names a body that is not JSON', async () => {
      server.overrideDiscovery({ raw: '<html>' });
      await discoveryFails();
      expect(loggedLines()).toContain('detail=body_not_json ');
    });

    it('refuses a JSON body that is not a document -- a 401, not a crash', async () => {
      server.overrideDiscovery({ raw: 'null' });
      await discoveryFails();
      expect(loggedLines()).toContain('detail=issuer_mismatch ');
    });

    it('names a body that stalls a timeout, not body_not_json', async () => {
      server.overrideDiscovery({ hang: 'body' });
      await discoveryFails(build({ discoveryMs: 200 }));
      expect(loggedLines()).toContain('detail=TimeoutError ');
    });

    it('names an issuer it cannot reach by the errno, without the URL', async () => {
      // A port that was just listening and is closed now: refused, not one
      // of fetch's blocked ports.
      const closed = createServer();
      await new Promise<void>((resolve) =>
        closed.listen(0, '127.0.0.1', resolve),
      );
      const { port } = closed.address() as AddressInfo;
      await new Promise<void>((resolve) => closed.close(() => resolve()));
      await discoveryFails(
        build({ env: { ACME_JWT_ISSUER: `http://127.0.0.1:${port}` } }),
      );
      const lines = loggedLines();
      expect(lines).toContain('detail=TypeError:ECONNREFUSED ');
      expect(lines).not.toContain('http://');
    });

    it('lets a defect in discovery surface as itself, not as DISCOVERY_FAILED', async () => {
      const defect = new TypeError('a bug, not the issuer');
      jest
        .spyOn(LoginDiscovery.prototype, 'endpoints')
        .mockRejectedValue(defect);
      await expect(begin(build())).rejects.toBe(defect);
      expect(warn).not.toHaveBeenCalled();
    });

    it('appends the well-known path to the issuer without doubling a trailing slash', () => {
      expect(discoveryUrl('https://signet.example/')).toBe(
        'https://signet.example/.well-known/openid-configuration',
      );
      expect(discoveryUrl('https://signet.example')).toBe(
        'https://signet.example/.well-known/openid-configuration',
      );
    });
  });

  describe('with the Signet flag off', () => {
    it('reads no login values, and refuses both steps with DISABLED', async () => {
      const flow = build({
        env: {
          ACME_LOGIN_CLIENT_ID: undefined,
          ACME_LOGIN_STATE_SECRET: undefined,
          ACME_SIGNET_ENABLED: 'false',
        },
      });
      expect(await rejection(begin(flow))).toBe(
        SignetLoginFailureEnum.DISABLED,
      );
      expect(
        await rejection(
          flow.complete(
            callback(`http://localhost:3000${CALLBACK_PATH}?code=c&state=s`)
              .request,
          ),
        ),
      ).toBe(SignetLoginFailureEnum.DISABLED);
    });
  });

  describe('at construction', () => {
    it('requires the login variable names in the options, with the flag off too', () => {
      for (const flag of ['true', 'false']) {
        expect(() =>
          build({
            env: { ACME_SIGNET_ENABLED: flag },
            options: FIXTURE_OPTIONS,
          }),
        ).toThrow(
          'SignetLoginStrategy acme-login needs options.env.login ({ clientId, stateSecret })',
        );
      }
    });

    it('requires their values with the flag on', () => {
      expect(() => build({ env: { ACME_LOGIN_CLIENT_ID: undefined } })).toThrow(
        'ACME_LOGIN_CLIENT_ID missing',
      );
    });

    it.each(['', ' ', 'acme-web\n', ' acme-web'])(
      'refuses the client id %j: empty, or with whitespace a mounted secret might carry',
      (clientId) => {
        expect(() =>
          build({ env: { ACME_LOGIN_CLIENT_ID: clientId } }),
        ).toThrow(
          'ACME_LOGIN_CLIENT_ID must not be empty or carry leading or trailing whitespace',
        );
      },
    );

    it.each([
      ['signet.example', 'is not a URL'],
      ['localhost:8080', 'is not an http(s) URL'],
    ])(
      'refuses the issuer %j at boot, not as a transport failure at every login',
      (issuer, problem) => {
        expect(() => build({ env: { ACME_JWT_ISSUER: issuer } })).toThrow(
          `ACME_JWT_ISSUER ${problem} for the login flow's discovery`,
        );
      },
    );

    it('does not judge the issuer with the flag off', () => {
      expect(() =>
        build({
          env: {
            ACME_JWT_ISSUER: 'signet.example',
            ACME_SIGNET_ENABLED: 'false',
          },
        }),
      ).not.toThrow();
    });

    it('refuses a state secret shorter than 32 bytes, naming its variable', () => {
      expect(() =>
        build({ env: { ACME_LOGIN_STATE_SECRET: 'short' } }),
      ).toThrow(
        'ACME_LOGIN_STATE_SECRET: the login state secret must be at least 32 bytes',
      );
    });

    it('refuses an http redirect URI in a deployed environment', () => {
      expect(() =>
        build({
          entry: {
            ...ENTRY,
            redirectUris: {
              ...ENTRY.redirectUris,
              production: 'http://acme.example/cb',
            },
          },
          profile: PRODUCTION_PROFILE,
        }),
      ).toThrow(
        'invalid SignetLoginEntry acme-login: redirect URI for production must be https',
      );
    });

    it.each([
      ['http://127.0.0.1:4000/cb', true],
      ['http://[::1]:4000/cb', true],
      ['http://dev.example/cb', false],
    ])('in development, allows %s: %s', (uri, allowed) => {
      const attempt = () =>
        build({
          entry: {
            ...ENTRY,
            redirectUris: { ...ENTRY.redirectUris, development: uri },
          },
        });
      if (allowed) expect(attempt).not.toThrow();
      else expect(attempt).toThrow('must be https, or http on a loopback host');
    });

    it('checks the redirect URI with the flag off too', () => {
      expect(() =>
        build({
          entry: {
            ...ENTRY,
            redirectUris: { ...ENTRY.redirectUris, development: 'not a url' },
          },
          env: { ACME_SIGNET_ENABLED: 'false' },
        }),
      ).toThrow('redirect URI for development is not a URL');
    });

    it('wants a redirect URI for every environment the options name, and none they do not, with the flag off too', () => {
      const { production: _, ...withoutProduction } = ENTRY.redirectUris;
      expect(() =>
        build({
          entry: { ...ENTRY, redirectUris: withoutProduction },
          env: { ACME_SIGNET_ENABLED: 'false' },
        }),
      ).toThrow(
        'invalid SignetLoginEntry acme-login: no redirect URI for production',
      );
      expect(() =>
        build({
          entry: {
            ...ENTRY,
            redirectUris: {
              ...ENTRY.redirectUris,
              prodution: 'https://acme.example/cb',
            },
          },
          env: { ACME_SIGNET_ENABLED: 'false' },
        }),
      ).toThrow(
        'invalid SignetLoginEntry acme-login: redirect URI for an environment the options do not name: prodution',
      );
    });
  });
});
