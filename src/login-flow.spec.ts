import { Logger } from '@nestjs/common';
import { type ConfigService } from '@nestjs/config';
import { type Request, type Response } from 'express';
import { decodeProtectedHeader } from 'jose';

import { type DeploymentProfile } from './deployment-profile';
import { discoveryUrl } from './login-discovery';
import { type SignetLoginEntry } from './login-entry';
import { SignetLoginError, SignetLoginFailureEnum } from './login-error';
import { SignetLoginFlow } from './login-flow';
import { type SignetIntegrationOptions } from './options';
import {
  startTestAuthorizationServer,
  type TestAuthorizationServer,
} from './testing/authorization-server';
import {
  FIXTURE_DEVELOPMENT_PROFILE,
  FIXTURE_OPTIONS,
} from './testing/fixture';

const CLIENT_ID = 'acme-web';
const SECRET = 'a-login-state-secret-of-32-bytes!';
const CALLBACK_PATH = '/auth/signet/callback';

const ENTRY: SignetLoginEntry<'production' | 'staging'> = {
  name: 'acme-login',
  redirectUris: {
    development: `http://localhost:3000${CALLBACK_PATH}`,
    production: `https://acme.example${CALLBACK_PATH}`,
    staging: `https://acme.staging.example${CALLBACK_PATH}`,
  },
};

const OPTIONS: SignetIntegrationOptions = {
  ...FIXTURE_OPTIONS,
  env: {
    ...FIXTURE_OPTIONS.env,
    loginClientId: 'ACME_LOGIN_CLIENT_ID',
    loginStateSecret: 'ACME_LOGIN_STATE_SECRET',
  },
};

const PRODUCTION_PROFILE: DeploymentProfile = {
  canonicalResource: 'https://acme.example/mcp',
  environment: 'production',
  host: 'acme.example',
  namespace: 'acme-production',
};

function configOf(env: Record<string, string | undefined>): ConfigService {
  return {
    get: (key: string, fallback?: unknown) => env[key] ?? fallback,
    getOrThrow: (key: string) => {
      const value = env[key];
      if (value === undefined) throw new Error(`${key} missing`);
      return value;
    },
  } as unknown as ConfigService;
}

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
    server.scriptTokenEndpoint(null);
    server.discovery(null);
  });

  const env = (overrides: Record<string, string | undefined> = {}) => ({
    ACME_JWT_ISSUER: server.issuer,
    ACME_JWT_JWKS_URI: server.jwksUri,
    ACME_LOGIN_CLIENT_ID: CLIENT_ID,
    ACME_LOGIN_STATE_SECRET: SECRET,
    ACME_SIGNET_ENABLED: 'true',
    ...overrides,
  });

  const build = (
    input: {
      entry?: SignetLoginEntry;
      env?: Record<string, string | undefined>;
      options?: SignetIntegrationOptions;
      profile?: DeploymentProfile;
      tokenMs?: number;
    } = {},
  ) =>
    new SignetLoginFlow(
      input.entry ?? ENTRY,
      configOf(input.env ?? env()),
      { profile: input.profile ?? FIXTURE_DEVELOPMENT_PROFILE },
      input.options ?? OPTIONS,
      logger,
      { discoveryMs: 2_000, tokenMs: input.tokenMs ?? 2_000 },
    );

  // begin() against a fake Express response: the authorization URL and the
  // Set-Cookie it appended.
  const begin = async (
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
    const url = await flow.begin(response);
    expect(setCookie).toHaveLength(1);
    return {
      cookie: setCookie[0].split(';')[0],
      setCookie: setCookie[0],
      url,
    };
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
      const [name, value] = [
        pair.split('=')[0],
        pair.slice(pair.indexOf('=') + 1),
      ];
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

    it('marks the cookie Secure for an https redirect URI', async () => {
      server.discovery({
        authorization_endpoint: 'https://idp.example/oauth2/auth',
        issuer: server.issuer,
        token_endpoint: 'https://idp.example/oauth2/token',
      });
      const { setCookie } = await begin(build({ profile: PRODUCTION_PROFILE }));
      expect(setCookie).toContain(`Path=${CALLBACK_PATH}`);
      expect(setCookie.endsWith('; Secure')).toBe(true);
    });
  });

  describe('complete', () => {
    it('exchanges the code with the PKCE verifier and returns the access token’s verified identity', async () => {
      const flow = build();
      const { cookie, url } = await begin(flow);
      const back = server.authorize(url, {
        claims: { email: 'someone@example.com' },
        subject: 'person-1',
      });
      const identity = await flow.complete(callback(back, cookie).request);
      expect(identity).toMatchObject({
        claims: { email: 'someone@example.com' },
        clientId: CLIENT_ID,
        scopes: ['openid', 'acme:access'],
        subject: 'person-1',
      });
      const [sent] = server.tokenRequests().slice(-1);
      expect(sent).toMatchObject({
        client_id: CLIENT_ID,
        grant_type: 'authorization_code',
        redirect_uri: ENTRY.redirectUris.development,
      });
      expect(sent.code_verifier).toMatch(/^[\w-]{43}$/);
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

    it('answers CANCELLED for access_denied and IDP_ERROR for any other error', async () => {
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

    describe('state', () => {
      it('refuses a state that does not match the cookie’s, before calling the token endpoint', async () => {
        const flow = build();
        const { cookie, url } = await begin(flow);
        const back = new URL(server.authorize(url));
        back.searchParams.set('state', 'someone-elses-state');
        const before = server.tokenRequests().length;
        expect(
          await rejection(
            flow.complete(callback(back.toString(), cookie).request),
          ),
        ).toBe(SignetLoginFailureEnum.STATE_INVALID);
        expect(server.tokenRequests()).toHaveLength(before);
      });

      it('refuses a callback with no state cookie', async () => {
        const flow = build();
        const { url } = await begin(flow);
        expect(
          await rejection(
            flow.complete(callback(server.authorize(url)).request),
          ),
        ).toBe(SignetLoginFailureEnum.STATE_INVALID);
      });

      it('refuses a cookie that was tampered with', async () => {
        const flow = build();
        const { cookie, url } = await begin(flow);
        const flipped =
          cookie.slice(0, -2) +
          (cookie.endsWith('A') ? 'B' : 'A') +
          cookie.slice(-1);
        expect(
          await rejection(
            flow.complete(callback(server.authorize(url), flipped).request),
          ),
        ).toBe(SignetLoginFailureEnum.STATE_INVALID);
      });

      it('refuses a cookie sealed under another secret', async () => {
        const other = build({
          env: env({
            ACME_LOGIN_STATE_SECRET: 'another-secret-also-32-bytes-long',
          }),
        });
        const { cookie, url } = await begin(other);
        expect(
          await rejection(
            build().complete(callback(server.authorize(url), cookie).request),
          ),
        ).toBe(SignetLoginFailureEnum.STATE_INVALID);
      });

      it('refuses a state issued for another entry, even under this entry’s cookie name', async () => {
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
        expect(loggedLines()).toContain('reason=state_invalid detail=entry');
      });

      it('refuses a state older than ten minutes', async () => {
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
        expect(loggedLines()).toContain('reason=state_invalid detail=cookie');
      });

      it('refuses a repeated state parameter', async () => {
        const flow = build();
        const { cookie, url } = await begin(flow);
        const back = new URL(server.authorize(url));
        const state = back.searchParams.get('state')!;
        const { request } = callback(back.toString(), cookie, {
          code: back.searchParams.get('code'),
          state: [state, state],
        });
        expect(await rejection(flow.complete(request))).toBe(
          SignetLoginFailureEnum.STATE_INVALID,
        );
      });

      it('accepts the current state beside a stale cookie of the same name', async () => {
        const flow = build();
        const stale = await begin(flow);
        const { cookie, url } = await begin(flow);
        const identity = await flow.complete(
          callback(server.authorize(url), `${stale.cookie}; ${cookie}`).request,
        );
        expect(identity.subject).toBe('test-user');
      });
    });

    describe('token exchange', () => {
      const exchangeFails = async (
        script: Parameters<TestAuthorizationServer['scriptTokenEndpoint']>[0],
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

      it('answers TOKEN_EXCHANGE_FAILED for a 5xx without a body', async () => {
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

      it('treats a 200 whose body is not JSON as a missing token', async () => {
        expect(await exchangeFails({ body: undefined })).toBe(
          SignetLoginFailureEnum.TOKEN_EXCHANGE_FAILED,
        );
        expect(loggedLines()).toContain('detail=access_token_missing');
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

      it('answers ADMISSION_SCOPE_NOT_GRANTED when the user did not grant the admission scope', async () => {
        const flow = build();
        const { cookie, url } = await begin(flow);
        const back = server.authorize(url, { scopes: ['openid'] });
        expect(
          await rejection(flow.complete(callback(back, cookie).request)),
        ).toBe(SignetLoginFailureEnum.ADMISSION_SCOPE_NOT_GRANTED);
      });
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
    it('refuses a document for another issuer, and does not cache the failure', async () => {
      const flow = build();
      server.discovery({
        authorization_endpoint: `${server.issuer}/oauth2/auth`,
        issuer: 'https://someone-else.example',
        token_endpoint: `${server.issuer}/oauth2/token`,
      });
      expect(await rejection(begin(flow))).toBe(
        SignetLoginFailureEnum.DISCOVERY_FAILED,
      );
      expect(loggedLines()).toContain(
        'reason=discovery_failed detail=issuer_mismatch',
      );
      server.discovery(null);
      const { url } = await begin(flow);
      expect(url.startsWith(`${server.issuer}/oauth2/auth?`)).toBe(true);
    });

    it('refuses http endpoints outside development', async () => {
      expect(
        await rejection(begin(build({ profile: PRODUCTION_PROFILE }))),
      ).toBe(SignetLoginFailureEnum.DISCOVERY_FAILED);
      expect(loggedLines()).toContain(
        'detail=authorization_endpoint_not_https',
      );
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
    const disabled = () =>
      build({
        env: env({
          ACME_LOGIN_CLIENT_ID: undefined,
          ACME_LOGIN_STATE_SECRET: undefined,
          ACME_SIGNET_ENABLED: 'false',
        }),
      });

    it('needs no login settings, and refuses both steps with DISABLED', async () => {
      const flow = disabled();
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
    it('requires the login variable names in the options', () => {
      expect(() => build({ options: FIXTURE_OPTIONS })).toThrow(
        'SignetLoginStrategy acme-login needs options.env.loginClientId and options.env.loginStateSecret',
      );
    });

    it('requires their values', () => {
      expect(() =>
        build({ env: env({ ACME_LOGIN_CLIENT_ID: undefined }) }),
      ).toThrow('ACME_LOGIN_CLIENT_ID missing');
    });

    it('refuses a state secret shorter than 32 bytes, naming its variable', () => {
      expect(() =>
        build({ env: env({ ACME_LOGIN_STATE_SECRET: 'short' }) }),
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

    it('allows http in development on a loopback host only', () => {
      expect(() =>
        build({
          entry: {
            ...ENTRY,
            redirectUris: {
              ...ENTRY.redirectUris,
              development: 'http://dev.example/cb',
            },
          },
        }),
      ).toThrow('must be https, or http on a loopback host');
      expect(() =>
        build({
          entry: {
            ...ENTRY,
            redirectUris: {
              ...ENTRY.redirectUris,
              development: 'http://127.0.0.1:4000/cb',
            },
          },
        }),
      ).not.toThrow();
    });

    it('checks the redirect URI with the flag off too', () => {
      expect(() =>
        build({
          entry: {
            ...ENTRY,
            redirectUris: { ...ENTRY.redirectUris, development: 'not a url' },
          },
          env: env({ ACME_SIGNET_ENABLED: 'false' }),
        }),
      ).toThrow('redirect URI for development is not a URL');
    });
  });
});
