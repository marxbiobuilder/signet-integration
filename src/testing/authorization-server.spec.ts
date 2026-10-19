import { codeChallenge } from '../login-state';
import {
  startTestAuthorizationServer,
  type TestAuthorizationServer,
} from './authorization-server';

// The login specs' oracle checks the flow; this checks the oracle. Each
// refusal below is one a broken flow would otherwise sail through.
describe('startTestAuthorizationServer', () => {
  const CLIENT = 'acme-web';
  const REDIRECT = 'http://localhost:3000/cb';
  const VERIFIER = 'v'.repeat(43);
  let server: TestAuthorizationServer;

  beforeAll(async () => {
    server = await startTestAuthorizationServer({ clientId: CLIENT });
  });

  afterAll(async () => {
    await server.close();
  });

  beforeEach(() => {
    server.reset();
  });

  const authorizationUrl = (
    overrides: Record<string, string | string[]> = {},
  ) => {
    const url = new URL(`${server.issuer}/oauth2/auth`);
    const params: Record<string, string | string[]> = {
      client_id: CLIENT,
      code_challenge: codeChallenge(VERIFIER),
      code_challenge_method: 'S256',
      redirect_uri: REDIRECT,
      resource: 'http://localhost/mcp',
      response_type: 'code',
      scope: 'openid acme:access',
      state: 's',
      ...overrides,
    };
    for (const [name, value] of Object.entries(params)) {
      for (const one of [value].flat()) url.searchParams.append(name, one);
    }
    return url.toString();
  };

  const redeem = async (fields: Record<string, string>) => {
    const response = await fetch(`${server.issuer}/oauth2/token`, {
      body: new URLSearchParams(fields),
      method: 'POST',
    });
    return {
      body: (await response.json()) as Record<string, unknown>,
      status: response.status,
    };
  };

  const codeFrom = (redirect: string) =>
    new URL(redirect).searchParams.get('code') ?? '';

  const exchange = (code: string, overrides: Record<string, string> = {}) =>
    redeem({
      client_id: CLIENT,
      code,
      code_verifier: VERIFIER,
      grant_type: 'authorization_code',
      redirect_uri: REDIRECT,
      ...overrides,
    });

  it('redeems a code issued for this PKCE, redirect URI and client, once', async () => {
    const code = codeFrom(server.authorize(authorizationUrl()));
    const first = await exchange(code);
    expect(first.status).toBe(200);
    expect(typeof first.body.access_token).toBe('string');
    expect(await exchange(code)).toEqual({
      body: { error: 'invalid_grant' },
      status: 400,
    });
    expect(server.tokenRequests()).toHaveLength(2);
  });

  it.each([
    ['a wrong verifier', { code_verifier: 'w'.repeat(43) }],
    ['another redirect URI', { redirect_uri: 'http://localhost:3000/other' }],
    ['another client', { client_id: 'someone-else' }],
    ['another grant type', { grant_type: 'client_credentials' }],
  ])('refuses %s with invalid_grant', async (_, overrides) => {
    const code = codeFrom(server.authorize(authorizationUrl()));
    expect(await exchange(code, overrides)).toEqual({
      body: { error: 'invalid_grant' },
      status: 400,
    });
  });

  it.each([
    ['another client', { client_id: 'someone-else' }, 'client_id'],
    [
      'a plain challenge',
      { code_challenge_method: 'plain' },
      'code_challenge_method',
    ],
    [
      'two resources',
      { resource: ['https://a', 'https://b'] },
      'more than one resource',
    ],
    ['another response type', { response_type: 'token' }, 'response_type'],
  ])('refuses an authorization request with %s', (_, overrides, reason) => {
    expect(() => server.authorize(authorizationUrl(overrides))).toThrow(
      `test authorization server refused the request: ${reason}`,
    );
  });

  it('refuses an authorization URL for another server', () => {
    expect(() =>
      server.authorize(
        authorizationUrl().replace(server.issuer, 'http://127.0.0.1:9'),
      ),
    ).toThrow('not this server’s authorization endpoint');
  });

  it('mints the token Signet would: aud the one resource, scp, client_id, iss', async () => {
    const code = codeFrom(
      server.authorize(authorizationUrl(), { subject: 'person-1' }),
    );
    const { body } = await exchange(code);
    const [, payload] = String(body.access_token).split('.');
    expect(
      JSON.parse(Buffer.from(payload, 'base64url').toString()),
    ).toMatchObject({
      aud: ['http://localhost/mcp'],
      client_id: CLIENT,
      iss: server.issuer,
      scp: ['openid', 'acme:access'],
      sub: 'person-1',
    });
  });

  it('serves its own discovery document, counts requests, and resets', async () => {
    const response = await fetch(
      `${server.issuer}/.well-known/openid-configuration`,
    );
    expect(await response.json()).toMatchObject({
      issuer: server.issuer,
      token_endpoint: `${server.issuer}/oauth2/token`,
    });
    expect(server.discoveryRequests()).toBe(1);
    server.reset();
    expect(server.discoveryRequests()).toBe(0);
  });
});
