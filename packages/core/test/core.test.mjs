import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { test } from 'node:test';
import { createRequire } from 'node:module';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import core from '../dist/index.js';
import oauth from '../dist/oauth.js';
import oidc from '../dist/oidc.js';

const { createTokenVerifier, hasAllScopes, createScopeVocabulary } = core;
const {
  createBearerChallenge,
  createProtectedResourceMetadata,
  protectedResourceMetadataUrl,
} = oauth;
const { createOidcClient, OidcError } = oidc;

async function issuerFixture(t) {
  const pair = await generateKeyPair('RS256');
  let keys = [
    { ...(await exportJWK(pair.publicKey)), kid: 'one', alg: 'RS256' },
  ];
  let requests = 0;
  let status = 200;
  let tokenBody;
  let tokenRequests = [];
  let endpointOverride;
  let discoveryIssuer;
  let address;
  const codes = new Set();
  const server = createServer(async (req, res) => {
    if (req.url === '/jwks') {
      requests++;
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ keys }));
    } else if (req.url === '/.well-known/openid-configuration') {
      res.setHeader('content-type', 'application/json');
      res.end(
        JSON.stringify({
          issuer: discoveryIssuer ?? address,
          authorization_endpoint: `${address}/authorize`,
          token_endpoint: endpointOverride ?? `${address}/token`,
        }),
      );
    } else if (req.url === '/token') {
      let body = '';
      for await (const part of req) body += part;
      const params = new URLSearchParams(body);
      tokenRequests.push(params);
      const code = params.get('code');
      if (codes.has(code)) {
        res.writeHead(400);
        res.end('{}');
        return;
      }
      codes.add(code);
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify(tokenBody));
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  address = `http://127.0.0.1:${server.address().port}`;
  t.after(
    () =>
      new Promise((resolve, reject) =>
        server.close((e) => (e ? reject(e) : resolve())),
      ),
  );
  const options = {
    issuer: address,
    audience: `${address}/api/mcp`,
    jwksUri: `${address}/jwks`,
    clockToleranceSeconds: 0,
    allowInsecureLoopback: true,
  };
  return {
    options,
    get requests() {
      return requests;
    },
    get tokenRequests() {
      return tokenRequests;
    },
    fail: () => {
      status = 503;
    },
    discoveryIssuer: (value) => {
      discoveryIssuer = value;
    },
    endpointOverride: (value) => {
      endpointOverride = value;
    },
    async token(claims = {}, key = pair.privateKey, kid = 'one') {
      return new SignJWT({
        iss: address,
        sub: 'person-1',
        aud: options.audience,
        exp: Math.floor(Date.now() / 1000) + 120,
        client_id: 'web',
        scope: 'cms:access cms:read',
        ...claims,
      })
        .setProtectedHeader({ alg: 'RS256', kid })
        .sign(key);
    },
    async rotate() {
      const next = await generateKeyPair('RS256');
      keys = [
        { ...(await exportJWK(next.publicKey)), kid: 'two', alg: 'RS256' },
      ];
      return next;
    },
    setTokens: (body) => {
      tokenBody = body;
    },
  };
}

test('verifier accepts valid tokens, caches JWKS and freezes parsed authorization', async (t) => {
  const f = await issuerFixture(t);
  const verifier = createTokenVerifier(f.options);
  const token = await f.token({ scp: ['cms:read', 'cms:write'] });
  const result = await verifier.verifyAccessToken(token);
  assert.equal(result.ok, true);
  assert.deepEqual(result.identity.scopes, [
    'cms:access',
    'cms:read',
    'cms:write',
  ]);
  assert.equal(result.identity.expiresAt, result.identity.claims.exp);
  assert.ok(Object.isFrozen(result.identity));
  assert.ok(Object.isFrozen(result.identity.scopes));
  assert.ok(hasAllScopes(result.identity, ['cms:read']));
  assert.ok(!hasAllScopes(result.identity, ['cms:publish']));
  await verifier.verifyAccessToken(token);
  assert.equal(f.requests, 1);
});

test('verifier rejects signature, issuer, audience, lifetime and malformed claims', async (t) => {
  const f = await issuerFixture(t);
  const verifier = createTokenVerifier(f.options);
  const other = await generateKeyPair('RS256');
  const tokens = [
    await f.token({}, other.privateKey),
    ...(await Promise.all(
      [
        { iss: 'https://other.example' },
        { aud: 'https://other.example/api/mcp' },
        { exp: 1 },
        { exp: undefined },
        { sub: '' },
        { client_id: '' },
        { scope: ['bad'] },
        { scp: 'bad' },
        { nbf: Math.floor(Date.now() / 1000) + 1000 },
      ].map((claims) => f.token(claims)),
    )),
    'not-a-token',
  ];
  for (const token of tokens) {
    const result = await verifier.verifyAccessToken(token);
    assert.equal(result.ok, false);
    assert.equal(result.kind, 'invalid_token');
  }
});

test('JWKS outage is unavailable; a fresh process accepts rotated keys', async (t) => {
  const f = await issuerFixture(t);
  f.fail();
  const result = await createTokenVerifier(f.options).verifyAccessToken(
    await f.token(),
  );
  assert.equal(result.kind, 'verification_unavailable');
  const g = await issuerFixture(t);
  const key = await g.rotate();
  const rotated = await g.token({}, key.privateKey, 'two');
  assert.equal(
    (await createTokenVerifier(g.options).verifyAccessToken(rotated)).ok,
    true,
  );
});

test('unsafe verifier settings fail before an HTTP request', () => {
  const options = {
    issuer: 'https://issuer.example',
    jwksUri: 'https://issuer.example/jwks',
    audience: 'https://cms.example/api/mcp',
  };
  for (const clockToleranceSeconds of [NaN, -1, 301, 0.5])
    assert.throws(() =>
      createTokenVerifier({ ...options, clockToleranceSeconds }),
    );
  for (const issuer of [
    'http://issuer.example',
    'https://u:p@issuer.example',
    'https://issuer.example#fragment',
    'https://issuer.example?query',
  ])
    assert.throws(() => createTokenVerifier({ ...options, issuer }));
});

test('OAuth metadata/challenge use path-aware discovery and validate scope syntax', () => {
  const resource = 'https://cms.example/api/mcp';
  assert.equal(
    protectedResourceMetadataUrl(resource),
    'https://cms.example/.well-known/oauth-protected-resource/api/mcp',
  );
  assert.equal(
    protectedResourceMetadataUrl('https://cms.example'),
    'https://cms.example/.well-known/oauth-protected-resource',
  );
  assert.deepEqual(
    createProtectedResourceMetadata({
      resource,
      issuer: 'https://issuer.example',
      scopesSupported: ['cms:access', 'cms:read'],
    }).bearer_methods_supported,
    ['header'],
  );
  assert.match(
    createBearerChallenge({
      resource,
      requiredScopes: ['cms:access', 'cms:read'],
      error: 'insufficient_scope',
    }),
    /error="insufficient_scope"/,
  );
  for (const scope of [
    '',
    'bad scope',
    'quote"',
    'newline\n',
    'back\\slash',
    '中文',
  ])
    assert.throws(() =>
      createBearerChallenge({ resource, requiredScopes: [scope] }),
    );
  const vocabulary = createScopeVocabulary({
    admissionScope: 'cms:access',
    actions: ['cms:read', 'cms:write'],
    defaultActions: new Set(),
  });
  assert.equal(vocabulary.readTokenScopes(['constructor']).actions.size, 0);
});

test('OIDC round trip binds state, PKCE, client, resource and both token subjects', async (t) => {
  const f = await issuerFixture(t);
  const options = {
    ...f.options,
    clientId: 'web',
    redirectUri: `${f.options.issuer}/callback`,
    scopes: ['openid', 'email'],
    admissionScopes: ['cms:access'],
  };
  const client = createOidcClient(options);
  const begin = await client.begin();
  const auth = new URL(begin.authorizationUrl);
  assert.equal(auth.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(auth.searchParams.get('resource'), f.options.audience);
  assert.equal(auth.searchParams.get('state'), begin.transaction.state);
  f.setTokens({
    access_token: await f.token(),
    id_token: await f.token({ aud: 'web' }),
  });
  const callbackUrl = `${options.redirectUri}?state=${begin.transaction.state}&code=one`;
  const result = await client.complete({
    callbackUrl,
    transaction: begin.transaction,
  });
  assert.equal(result.identity.subject, result.idTokenClaims.sub);
  assert.equal(
    f.tokenRequests[0].get('code_verifier'),
    begin.transaction.verifier,
  );
  assert.equal(f.tokenRequests[0].get('client_id'), 'web');
  assert.equal('accessToken' in result, false);
  await assert.rejects(
    client.complete({ callbackUrl, transaction: begin.transaction }),
    OidcError,
  );
});

test('OIDC rejects invalid, expired, duplicate and cross-client transactions before exchange', async (t) => {
  const f = await issuerFixture(t);
  const options = {
    ...f.options,
    clientId: 'web',
    redirectUri: `${f.options.issuer}/callback`,
    scopes: ['openid'],
    admissionScopes: ['cms:access'],
  };
  const client = createOidcClient(options);
  const { transaction } = await client.begin();
  const callbackUrl = `${options.redirectUri}?state=${transaction.state}&code=one`;
  for (const tx of [
    { ...transaction, state: 'other' },
    { ...transaction, expiresAt: 1 },
    { ...transaction, clientId: 'other' },
    { ...transaction, resource: 'other' },
  ]) {
    await assert.rejects(client.complete({ callbackUrl, transaction: tx }), {
      reason: 'state_invalid',
    });
  }
  await assert.rejects(
    client.complete({
      callbackUrl: callbackUrl + '&state=duplicate',
      transaction,
    }),
    { reason: 'state_invalid' },
  );
  await assert.rejects(
    client.complete({
      callbackUrl: `${options.redirectUri}?state=${transaction.state}&error=access_denied`,
      transaction,
    }),
    { reason: 'cancelled' },
  );
  assert.equal(f.tokenRequests.length, 0);
});

test('OIDC rejects mixed identities, wrong client and ID token audience', async (t) => {
  const f = await issuerFixture(t);
  const options = {
    ...f.options,
    clientId: 'web',
    redirectUri: `${f.options.issuer}/callback`,
    scopes: ['openid'],
    admissionScopes: ['cms:access'],
  };
  const client = createOidcClient(options);
  let index = 0;
  for (const [accessClaims, idClaims] of [
    [{}, { sub: 'other', aud: 'web' }],
    [{ client_id: 'other' }, { aud: 'web' }],
    [{ scope: 'cms:read' }, { aud: 'web' }],
    [{}, { aud: 'other' }],
    [{}, { aud: ['web', 'other'], azp: 'web' }],
    [{}, { aud: 'web', azp: 'other' }],
  ]) {
    const { transaction } = await client.begin();
    f.setTokens({
      access_token: await f.token(accessClaims),
      id_token: await f.token(idClaims),
    });
    await assert.rejects(
      client.complete({
        callbackUrl: `${options.redirectUri}?state=${transaction.state}&code=${index++}`,
        transaction,
      }),
      { reason: 'token_rejected' },
    );
  }
});

test('transaction encryption is tamper resistant and core loads through CJS and ESM', async () => {
  const key = oidc.loginStateKey('x'.repeat(32), 'secret');
  const state = oidc.newLoginState('web');
  const encrypted = await oidc.sealLoginState(key, state);
  assert.equal(encrypted.includes(state.verifier), false);
  assert.deepEqual((await oidc.openLoginState(key, encrypted)).state, state);
  assert.equal((await oidc.openLoginState(key, encrypted + 'x')).ok, false);
  const require = createRequire(import.meta.url);
  assert.equal(
    typeof require('../dist/index.js').createTokenVerifier,
    'function',
  );
  assert.equal(
    typeof (await import('../dist/oidc.js')).createOidcClient,
    'function',
  );
});
