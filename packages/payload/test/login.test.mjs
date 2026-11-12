import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { decodeJwt, exportJWK, generateKeyPair, SignJWT } from 'jose';
import {
  buildConfig,
  createLocalReq,
  getPayload,
  logoutOperation,
  refreshOperation,
  getFieldsToSign,
  jwtSign,
} from 'payload';
import { addSessionToUser } from 'payload/shared';
import { sqliteAdapter } from '@payloadcms/db-sqlite';
import { createXignetPayload } from '../dist/v3.js';
import { createXignetRouteHandlers } from '../dist/next.js';
import { xignetPlugin, XIGNET_PROVIDER } from '../dist/plugin.js';

async function fixture(
  t,
  transactions = false,
  {
    userCollection = 'users',
    cmsOrigin = 'https://cms.example.test',
    clientId = 'website-web',
    admissionScope = 'cms:access',
    sessionAuthentication = 'mixed',
    managedUsers = false,
  } = {},
) {
  const folder = await mkdtemp(join(tmpdir(), 'xignet-sso-'));
  const keys = await generateKeyPair('RS256');
  const jwk = {
    ...(await exportJWK(keys.publicKey)),
    kid: 'test',
    alg: 'RS256',
  };
  const codes = new Map();
  let issuer;
  let hooks = { before: 0, after: 0 };
  const sign = (subject, audience, extra = {}) =>
    new SignJWT({
      iss: issuer,
      aud: audience,
      sub: subject,
      client_id: clientId,
      scope: `openid email ${admissionScope}`,
      exp: Math.floor(Date.now() / 1000) + 120,
      ...extra,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test' })
      .sign(keys.privateKey);
  const server = createServer(async (req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.url === '/.well-known/openid-configuration')
      return res.end(
        JSON.stringify({
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
        }),
      );
    if (req.url === '/jwks') return res.end(JSON.stringify({ keys: [jwk] }));
    if (req.url === '/token') {
      let body = '';
      for await (const chunk of req) body += chunk;
      const params = new URLSearchParams(body);
      const entry = codes.get(params.get('code'));
      codes.delete(params.get('code'));
      if (
        !entry ||
        params.get('client_id') !== clientId ||
        params.get('redirect_uri') !== `${cmsOrigin}/auth/xignet/callback` ||
        createHash('sha256')
          .update(params.get('code_verifier') ?? '')
          .digest('base64url') !== entry.challenge
      ) {
        res.statusCode = 400;
        return res.end('{}');
      }
      return res.end(
        JSON.stringify({
          access_token: await sign(entry.subject, `${cmsOrigin}/api/mcp`),
          id_token: await sign(entry.subject, clientId, {
            email: 'display@example.test',
          }),
        }),
      );
    }
    res.statusCode = 404;
    res.end('{}');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  issuer = `http://127.0.0.1:${server.address().port}`;
  const createIntegration = managedUsers
    ? (settings) => {
        const { issuer, jwksUri, resolveUser, sessionAuthentication, ...rest } =
          settings;
        return xignetPlugin({
          ...rest,
          provider: { issuer, jwksUri },
          users: {
            canManageBindings: (req) => req.user?.role === 'admin',
            allowUser: (user) => ['admin', 'editor'].includes(user.role),
            revokeOnFields: ['role'],
          },
        });
      }
    : createXignetPayload;
  const integration = createIntegration({
    issuer,
    jwksUri: `${issuer}/jwks`,
    resource: `${cmsOrigin}/api/mcp`,
    allowInsecureLoopback: true,
    admissionScopes: [admissionScope],
    userCollection,
    sessionAuthentication,
    resolveUser: async ({ identity, payload }) => {
      const { docs } = await payload.find({
        collection: userCollection,
        where: { subject: { equals: identity.subject } },
        limit: 1,
        overrideAccess: true,
      });
      if (!docs[0]) return { status: 'denied', reason: 'unbound' };
      return docs[0].enabled
        ? {
            status: 'allowed',
            user: { ...docs[0], collection: userCollection },
          }
        : { status: 'denied', reason: 'disabled' };
    },
    mcp: { enabled: false, collections: {} },
    login: {
      enabled: true,
      clientId,
      redirectUri: `${cmsOrigin}/auth/xignet/callback`,
      scopes: ['openid', 'email'],
      transactionSecret: randomBytes(32).toString('hex'),
      successRedirect: '/admin',
      session: { maxAgeSeconds: 120, absoluteMaxAgeSeconds: 240 },
    },
  });
  const config = await buildConfig({
    secret: randomBytes(32).toString('hex'),
    serverURL: cmsOrigin,
    telemetry: false,
    admin: { user: userCollection, importMap: { autoGenerate: false } },
    typescript: { autoGenerate: false },
    db: sqliteAdapter({
      client: { url: `file:${folder}/test.sqlite` },
      push: true,
      ...(transactions ? { transactionOptions: { behavior: 'deferred' } } : {}),
    }),
    collections: [
      {
        slug: userCollection,
        auth: { useSessions: true, tokenExpiration: 3600 },
        hooks: {
          beforeLogin: [
            ({ user, req }) => {
              hooks.before++;
              hooks.beforeContext = {
                header: req.headers.get('x-login-context'),
                pathname: req.pathname,
              };
              return user;
            },
          ],
          afterLogin: [
            ({ user, req }) => {
              hooks.after++;
              hooks.afterContext = {
                header: req.headers.get('x-login-context'),
                pathname: req.pathname,
              };
              if (hooks.failAfter)
                throw new Error(
                  'private-sensitive-hook-message\nprivate-sensitive-continuation',
                );
              return { ...user, hookEnrichment: 'from-first-hook' };
            },
            ({ user }) => {
              hooks.chainedValue = user.hookEnrichment;
              return user;
            },
          ],
        },
        fields: managedUsers
          ? [{ name: 'role', type: 'text' }]
          : [
              { name: 'subject', type: 'text' },
              { name: 'enabled', type: 'checkbox' },
            ],
      },
    ],
    plugins: [managedUsers ? integration : integration.plugin()],
  });
  // Drizzle's development schema cache is process-wide rather than per DB.
  const previousForcePush = process.env.PAYLOAD_FORCE_DRIZZLE_PUSH;
  process.env.PAYLOAD_FORCE_DRIZZLE_PUSH = 'true';
  let payload;
  try {
    payload = await getPayload({ config, key: folder });
  } finally {
    if (previousForcePush === undefined)
      delete process.env.PAYLOAD_FORCE_DRIZZLE_PUSH;
    else process.env.PAYLOAD_FORCE_DRIZZLE_PUSH = previousForcePush;
  }
  t.after(async () => {
    await payload.destroy();
    await new Promise((resolve) => server.close(resolve));
    await rm(folder, { recursive: true, force: true });
  });
  const user = await payload.create({
    collection: userCollection,
    data: {
      email: 'one@example.test',
      ...(!managedUsers && sessionAuthentication === 'mixed'
        ? { password: 'fixture-only-password-long' }
        : {}),
      ...(managedUsers
        ? { role: 'admin', xignetSubject: 'one' }
        : { subject: 'one', enabled: true }),
    },
  });
  const handlers = createXignetRouteHandlers(integration, {
    getPayload: async () => payload,
  });
  const requestFor = (cookie, path = `/api/${userCollection}/me`) =>
    new Request(`${cmsOrigin}${path}`, {
      headers: { cookie, origin: cmsOrigin },
    });
  return {
    payload,
    integration,
    handlers,
    user,
    issuer,
    cmsOrigin,
    hooks,
    requestFor,
    async begin(subject = 'one') {
      const response = await handlers.login(
        new Request(`${cmsOrigin}/auth/xignet/login`),
      );
      assert.equal(response.status, 303);
      assert.match(response.headers.get('set-cookie'), /; Secure/);
      assert.match(
        response.headers.get('set-cookie'),
        /HttpOnly; SameSite=Lax/,
      );
      const auth = new URL(response.headers.get('location'));
      const cookie = response.headers.get('set-cookie').split(';')[0];
      const code = randomBytes(24).toString('base64url');
      codes.set(code, {
        subject,
        challenge: auth.searchParams.get('code_challenge'),
      });
      return {
        cookie,
        url: `${cmsOrigin}/auth/xignet/callback?state=${auth.searchParams.get('state')}&code=${code}`,
      };
    },
    async complete(begin, headers = {}) {
      const response = await handlers.callback(
        new Request(begin.url, {
          headers: {
            cookie: begin.cookie,
            'x-login-context': 'callback-context',
            ...headers,
          },
        }),
      );
      const cookie = response.headers
        .getSetCookie()
        .find((cookie) => cookie.startsWith('payload-token='))
        ?.split(';')[0];
      return { response, cookie };
    },
    async signedIn() {
      const result = await this.complete(await this.begin());
      assert.equal(result.response.status, 303);
      assert.ok(result.cookie);
      return result;
    },
    async authenticatedReq(
      cookie,
      path = `/api/${userCollection}/refresh-token`,
    ) {
      const request = requestFor(cookie, path);
      const { user } = await payload.auth({ headers: request.headers });
      assert.ok(user);
      return createLocalReq({ req: request, user }, payload);
    },
  };
}

test('SSO creates native Payload sessions with bounded refresh and revocation', async (t) => {
  const f = await fixture(t);
  const errorEvents = [];
  t.mock.method(f.payload.logger, 'error', (event) => {
    errorEvents.push(event);
  });
  await t.test(
    'transaction is encrypted, callback clears it, SID authenticates natively',
    async () => {
      const begin = await f.begin();
      assert.equal(begin.cookie.split('=')[1].split('.').length, 5);
      const { response, cookie } = await f.complete(begin);
      assert.equal(response.status, 303);
      assert.equal(response.headers.get('location'), `${f.cmsOrigin}/admin`);
      assert.ok(
        response.headers
          .getSetCookie()
          .some(
            (c) =>
              c.startsWith('xignet_login.users=;') && c.includes('Max-Age=0'),
          ),
      );
      const auth = await f.payload.auth({
        headers: f.requestFor(cookie).headers,
      });
      assert.equal(auth.user.id, f.user.id);
      const jwt = decodeJwt(cookie.slice('payload-token='.length));
      assert.equal(jwt.sid, auth.user._sid);
      assert.equal(jwt.__xignet_sso, true);
      assert.ok(jwt.exp - jwt.iat <= 120);
      assert.equal(f.hooks.before, 1);
      assert.equal(f.hooks.after, 1);
      assert.deepEqual(f.hooks.beforeContext, {
        header: 'callback-context',
        pathname: '/auth/xignet/callback',
      });
      assert.deepEqual(f.hooks.afterContext, f.hooks.beforeContext);
      assert.equal(f.hooks.chainedValue, 'from-first-hook');
      assert.equal((await f.complete(begin)).response.status, 401);
    },
  );
  await t.test(
    'Next callbacks use configured public origin and retain path validation',
    async () => {
      const begin = await f.begin();
      const incoming = new URL(begin.url);
      const proxied = {
        ...begin,
        url: `https://0.0.0.0:3050${incoming.pathname}${incoming.search}`,
      };
      const result = await f.complete(proxied, {
        host: 'untrusted.example.test',
        'x-forwarded-host': 'untrusted.example.test',
        'x-forwarded-proto': 'http',
      });
      assert.equal(result.response.status, 303);
      assert.equal(
        result.response.headers.get('location'),
        `${f.cmsOrigin}/admin`,
      );
      assert.equal(
        (await f.payload.auth({ headers: f.requestFor(result.cookie).headers }))
          .user.id,
        f.user.id,
      );
      const wrongPath = await f.begin();
      wrongPath.url = wrongPath.url.replace(
        '/auth/xignet/callback?',
        '/wrong/callback?',
      );
      assert.equal((await f.complete(wrongPath)).response.status, 401);
    },
  );
  await t.test(
    'missing cookie, mismatched state and unbound identity never create a session',
    async () => {
      const before = await f.payload.count({
        collection: 'xignet-sessions',
        overrideAccess: true,
      });
      const begin = await f.begin();
      assert.equal(
        (await f.handlers.callback(new Request(begin.url))).status,
        401,
      );
      assert.equal(
        (
          await f.complete({
            ...begin,
            url: begin.url.replace('state=', 'state=wrong'),
          })
        ).response.status,
        401,
      );
      assert.equal(
        (await f.complete(await f.begin('unbound'))).response.status,
        403,
      );
      const after = await f.payload.count({
        collection: 'xignet-sessions',
        overrideAccess: true,
      });
      assert.equal(after.totalDocs, before.totalDocs);
    },
  );
  await t.test(
    'refresh preserves SID and cannot pass the absolute expiry',
    async () => {
      const { cookie } = await f.signedIn();
      const jwt = decodeJwt(cookie.slice('payload-token='.length));
      const expiresAt = new Date(Date.now() + 5000).toISOString();
      await f.payload.update({
        collection: 'xignet-sessions',
        where: { sid: { equals: jwt.sid } },
        overrideAccess: true,
        data: { absoluteExpiresAt: expiresAt },
      });
      const refreshed = await refreshOperation({
        collection: f.payload.collections.users,
        req: await f.authenticatedReq(cookie),
      });
      const next = decodeJwt(refreshed.refreshedToken);
      assert.equal(next.sid, jwt.sid);
      assert.equal(next.__xignet_sso, true);
      assert.ok(next.exp <= Math.floor(Date.parse(expiresAt) / 1000));
      assert.ok(!JSON.stringify(refreshed.user).includes('hash'));
    },
  );
  await t.test(
    'metadata expiry and local disablement invalidate an unexpired cookie',
    async () => {
      const { cookie } = await f.signedIn();
      const jwt = decodeJwt(cookie.slice('payload-token='.length));
      await f.payload.update({
        collection: 'xignet-sessions',
        where: { sid: { equals: jwt.sid } },
        overrideAccess: true,
        data: { absoluteExpiresAt: new Date(Date.now() - 1000).toISOString() },
      });
      assert.equal(
        (await f.payload.auth({ headers: f.requestFor(cookie).headers })).user,
        null,
      );
      const second = await f.signedIn();
      await f.payload.update({
        collection: 'users',
        id: f.user.id,
        data: { enabled: false },
      });
      assert.equal(
        (await f.payload.auth({ headers: f.requestFor(second.cookie).headers }))
          .user,
        null,
      );
      await f.payload.update({
        collection: 'users',
        id: f.user.id,
        data: { enabled: true },
      });
      assert.equal(
        (await f.payload.auth({ headers: f.requestFor(second.cookie).headers }))
          .user,
        null,
        're-enabling must not revive a revoked SSO cookie',
      );
    },
  );
  await t.test(
    'SSO metadata cannot authorize another CMS resource',
    async () => {
      const { cookie } = await f.signedIn();
      const jwt = decodeJwt(cookie.slice('payload-token='.length));
      await f.payload.update({
        collection: 'xignet-sessions',
        where: { sid: { equals: jwt.sid } },
        overrideAccess: true,
        data: { resource: 'https://other-cms.example/api/mcp' },
      });
      assert.equal(
        (await f.payload.auth({ headers: f.requestFor(cookie).headers })).user,
        null,
      );
    },
  );
  await t.test('logout removes native SID and session metadata', async () => {
    const { cookie } = await f.signedIn();
    const jwt = decodeJwt(cookie.slice('payload-token='.length));
    await logoutOperation({
      collection: f.payload.collections.users,
      req: await f.authenticatedReq(cookie, '/api/users/logout'),
    });
    assert.equal(
      (await f.payload.auth({ headers: f.requestFor(cookie).headers })).user,
      null,
    );
    assert.equal(
      (
        await f.payload.count({
          collection: 'xignet-sessions',
          overrideAccess: true,
          where: { sid: { equals: jwt.sid } },
        })
      ).totalDocs,
      0,
    );
  });
  await t.test(
    'explicit user revocation removes SSO sessions but keeps local login usable',
    async () => {
      const local = await f.payload.login({
        collection: 'users',
        data: {
          email: 'one@example.test',
          password: 'fixture-only-password-long',
        },
      });
      const localCookie = `payload-token=${local.token}`;
      assert.equal(
        (await f.payload.auth({ headers: f.requestFor(localCookie).headers }))
          .user.id,
        f.user.id,
      );
      const { cookie } = await f.signedIn();
      await f.integration.revokeUserSessions({
        payload: f.payload,
        userId: f.user.id,
      });
      assert.equal(
        (await f.payload.auth({ headers: f.requestFor(cookie).headers })).user,
        null,
      );
      assert.equal(
        (await f.payload.auth({ headers: f.requestFor(localCookie).headers }))
          .user.id,
        f.user.id,
      );
      const refreshed = await refreshOperation({
        collection: f.payload.collections.users,
        req: await f.authenticatedReq(localCookie),
      });
      assert.equal(
        decodeJwt(refreshed.refreshedToken).sid,
        decodeJwt(local.token).sid,
      );
      assert.equal(
        decodeJwt(refreshed.refreshedToken).exp -
          decodeJwt(refreshed.refreshedToken).iat,
        3600,
      );
      assert.equal(decodeJwt(local.token).__xignet_sso, undefined);
      assert.equal(
        decodeJwt(local.token).exp - decodeJwt(local.token).iat,
        3600,
      );
    },
  );
  await t.test(
    'hook failure rolls back SID/metadata, clears transaction and returns safe 500',
    async () => {
      const beforeMetadata = await f.payload.count({
        collection: 'xignet-sessions',
        overrideAccess: true,
      });
      const beforeUser = await f.payload.findByID({
        collection: 'users',
        id: f.user.id,
        showHiddenFields: true,
        overrideAccess: true,
      });
      f.hooks.failAfter = true;
      const result = await f.complete(await f.begin());
      f.hooks.failAfter = false;
      assert.equal(result.response.status, 500);
      assert.ok(
        !JSON.stringify(await result.response.json()).includes(
          'private-sensitive',
        ),
      );
      assert.ok(!JSON.stringify(errorEvents).includes('private-sensitive'));
      assert.equal(result.cookie, undefined);
      assert.ok(
        result.response.headers
          .getSetCookie()
          .some(
            (c) =>
              c.startsWith('xignet_login.users=;') && c.includes('Max-Age=0'),
          ),
      );
      const afterMetadata = await f.payload.count({
        collection: 'xignet-sessions',
        overrideAccess: true,
      });
      const afterUser = await f.payload.findByID({
        collection: 'users',
        id: f.user.id,
        showHiddenFields: true,
        overrideAccess: true,
      });
      assert.equal(afterMetadata.totalDocs, beforeMetadata.totalDocs);
      assert.deepEqual(afterUser.sessions, beforeUser.sessions);
    },
  );
});

test('transaction failures are observable and never issue a login cookie', async (t) => {
  const f = await fixture(t, true);
  const events = [];
  t.mock.method(f.payload.logger, 'error', (event) => events.push(event));
  const countSessions = () =>
    f.payload.count({ collection: 'xignet-sessions', overrideAccess: true });
  const before = await countSessions();
  // Real SQLite transactions: an afterLogin failure must undo both tables.
  f.hooks.failAfter = true;
  const failure = await f.complete(await f.begin());
  assert.equal(failure.response.status, 500);
  assert.equal(failure.cookie, undefined);
  assert.equal((await countSessions()).totalDocs, before.totalDocs);
  f.hooks.failAfter = false;
  const rollback = f.payload.db.rollbackTransaction.bind(f.payload.db);
  const commitMock = t.mock.method(
    f.payload.db,
    'commitTransaction',
    async () => {
      throw new Error('private-commit-message');
    },
  );
  const commitFailure = await f.complete(await f.begin());
  commitMock.mock.restore();
  assert.equal(commitFailure.response.status, 500);
  assert.equal(commitFailure.cookie, undefined);
  assert.equal(commitFailure.response.headers.has('location'), false);
  assert.equal((await countSessions()).totalDocs, before.totalDocs);
  f.hooks.failAfter = true;
  const rollbackMock = t.mock.method(
    f.payload.db,
    'rollbackTransaction',
    async (id) => {
      await rollback(id);
      throw new Error('private-rollback-message');
    },
  );
  const rollbackFailure = await f.complete(await f.begin());
  rollbackMock.mock.restore();
  assert.equal(rollbackFailure.response.status, 503);
  assert.equal(rollbackFailure.cookie, undefined);
  assert.ok(
    events.some((event) => event.event === 'xignet_login_cleanup_failed'),
  );
  assert.ok(!JSON.stringify(events).includes('private-'));
});

test('metadata failure cannot conceal a nested rollback failure', async (t) => {
  const f = await fixture(t, true);
  const events = [];
  t.mock.method(f.payload.logger, 'error', (event) => events.push(event));
  const before = await f.payload.count({
    collection: 'xignet-sessions',
    overrideAccess: true,
  });
  const rollback = f.payload.db.rollbackTransaction.bind(f.payload.db);
  const rollbackMock = t.mock.method(
    f.payload.db,
    'rollbackTransaction',
    async (id) => {
      await rollback(id);
      if (id !== undefined) throw new Error('private-nested-rollback-failure');
    },
  );
  f.payload.collections['xignet-sessions'].config.hooks.beforeChange.push(
    () => {
      throw new Error('private-metadata-write-failure');
    },
  );
  const result = await f.complete(await f.begin());
  rollbackMock.mock.restore();
  assert.equal(result.response.status, 503);
  assert.equal(result.cookie, undefined);
  assert.ok(events.some((e) => e.event === 'xignet_login_cleanup_failed'));
  assert.ok(!JSON.stringify(events).includes('private-'));
  assert.equal(
    (
      await f.payload.count({
        collection: 'xignet-sessions',
        overrideAccess: true,
      })
    ).totalDocs,
    before.totalDocs,
  );
});

test('a fulfilled Drizzle commit cannot issue a cookie after underlying rollback', async (t) => {
  const f = await fixture(t, true);
  const before = await f.payload.count({
    collection: 'xignet-sessions',
    overrideAccess: true,
  });
  const transaction = f.payload.db.drizzle.transaction.bind(
    f.payload.db.drizzle,
  );
  let underlyingRejected = false;
  const mock = t.mock.method(
    f.payload.db.drizzle,
    'transaction',
    (operation, options) =>
      transaction(async (tx) => {
        await operation(tx);
        underlyingRejected = true;
        throw new Error('private-underlying-commit-failure');
      }, options),
  );
  const result = await f.complete(await f.begin());
  mock.mock.restore();
  assert.equal(underlyingRejected, true);
  assert.equal(result.response.status, 503);
  assert.equal(result.cookie, undefined);
  assert.equal(
    (
      await f.payload.count({
        collection: 'xignet-sessions',
        overrideAccess: true,
      })
    ).totalDocs,
    before.totalDocs,
  );
  const user = await f.payload.db.findOne({
    collection: 'users',
    where: { id: { equals: f.user.id } },
  });
  assert.equal(user.sessions?.length ?? 0, 0);
});

test('another CMS reuses SSO with its own auth collection and trust configuration', async (t) => {
  const f = await fixture(t, false, {
    userCollection: 'members',
    cmsOrigin: 'https://members.example.test',
    clientId: 'members-web',
    admissionScope: 'members:access',
  });
  const begin = await f.begin();
  assert.ok(begin.cookie.startsWith('xignet_login.members='));
  const signed = await f.complete(begin);
  assert.equal(signed.response.status, 303);
  assert.equal(signed.response.headers.get('location'), `${f.cmsOrigin}/admin`);
  const auth = await f.payload.auth({
    headers: f.requestFor(signed.cookie).headers,
  });
  assert.equal(auth.user.collection, 'members');
  assert.equal(auth.user.id, f.user.id);
  const refreshed = await refreshOperation({
    collection: f.payload.collections.members,
    req: await f.authenticatedReq(signed.cookie),
  });
  assert.equal(decodeJwt(refreshed.refreshedToken).collection, 'members');
  await f.integration.revokeUserSessions({
    payload: f.payload,
    userId: f.user.id,
  });
  assert.equal(
    (await f.payload.auth({ headers: f.requestFor(signed.cookie).headers }))
      .user,
    null,
  );
});

test('Xignet-only users have no password and use the supported custom session strategy', async (t) => {
  const f = await fixture(t, false, { sessionAuthentication: 'xignet-only' });
  const collection = f.payload.collections.users;
  assert.deepEqual(collection.config.auth.disableLocalStrategy, {
    enableFields: true,
  });
  const stored = await f.payload.db.findOne({
    collection: 'users',
    where: { id: { equals: f.user.id } },
  });
  assert.ok(!stored.hash && !stored.salt);
  await assert.rejects(
    f.payload.login({
      collection: 'users',
      data: {
        email: f.user.email,
        password: 'not-a-credential',
      },
    }),
  );
  await assert.rejects(
    f.payload.update({
      collection: 'users',
      id: f.user.id,
      data: { password: 'cannot-enable-local-login' },
    }),
  );

  const req = await createLocalReq({}, f.payload);
  const { sid } = await addSessionToUser({
    collectionConfig: collection.config,
    payload: f.payload,
    req,
    user: { ...stored, collection: 'users' },
  });
  const unmarked = await jwtSign({
    fieldsToSign: getFieldsToSign({
      collectionConfig: collection.config,
      user: { ...stored, collection: 'users' },
      email: stored.email,
      sid,
    }),
    secret: f.payload.secret,
    tokenExpiration: 120,
  });
  assert.equal(
    (
      await f.payload.auth({
        headers: f.requestFor(`payload-token=${unmarked.token}`).headers,
      })
    ).user,
    null,
  );

  const signed = await f.signedIn();
  const auth = await f.payload.auth({
    headers: f.requestFor(signed.cookie).headers,
  });
  assert.equal(auth.user._strategy, 'xignet-session');
  const refreshed = await refreshOperation({
    collection,
    req: await f.authenticatedReq(signed.cookie),
  });
  assert.equal(decodeJwt(refreshed.refreshedToken).__xignet_sso, true);
  const refreshedCookie = `payload-token=${refreshed.refreshedToken}`;
  assert.equal(
    (await f.payload.auth({ headers: f.requestFor(refreshedCookie).headers }))
      .user.id,
    f.user.id,
  );
  await logoutOperation({
    collection,
    req: await f.authenticatedReq(refreshedCookie, '/api/users/logout'),
  });
  assert.equal(
    (await f.payload.auth({ headers: f.requestFor(refreshedCookie).headers }))
      .user,
    null,
  );
});

test('standard plugin uses the shared provider without per-project issuer settings', async () => {
  const plugin = xignetPlugin({
    resource: 'https://cms.example.test/api/mcp',
    admissionScopes: ['cms:access'],
    userCollection: 'users',
    mcp: { enabled: true, collections: {} },
    users: { canManageBindings: () => false, allowUser: () => true },
  });
  assert.equal(typeof plugin, 'function');
  assert.deepEqual((await plugin.metadata().json()).authorization_servers, [
    XIGNET_PROVIDER.issuer,
  ]);
});

test('Xignet-only configuration refuses alternative auth entry points', async () => {
  const plugin = xignetPlugin({
    resource: 'https://cms.example.test/api/mcp',
    admissionScopes: ['cms:access'],
    userCollection: 'users',
    mcp: { enabled: false, collections: {} },
    users: { canManageBindings: () => false, allowUser: () => true },
  });
  for (const auth of [
    { useAPIKey: true },
    { useSessions: false },
    {
      strategies: [
        { name: 'bypass', authenticate: async () => ({ user: null }) },
      ],
    },
  ]) {
    await assert.rejects(
      plugin({ collections: [{ slug: 'users', auth, fields: [] }] }),
    );
  }
  await assert.rejects(
    plugin({
      admin: { autoLogin: { email: 'fixture@example.test' } },
      collections: [{ slug: 'users', auth: true, fields: [] }],
    }),
    /autoLogin/,
  );
});

test('standard plugin manages passwordless accounts from admin-supplied subjects', async (t) => {
  const f = await fixture(t, false, { managedUsers: true });
  assert.equal(f.user.xignetIssuer, f.issuer);
  assert.equal(f.user.xignetSubject, 'one');
  const admin = await f.signedIn();
  const req = await f.authenticatedReq(admin.cookie);
  req.payloadAPI = 'REST';
  let editor;

  await t.test(
    'an authenticated admin creates a passwordless editor with only sub',
    async () => {
      editor = await f.payload.create({
        collection: 'users',
        req,
        overrideAccess: false,
        data: {
          email: 'editor@example.test',
          role: 'editor',
          xignetSubject: 'two',
        },
      });
      assert.equal(editor.xignetIssuer, f.issuer);
      assert.equal(editor.xignetEnabled, true);
      const stored = await f.payload.db.findOne({
        collection: 'users',
        where: { id: { equals: editor.id } },
      });
      assert.ok(!stored.hash && !stored.salt);
      await assert.rejects(
        f.payload.create({
          collection: 'users',
          req,
          data: { email: 'missing@example.test', role: 'editor' },
        }),
      );
      await assert.rejects(
        f.payload.create({
          collection: 'users',
          req,
          data: {
            email: 'foreign@example.test',
            role: 'editor',
            xignetSubject: 'three',
            xignetIssuer: 'https://foreign.example.test',
          },
        }),
      );
      await assert.rejects(
        f.payload.db.create({
          collection: 'users',
          data: {
            email: 'duplicate@example.test',
            role: 'editor',
            xignetIssuer: f.issuer,
            xignetSubject: 'two',
            xignetEnabled: true,
          },
        }),
      );
    },
  );

  await t.test(
    'native password operations cannot enable password login',
    async () => {
      const forbidden = (error) => error.status === 403;
      await assert.rejects(
        f.payload.login({
          collection: 'users',
          data: {
            email: editor.email,
            password: 'unused-password',
          },
        }),
        forbidden,
      );
      await assert.rejects(
        f.payload.forgotPassword({
          collection: 'users',
          data: {
            email: editor.email,
          },
        }),
        forbidden,
      );
      await f.payload.db.updateOne({
        collection: 'users',
        id: editor.id,
        data: {
          resetPasswordToken: 'fixture-reset-token',
          resetPasswordExpiration: new Date(Date.now() + 60000).toISOString(),
        },
      });
      await assert.rejects(
        f.payload.resetPassword({
          collection: 'users',
          data: {
            token: 'fixture-reset-token',
            password: 'cannot-install-password',
          },
        }),
        forbidden,
      );
      const stored = await f.payload.db.findOne({
        collection: 'users',
        where: { id: { equals: editor.id } },
      });
      assert.ok(!stored.hash && !stored.salt);
    },
  );

  await t.test(
    'editor signs in with Xignet but cannot change bindings',
    async () => {
      const signed = await f.complete(await f.begin('two'));
      assert.equal(signed.response.status, 303);
      const editorReq = await f.authenticatedReq(signed.cookie);
      editorReq.payloadAPI = 'REST';
      await f.payload.update({
        collection: 'users',
        id: editor.id,
        req: editorReq,
        overrideAccess: false,
        data: { xignetSubject: 'other' },
      });
      const unchanged = await f.payload.db.findOne({
        collection: 'users',
        where: { id: { equals: editor.id } },
      });
      assert.equal(unchanged.xignetSubject, 'two');
      assert.equal(unchanged.xignetIssuer, f.issuer);
      await f.payload.update({
        collection: 'users',
        id: editor.id,
        req,
        data: { role: 'admin' },
      });
      assert.equal(
        (await f.payload.auth({ headers: f.requestFor(signed.cookie).headers }))
          .user,
        null,
      );
    },
  );

  await t.test(
    'historical issuer stays stable until an explicit subject rebind',
    async () => {
      const previous = 'https://previous.example.test';
      await f.payload.db.updateOne({
        collection: 'users',
        id: editor.id,
        data: { xignetIssuer: previous },
      });
      const preserved = await f.payload.update({
        collection: 'users',
        id: editor.id,
        req,
        data: { role: 'editor' },
      });
      assert.equal(preserved.xignetIssuer, previous);
      await assert.rejects(
        f.payload.update({
          collection: 'users',
          id: editor.id,
          req,
          data: { xignetIssuer: f.issuer },
        }),
      );
      const rebound = await f.payload.update({
        collection: 'users',
        id: editor.id,
        req,
        data: { xignetSubject: 'new-two', xignetIssuer: previous },
      });
      assert.equal(rebound.xignetIssuer, f.issuer);
      assert.equal(
        (await f.complete(await f.begin('two'))).response.status,
        403,
      );
      assert.equal(
        (await f.complete(await f.begin('new-two'))).response.status,
        303,
      );
    },
  );
});
