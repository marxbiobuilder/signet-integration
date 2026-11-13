import assert from 'node:assert/strict';
import { test } from 'node:test';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { buildConfig, getPayload, handleEndpoints } from 'payload';
import { sqliteAdapter } from '@payloadcms/db-sqlite';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { createXignetPayload } from '../dist/v3.js';
import { isXignetService } from '../dist/plugin.js';

async function fixture(t, legacyAPIKeys = false) {
  const dir = await mkdtemp(join(tmpdir(), 'xignet-rest-'));
  const keys = await generateKeyPair('RS256');
  const jwk = {
    ...(await exportJWK(keys.publicKey)),
    kid: 'rest',
    alg: 'RS256',
  };
  const server = createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const issuer = `http://127.0.0.1:${server.address().port}`;
  const origin = 'https://cms.example.test';
  let active = true;
  let user;
  const integration = createXignetPayload({
    issuer,
    jwksUri: `${issuer}/jwks`,
    allowInsecureLoopback: true,
    resource: `${origin}/api/mcp`,
    admissionScopes: ['cms:access'],
    userCollection: 'users',
    sessionAuthentication: 'xignet-only',
    legacyAPIKeys,
    resolveUser: async ({ identity }) => {
      if (identity.subject === 'resolver-failure')
        throw new Error('private-database-error');
      return active && identity.subject === 'person'
        ? { status: 'allowed', user: { ...user, collection: 'users' } }
        : { status: 'denied', reason: 'disabled' };
    },
    mcp: { enabled: false, collections: {} },
    rest: {
      enabled: true,
      admissionScopes: ['cms:access'],
      collections: {
        documents: { read: ['cms:read'], create: ['cms:write', 'cms:publish'] },
        pages: {
          read: ['cms:read'],
          create: ['cms:write', 'cms:publish'],
          update: ['cms:write', 'cms:publish'],
        },
      },
      globals: {
        settings: { read: ['cms:read'], update: ['cms:write', 'cms:publish'] },
      },
      services: [{ subject: 'service:sync', clientId: 'service:sync' }],
      endpoints: [{ path: '/sync/info', method: 'GET', scopes: ['cms:sync'] }],
    },
  });
  const localAccess = ({ req }) =>
    isXignetService(req) || req.user?.role === 'editor';
  const config = await buildConfig({
    secret: randomBytes(32).toString('hex'),
    serverURL: origin,
    telemetry: false,
    admin: { user: 'users', importMap: { autoGenerate: false } },
    typescript: { autoGenerate: false },
    db: sqliteAdapter({ client: { url: `file:${dir}/db.sqlite` }, push: true }),
    collections: [
      { slug: 'users', auth: true, fields: [{ name: 'role', type: 'text' }] },
      {
        slug: 'pages',
        access: {
          read: () => true,
          create: localAccess,
          update: localAccess,
          delete: localAccess,
        },
        fields: [{ name: 'title', type: 'text', required: true }],
      },
      {
        slug: 'documents',
        upload: { staticDir: `${dir}/uploads`, mimeTypes: ['text/plain'] },
        access: { read: () => true, create: localAccess },
        fields: [{ name: 'name', type: 'text', required: true }],
      },
      { slug: 'private-data', access: { read: () => true }, fields: [] },
    ],
    globals: [
      {
        slug: 'settings',
        access: { read: () => true, update: localAccess },
        fields: [{ name: 'title', type: 'text' }],
      },
    ],
    endpoints: [
      {
        path: '/sync/info',
        method: 'get',
        handler: (req) =>
          Response.json({
            service: isXignetService(req),
            collection: req.user?.collection,
            role: req.user?.role,
          }),
      },
    ],
    plugins: [integration.plugin()],
  });
  process.env.PAYLOAD_FORCE_DRIZZLE_PUSH = 'true';
  const payload = await getPayload({ config, key: dir });
  delete process.env.PAYLOAD_FORCE_DRIZZLE_PUSH;
  t.after(async () => {
    await payload.destroy();
    await new Promise((r) => server.close(r));
    await rm(dir, { recursive: true, force: true });
  });
  user = await payload.create({
    collection: 'users',
    data: {
      email: 'editor@example.test',
      role: 'editor',
      ...(legacyAPIKeys
        ? { enableAPIKey: true, apiKey: 'fixture-api-key' }
        : {}),
    },
  });
  const sign = (extra = {}) =>
    new SignJWT({
      iss: issuer,
      aud: `${origin}/api/mcp`,
      sub: 'service:sync',
      client_id: 'service:sync',
      scope: 'cms:access cms:read cms:write cms:publish cms:sync',
      exp: Math.floor(Date.now() / 1000) + 120,
      ...extra,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'rest' })
      .sign(keys.privateKey);
  async function request(path, token, method = 'GET', data, headers = {}) {
    const req = new Request(`${origin}/api${path}`, {
      method,
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(data && !(data instanceof FormData)
          ? { 'content-type': 'application/json' }
          : {}),
        ...headers,
      },
      ...(data
        ? { body: data instanceof FormData ? data : JSON.stringify(data) }
        : {}),
    });
    return integration.rest(req, payload, () =>
      handleEndpoints({ config, request: req, payloadInstanceCacheKey: dir }),
    );
  }
  return {
    sign,
    request,
    payload,
    integration,
    disable: () => {
      active = false;
    },
  };
}

test('REST and MCP share an audience while enforcing REST scopes, human bindings and service identity', async (t) => {
  const f = await fixture(t);
  const token = await f.sign();
  let id;
  await t.test(
    'service creates, reads, updates content and globals without an admin role',
    async () => {
      const created = await f.request('/pages', token, 'POST', {
        title: 'first',
      });
      assert.equal(created.status, 201);
      id = (await created.json()).doc.id;
      assert.equal((await f.request(`/pages/${id}`, token)).status, 200);
      assert.equal(
        (await f.request(`/pages/${id}`, token, 'PATCH', { title: 'second' }))
          .status,
        200,
      );
      assert.equal(
        (
          await f.request('/globals/settings', token, 'POST', {
            title: 'global',
          })
        ).status,
        200,
      );
      assert.deepEqual(await (await f.request('/sync/info', token)).json(), {
        service: true,
        collection: 'xignet-services',
      });
    },
  );
  await t.test(
    'native multipart parsing retains uploaded document metadata',
    async () => {
      const form = new FormData();
      form.append(
        'file',
        new Blob(['fixture upload'], { type: 'text/plain' }),
        'fixture.txt',
      );
      form.append('_payload', JSON.stringify({ name: 'Retained metadata' }));
      const response = await f.request('/documents', token, 'POST', form);
      assert.equal(response.status, 201);
      const doc = (await response.json()).doc;
      assert.equal(doc.name, 'Retained metadata');
      assert.equal(doc.filename, 'fixture.txt');
    },
  );
  await t.test(
    'resolver outage is observable without leaking its message',
    async () => {
      const events = [];
      t.mock.method(f.payload.logger, 'error', (entry) => events.push(entry));
      const response = await f.request(
        '/pages',
        await f.sign({ sub: 'resolver-failure', client_id: 'interactive' }),
      );
      assert.equal(response.status, 503);
      assert.equal(events.at(-1).category, 'authentication_internal_error');
      assert.ok(!JSON.stringify(events).includes('private-database-error'));
      assert.ok(!(await response.text()).includes('private-database-error'));
    },
  );
  await t.test(
    'deny users, deletion, bulk update, unlisted endpoints, GraphQL and private collections',
    async () => {
      for (const [path, method] of [
        ['/users', 'GET'],
        [`/pages/${id}`, 'DELETE'],
        ['/pages', 'PATCH'],
        ['/pages/access', 'GET'],
        ['/graphql', 'POST'],
        ['/private-data', 'GET'],
        ['/sync', 'POST'],
      ]) {
        assert.equal(
          (await f.request(path, token, method)).status,
          403,
          `${method} ${path}`,
        );
      }
    },
  );
  await t.test(
    'invalid or unsuitable tokens fail before public fallback or cookie authentication',
    async () => {
      for (const extra of [
        { aud: 'https://cms.example.test/api' },
        { aud: 'https://issuer.example.test/directory' },
        { iss: 'https://evil.test' },
        { exp: 1 },
      ]) {
        assert.equal(
          (await f.request('/pages', await f.sign(extra))).status,
          401,
        );
      }
      assert.equal(
        (
          await f.request('/pages', `${token}x`, 'GET', undefined, {
            cookie: 'payload-token=untrusted',
          })
        ).status,
        401,
      );
      assert.equal(
        (
          await f.request('/pages', undefined, 'GET', undefined, {
            authorization: 'Bearer',
          })
        ).status,
        401,
      );
      assert.equal((await f.request('/pages')).status, 200);
    },
  );
  await t.test(
    'local allowlist and operation scopes remain mandatory',
    async () => {
      for (const extra of [
        { sub: 'service:other', client_id: 'service:other' },
        { client_id: 'service:other' },
        { scope: 'cms:read' },
        { scope: 'cms:access' },
      ])
        assert.equal(
          (await f.request('/pages', await f.sign(extra))).status,
          403,
        );
      assert.equal(
        (
          await f.request(
            '/pages',
            await f.sign({ scope: 'cms:access cms:write' }),
            'POST',
            { title: 'no-publish' },
          )
        ).status,
        403,
      );
      assert.equal(
        (
          await f.request(
            '/sync/info',
            await f.sign({ scope: 'cms:access cms:read' }),
          )
        ).status,
        403,
      );
    },
  );
  await t.test(
    'human access resolves the local account on each request',
    async () => {
      const human = await f.sign({ sub: 'person', client_id: 'interactive' });
      assert.equal(
        (await f.request('/pages', human, 'POST', { title: 'human' })).status,
        201,
      );
      f.disable();
      assert.equal((await f.request('/pages', human)).status, 403);
    },
  );
  await t.test(
    'API keys are disabled after the migration flag is off',
    async () => {
      assert.equal(f.payload.collections.users.config.auth.useAPIKey, false);
      assert.equal(
        (
          await f.request(
            '/pages',
            undefined,
            'POST',
            { title: 'no' },
            { authorization: 'users API-Key fixture-api-key' },
          )
        ).status,
        403,
      );
    },
  );
});

test('transitional API keys coexist with Xignet-only humans and REST service tokens', async (t) => {
  const f = await fixture(t, true);
  assert.equal(
    (
      await f.request(
        '/pages',
        undefined,
        'POST',
        { title: 'legacy' },
        { authorization: 'users API-Key fixture-api-key' },
      )
    ).status,
    201,
  );
  assert.equal((await f.request('/pages', await f.sign())).status, 200);
  await assert.rejects(
    f.payload.login({
      collection: 'users',
      data: { email: 'editor@example.test', password: 'anything' },
    }),
  );
});
