import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { buildConfig, createLocalReq, getPayload } from 'payload';
import { sqliteAdapter } from '@payloadcms/db-sqlite';
import { createXignetPayload } from '../dist/v3.js';
import { createXignetRouteHandlers } from '../dist/next.js';

async function fixture(t) {
  // mcp-handler owns a process-wide cleanup interval with no public dispose.
  // Explicitly release intervals created by this fixture after all assertions.
  const intervals = new Set();
  const originalSetInterval = globalThis.setInterval;
  const intervalMock = t.mock.method(globalThis, 'setInterval', (...args) => {
    const handle = originalSetInterval(...args);
    intervals.add(handle);
    return handle;
  });
  t.after(() => {
    for (const handle of intervals) clearInterval(handle);
    intervalMock.mock.restore();
  });

  const folder = await mkdtemp(join(tmpdir(), 'xignet-mcp-'));
  const keys = await generateKeyPair('RS256');
  const jwk = {
    ...(await exportJWK(keys.publicKey)),
    kid: 'test',
    alg: 'RS256',
  };
  let issuerStatus = 200;
  const server = createServer((_req, res) => {
    res.writeHead(issuerStatus, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ keys: [jwk] }));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const issuer = `http://127.0.0.1:${server.address().port}`;
  let resolverUnavailable = false;
  const options = {
    issuer,
    jwksUri: `${issuer}/jwks`,
    resource: `${issuer}/api/mcp`,
    allowInsecureLoopback: true,
    clockToleranceSeconds: 0,
    admissionScopes: ['cms:access'],
    userCollection: 'users',
    resolveUser: async ({ identity, payload }) => {
      if (resolverUnavailable) throw new Error('database lookup unavailable');
      const { docs } = await payload.find({
        collection: 'users',
        where: { subject: { equals: identity.subject } },
        limit: 1,
        overrideAccess: true,
      });
      const user = docs[0];
      if (!user) return { status: 'denied', reason: 'unbound' };
      if (!user.enabled) return { status: 'denied', reason: 'disabled' };
      return { status: 'allowed', user: { ...user, collection: 'users' } };
    },
    mcp: {
      enabled: true,
      collections: {
        bulletins: {
          find: { scopes: ['cms:read'] },
          update: { scopes: ['cms:write'] },
          mutationPolicy: () => ['cms:publish'],
        },
      },
      scopesSupported: ['cms:publish'],
    },
  };
  const xignet = createXignetPayload(options);
  const config = await buildConfig({
    secret: randomBytes(32).toString('hex'),
    serverURL: issuer,
    admin: { user: 'users', importMap: { autoGenerate: false } },
    typescript: { autoGenerate: false },
    telemetry: false,
    db: sqliteAdapter({
      client: { url: `file:${folder}/test.sqlite` },
      push: true,
    }),
    collections: [
      {
        slug: 'users',
        auth: true,
        fields: [
          { name: 'subject', type: 'text' },
          { name: 'enabled', type: 'checkbox', defaultValue: true },
        ],
      },
      {
        slug: 'bulletins',
        access: {
          read: ({ req }) =>
            req.user ? { owner: { equals: req.user.id } } : true,
          update: ({ req }) => Boolean(req.user),
        },
        fields: [
          { name: 'title', type: 'text', required: true },
          { name: 'owner', type: 'relationship', relationTo: 'users' },
          { name: 'privateNote', type: 'text', access: { read: () => false } },
        ],
      },
      {
        slug: 'restricted',
        access: { read: () => true },
        fields: [{ name: 'title', type: 'text' }],
      },
    ],
    plugins: [xignet.plugin()],
  });
  const payload = await getPayload({ config });
  t.after(async () => {
    await payload.destroy();
    await new Promise((resolve) => server.close(resolve));
    await rm(folder, { recursive: true, force: true });
  });
  const one = await payload.create({
    collection: 'users',
    data: {
      email: 'one@example.test',
      password: randomBytes(24).toString('hex'),
      subject: 'one',
      enabled: true,
    },
  });
  const two = await payload.create({
    collection: 'users',
    data: {
      email: 'two@example.test',
      password: randomBytes(24).toString('hex'),
      subject: 'two',
      enabled: true,
    },
  });
  const doc = await payload.create({
    collection: 'bulletins',
    data: {
      title: 'visible-for-one',
      owner: one.id,
      privateNote: 'PRIVATE-NEVER-RETURN',
    },
  });
  await payload.create({
    collection: 'bulletins',
    data: { title: 'only-for-two', owner: two.id },
  });
  const endpoint = payload.config.endpoints.find(
    (e) => e.path === '/mcp' && e.method === 'post',
  );
  let id = 0;
  return {
    payload,
    options,
    xignet,
    one,
    doc,
    unavailable: () => {
      resolverUnavailable = true;
    },
    issuerFail: () => {
      issuerStatus = 503;
    },
    async token(
      scope = 'cms:access cms:read',
      subject = 'one',
      claims = {},
      kid = 'test',
    ) {
      return new SignJWT({
        iss: issuer,
        sub: subject,
        client_id: 'mcp-client',
        aud: options.resource,
        exp: Math.floor(Date.now() / 1000) + 60,
        scope,
        ...claims,
      })
        .setProtectedHeader({ alg: 'RS256', kid })
        .sign(keys.privateKey);
    },
    async request(method, params, token, extraHeaders = {}) {
      const request = new Request(options.resource, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          ...(token ? { authorization: `Bearer ${token}` } : {}),
          ...extraHeaders,
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
      });
      const req = await createLocalReq({ req: request }, payload);
      const response = await endpoint.handler(req);
      const text = await response.text();
      const data = response.headers
        .get('content-type')
        ?.includes('text/event-stream')
        ? JSON.parse(
            text
              .split('\n')
              .find((line) => line.startsWith('data: '))
              .slice(6),
          )
        : text
          ? JSON.parse(text)
          : null;
      return { response, data, req, text };
    },
  };
}

test('official MCP enforces external identity, scopes and Payload access', async (t) => {
  const f = await fixture(t);
  const auditEvents = [];
  t.mock.method(f.payload.logger, 'info', (event) => {
    auditEvents.push(event);
  });
  await t.test(
    'metadata is canonical and admission requires Bearer, never cookies',
    async () => {
      const metadata = await f.xignet.metadata().json();
      assert.equal(metadata.resource, f.options.resource);
      const { response } = await f.request('tools/list', {}, undefined, {
        cookie: 'payload-token=not-a-bearer',
      });
      assert.equal(response.status, 401);
      assert.match(
        response.headers.get('www-authenticate'),
        /resource_metadata=/,
      );
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.equal(
        (await f.request('tools/list', {}, 'bad')).response.status,
        401,
      );
      assert.equal(
        (await f.request('tools/list', {}, await f.token('cms:read'))).response
          .status,
        403,
      );
    },
  );
  await t.test(
    'unbound and disabled users get local 403 without scope advice',
    async () => {
      const unbound = await f.request(
        'tools/list',
        {},
        await f.token(undefined, 'unknown'),
      );
      assert.equal(unbound.response.status, 403);
      assert.equal(unbound.response.headers.has('www-authenticate'), false);
      await f.payload.update({
        collection: 'users',
        id: f.one.id,
        data: { enabled: false },
      });
      assert.equal(
        (await f.request('tools/list', {}, await f.token())).response.status,
        403,
      );
      await f.payload.update({
        collection: 'users',
        id: f.one.id,
        data: { enabled: true },
      });
    },
  );
  await t.test('token issuer, audience and expiry are enforced', async () => {
    for (const claims of [
      { iss: 'https://other.example' },
      { aud: 'https://other.example/api/mcp' },
      { exp: 1 },
    ]) {
      assert.equal(
        (
          await f.request(
            'tools/list',
            {},
            await f.token(undefined, 'one', claims),
          )
        ).response.status,
        401,
      );
    }
  });
  await t.test(
    'tool enumeration and calls preserve document and field filters',
    async () => {
      const token = await f.token();
      const list = await f.request('tools/list', {}, token);
      assert.equal(list.response.status, 200);
      assert.deepEqual(
        list.data.result.tools.map((tool) => tool.name),
        ['findBulletins'],
      );
      const read = await f.request(
        'tools/call',
        { name: 'findBulletins', arguments: {} },
        token,
      );
      assert.ok(read.text.includes('visible-for-one'), read.text);
      assert.ok(!read.text.includes('only-for-two'));
      assert.ok(!read.text.includes('PRIVATE-NEVER-RETURN'));
      const other = await f.request(
        'tools/call',
        { name: 'findBulletins', arguments: {} },
        await f.token(undefined, 'two'),
      );
      assert.ok(other.text.includes('only-for-two'));
      assert.ok(!other.text.includes('visible-for-one'));
      const [parallelOne, parallelTwo] = await Promise.all([
        f.request(
          'tools/call',
          { name: 'findBulletins', arguments: {} },
          token,
        ),
        f.request(
          'tools/call',
          { name: 'findBulletins', arguments: {} },
          await f.token(undefined, 'two'),
        ),
      ]);
      assert.ok(
        parallelOne.text.includes('visible-for-one') &&
          !parallelOne.text.includes('only-for-two'),
      );
      assert.ok(
        parallelTwo.text.includes('only-for-two') &&
          !parallelTwo.text.includes('visible-for-one'),
      );
      const denied = await f.request(
        'tools/call',
        { name: 'updateBulletins', arguments: {} },
        token,
      );
      assert.ok(denied.data.error || denied.data.result?.isError);
    },
  );
  await t.test(
    'forged context cannot bypass guards; public Local API stays public',
    async () => {
      const req = await createLocalReq(
        {
          context: { __xignetPayloadPrincipal: {} },
          user: { ...f.one, collection: 'users' },
        },
        f.payload,
      );
      req.payloadAPI = 'MCP';
      await assert.rejects(
        f.payload.find({ collection: 'bulletins', req, overrideAccess: false }),
        (error) => error.status === 403,
      );
      const publicRead = await f.payload.find({
        collection: 'bulletins',
        overrideAccess: false,
      });
      assert.equal(publicRead.docs.length, 2);
    },
  );
  await t.test(
    'publish policy prevents write token from changing public content',
    async () => {
      const request = await f.request(
        'tools/list',
        {},
        await f.token('cms:access cms:read cms:write'),
      );
      assert.ok(
        request.data.result.tools.some(
          (tool) => tool.name === 'updateBulletins',
        ),
      );
      await assert.rejects(
        f.payload.update({
          collection: 'bulletins',
          id: f.doc.id,
          data: { title: 'must-not-publish' },
          req: request.req,
          overrideAccess: false,
        }),
        /scope insufficient/,
      );
      assert.equal(
        (await f.payload.findByID({ collection: 'bulletins', id: f.doc.id }))
          .title,
        'visible-for-one',
      );
      const authorized = await f.request(
        'tools/list',
        {},
        await f.token('cms:access cms:read cms:write cms:publish'),
      );
      const updated = await f.payload.update({
        collection: 'bulletins',
        id: f.doc.id,
        data: { title: 'published-change' },
        req: authorized.req,
        overrideAccess: false,
      });
      assert.equal(updated.title, 'published-change');
    },
  );
  await t.test(
    'audit events identify operations and clients without credentials or content',
    async () => {
      const token = await f.token();
      await f.request('tools/list', {}, token);
      const requests = auditEvents.filter(
        (event) => event.operation === 'request',
      );
      assert.ok(requests.length > 1);
      assert.equal(
        new Set(requests.map((event) => event.requestId)).size,
        requests.length,
      );
      assert.ok(
        auditEvents.some(
          (event) =>
            /update/i.test(event.operation) &&
            event.target === 'collection:bulletins' &&
            event.outcome === 'success',
        ),
      );
      assert.ok(
        requests.every(
          (event) =>
            event.issuer === f.options.issuer &&
            event.clientId === 'mcp-client' &&
            event.subject,
        ),
      );
      assert.ok(!JSON.stringify(auditEvents).includes(token));
      assert.ok(!JSON.stringify(auditEvents).includes('PRIVATE-NEVER-RETURN'));
    },
  );
  await t.test(
    'resolver outage remains a server failure, never an identity refusal',
    async () => {
      f.unavailable();
      await assert.rejects(
        f.request('tools/list', {}, await f.token()),
        /database lookup unavailable/,
      );
    },
  );
});

test('unsafe or ambiguous MCP policies are rejected at configuration', async () => {
  const options = {
    issuer: 'https://issuer.example',
    jwksUri: 'https://issuer.example/jwks',
    resource: 'https://cms.example/api/mcp',
    admissionScopes: ['cms:access'],
    userCollection: 'users',
    resolveUser: async () => ({ status: 'denied', reason: 'unbound' }),
    mcp: {
      enabled: true,
      collections: { bulletins: { find: { scopes: ['cms:read'] } } },
    },
  };
  for (const collections of [
    { bulletins: { update: { scopes: ['cms:write'] } } },
    { bulletins: { find: { scopes: [] } } },
    {
      'foo-bar': { find: { scopes: ['read'] } },
      foo_bar: { find: { scopes: ['read'] } },
    },
    { user: { find: { scopes: ['read'] } } },
  ])
    assert.throws(() =>
      createXignetPayload({ ...options, mcp: { enabled: true, collections } }),
    );
  const disabled = createXignetPayload({
    ...options,
    mcp: { ...options.mcp, enabled: false },
  });
  assert.equal(disabled.metadata().status, 404);
  const disabledRoutes = createXignetRouteHandlers(disabled, {
    getPayload: async () => {
      throw new Error('disabled route must not initialize a database');
    },
  });
  assert.equal(
    (
      await disabledRoutes.callback(
        new Request('https://cms.example/auth/xignet/callback'),
      )
    ).status,
    404,
  );
  const integration = createXignetPayload(options);
  const config = {
    secret: 'fixture-only',
    serverURL: 'https://cms.example',
    collections: [
      { slug: 'users', auth: true, fields: [] },
      { slug: 'bulletins', fields: [] },
    ],
  };
  await assert.rejects(
    integration.plugin()({ ...config, serverURL: 'https://wrong.example' }),
    /origin/,
  );
  await assert.rejects(
    integration.plugin()({
      ...config,
      endpoints: [
        { path: '/mcp', method: 'post', handler: () => new Response() },
      ],
    }),
    /already exists/,
  );
});
