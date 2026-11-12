import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { createDirectoryClient, canonicalEmail } from '../dist/directory.cjs';

async function fixture(t, timeoutMs = 500) {
  const state = {
    tokens: 0,
    calls: 0,
    status: 200,
    tokenStatus: 200,
    response: null,
    stall: false,
  };
  let origin;
  const server = createServer(async (req, res) => {
    res.setHeader('content-type', 'application/json');
    let text = '';
    for await (const chunk of req) text += chunk;
    if (req.url === '/token') {
      state.tokens++;
      assert.deepEqual(
        Buffer.from(req.headers.authorization.slice(6), 'base64')
          .toString()
          .split(':')
          .map(decodeURIComponent),
        ['service:cms', 'fixture-secret'],
      );
      const body = new URLSearchParams(text);
      assert.equal(body.get('grant_type'), 'client_credentials');
      assert.equal(body.get('audience'), `${origin}/directory`);
      assert.equal(body.get('scope'), 'directory:access directory:read');
      res.statusCode = state.tokenStatus;
      return res.end(
        JSON.stringify({
          access_token: `fixture-token-${state.tokens}`,
          token_type: 'Bearer',
          expires_in: 120,
        }),
      );
    }
    state.calls++;
    assert.match(req.headers['x-request-id'], /^[A-Za-z0-9_-]{1,64}$/);
    assert.match(req.headers.authorization, /^Bearer fixture-token-/);
    assert.equal(req.url, '/directory/users/resolve');
    assert.deepEqual(JSON.parse(text), { email: 'alice@example.test' });
    if (state.stall) {
      res.write('{');
      return;
    }
    res.statusCode = state.status;
    res.end(
      JSON.stringify(
        state.response ?? {
          issuer: origin,
          sub: 'alice-sub',
          email: 'alice@example.test',
        },
      ),
    );
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  origin = `http://127.0.0.1:${server.address().port}`;
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
  return {
    state,
    origin,
    client: createDirectoryClient({
      clientId: 'service:cms',
      clientSecret: 'fixture-secret',
      issuer: origin,
      resource: `${origin}/directory`,
      tokenEndpoint: `${origin}/token`,
      resolveEndpoint: `${origin}/directory/users/resolve`,
      allowInsecureLoopback: true,
      timeoutMs,
    }),
  };
}

test('Directory reuses machine token caching and sends exact email queries without aliases', async (t) => {
  const f = await fixture(t);
  const rows = await Promise.all(
    Array.from({ length: 4 }, () => f.client.resolve(' Alice@Example.Test ')),
  );
  assert.equal(f.state.tokens, 1);
  assert.equal(f.state.calls, 4);
  assert.deepEqual(rows[0], {
    issuer: f.origin,
    sub: 'alice-sub',
    email: 'alice@example.test',
  });
  assert.equal(
    canonicalEmail('Alice+team@example.test'),
    'alice+team@example.test',
  );
  assert.equal(canonicalEmail('a.lice@example.test'), 'a.lice@example.test');
  await assert.rejects(f.client.resolve('alice'), { code: 'invalid_email' });
});

test('Directory only retries a resource 401 once and exposes safe error codes', async (t) => {
  const f = await fixture(t);
  f.state.status = 401;
  await assert.rejects(f.client.resolve('alice@example.test'), {
    code: 'unauthorized',
  });
  assert.equal(f.state.tokens, 2);
  assert.equal(f.state.calls, 2);
  for (const [status, code] of [
    [403, 'forbidden'],
    [404, 'not_found'],
    [429, 'rate_limited'],
    [503, 'unavailable'],
  ]) {
    f.state.status = status;
    const before = f.state.calls;
    await assert.rejects(f.client.resolve('alice@example.test'), (error) => {
      assert.equal(error.code, code);
      assert.ok(!JSON.stringify(error).includes('fixture-secret'));
      assert.ok(!error.message.includes('alice'));
      return true;
    });
    assert.equal(f.state.calls, before + 1);
  }
});

test('Directory refuses mismatched identity, malformed, and oversized responses', async (t) => {
  const f = await fixture(t);
  for (const response of [
    null,
    {},
    { issuer: 'https://wrong.test', sub: 'one', email: 'alice@example.test' },
    { issuer: f.origin, sub: 'service:machine', email: 'alice@example.test' },
    { issuer: f.origin, sub: 'one', email: 'bob@example.test' },
    { padding: 'x'.repeat(17000) },
  ]) {
    // null would select the valid default in this fixture.
    f.state.response = response ?? [];
    await assert.rejects(f.client.resolve('alice@example.test'), {
      code: 'invalid_response',
    });
  }
});

test('Directory timeout covers the response body', async (t) => {
  const f = await fixture(t, 250);
  await f.client.resolve('alice@example.test');
  f.state.stall = true;
  await assert.rejects(f.client.resolve('alice@example.test'), {
    code: 'unavailable',
  });
  assert.equal(f.state.calls, 2);
});

test('Directory validates trusted endpoints before sending credentials', () => {
  const base = { clientId: 'service:cms', clientSecret: 'secret' };
  for (const change of [
    { tokenEndpoint: 'https://evil.example/token' },
    { resolveEndpoint: 'https://evil.example/lookup' },
    { issuer: 'http://remote.test', allowInsecureLoopback: true },
    { clientId: 'human' },
    { timeoutMs: 0 },
    { resolveEndpoint: 'https://signet.marxbio.tech/lookup?q=secret' },
  ])
    assert.throws(() => createDirectoryClient({ ...base, ...change }));
});
