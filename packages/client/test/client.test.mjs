import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { inspect } from 'node:util';
import { afterEach, mock, test } from 'node:test';

import { SignetClient, SignetOAuthError } from '../dist/index.cjs';

const settings = {
  tokenUrl: 'https://issuer.example/oauth2/token',
  clientId: 'service:stocksync:production:medusajs-core',
  clientSecret: 'secret: &+=/sensitive',
  audience: 'https://stocksync.example/api/mcp',
  scope: 'stocksync:access',
};
const token = (value = 'sensitive-token', expires = 1800) => ({
  access_token: value,
  token_type: 'Bearer',
  expires_in: expires,
});
const response = (data = token(), status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json' },
  });
const harness = (responses = [response()], options = {}) => {
  const requests = [];
  const fetch = async (url, init) => {
    requests.push({ url, ...init });
    const next = responses.shift();
    if (next instanceof Error) throw next;
    if (typeof next === 'function') return next();
    assert.ok(next, 'Unexpected token exchange');
    return next;
  };
  return {
    requests,
    client: new SignetClient({ ...settings, fetch, ...options }),
  };
};
afterEach(() => mock.restoreAll());

test('supports CommonJS require and ESM named imports', () => {
  const require = createRequire(import.meta.url);
  assert.equal(require('../dist/index.cjs').SignetClient, SignetClient);
});

test('uses the real OAuth library with encoded Basic credentials and body audience/scope', async () => {
  const { client, requests } = harness();
  assert.equal(await client.getAccessToken(), 'sensitive-token');
  assert.equal(requests.length, 1);
  const request = requests[0];
  assert.equal(String(request.url), settings.tokenUrl);
  assert.equal(request.method, 'POST');
  assert.equal(request.redirect, 'error');
  assert.ok(request.signal instanceof AbortSignal);
  const headers = new Headers(request.headers);
  assert.match(
    headers.get('content-type'),
    /application\/x-www-form-urlencoded/,
  );
  assert.equal(headers.get('x-api-key'), null);
  const authorization = headers.get('authorization');
  assert.ok(authorization.startsWith('Basic '));
  const credentials = Buffer.from(authorization.slice(6), 'base64').toString();
  const parts = credentials.split(':');
  assert.equal(parts.length, 2, 'Colons in the ID and secret must be encoded');
  const decoded = parts.map((value) =>
    new URLSearchParams(`v=${value}`).get('v'),
  );
  assert.deepEqual(decoded, [settings.clientId, settings.clientSecret]);
  const body = new URLSearchParams(request.body);
  assert.equal(body.get('grant_type'), 'client_credentials');
  assert.equal(body.get('audience'), settings.audience);
  assert.equal(body.get('scope'), settings.scope);
  assert.equal(body.get('client_secret'), null);
});

test('caches until the expiry safety margin and shares parallel exchanges', async () => {
  let now = 1_000_000;
  mock.method(Date, 'now', () => now);
  const { client, requests } = harness([
    response(),
    response(token('replacement')),
  ]);
  assert.deepEqual(
    await Promise.all(
      Array.from({ length: 10 }, () => client.getAccessToken()),
    ),
    Array(10).fill('sensitive-token'),
  );
  assert.equal(requests.length, 1);
  now += 1_739_999;
  assert.equal(await client.getAccessToken(), 'sensitive-token');
  now++;
  assert.equal(await client.getAccessToken(), 'replacement');
  assert.equal(requests.length, 2);
});

test('caps the margin to half the lifetime for short-lived tokens', async () => {
  let now = 1_000_000;
  mock.method(Date, 'now', () => now);
  const { client, requests } = harness([
    response(token('short', 30)),
    response(token('new')),
  ]);
  assert.equal(await client.getAccessToken(), 'short');
  now += 14_999;
  assert.equal(await client.getAccessToken(), 'short');
  now++;
  assert.equal(await client.getAccessToken(), 'new');
  assert.equal(requests.length, 2);
});

test('uses the configured margin and accounts for time spent waiting on the token endpoint', async () => {
  let now = 1_000_000;
  mock.method(Date, 'now', () => now);
  const { client } = harness(
    [
      () => {
        now += 5000;
        return response(token('first', 30));
      },
      response(token('next')),
    ],
    { refreshMarginSeconds: 10 },
  );
  assert.equal(await client.getAccessToken(), 'first');
  now += 15_000;
  assert.equal(await client.getAccessToken(), 'next');
});

test('invalidates only the rejected token, preserving a replacement after late 401s', async () => {
  const { client, requests } = harness([
    response(),
    response(token('replacement')),
  ]);
  await client.getAccessToken();
  client.invalidateToken('unrelated-token');
  assert.equal(await client.getAccessToken(), 'sensitive-token');
  client.invalidateToken('sensitive-token');
  assert.equal(await client.getAccessToken(), 'replacement');
  client.invalidateToken('sensitive-token');
  assert.equal(await client.getAccessToken(), 'replacement');
  assert.equal(requests.length, 2);
});

test('does not evict a refresh already in flight after a concurrent late 401', async () => {
  let resolve;
  const waiting = new Promise((r) => {
    resolve = r;
  });
  const { client, requests } = harness([response(), () => waiting]);
  await client.getAccessToken();
  client.invalidateToken('sensitive-token');
  const first = client.getAccessToken();
  client.invalidateToken('sensitive-token');
  const second = client.getAccessToken();
  resolve(response(token('replacement')));
  assert.deepEqual(await Promise.all([first, second]), [
    'replacement',
    'replacement',
  ]);
  assert.equal(requests.length, 2);
});

for (const status of [302, 400, 401, 403, 429, 500]) {
  test(`does not retry token HTTP ${status}, drops sensitive upstream content and permits recovery`, async () => {
    const { client, requests } = harness([
      response(
        {
          error: 'invalid_client',
          error_description: `${settings.clientSecret} sensitive-token`,
        },
        status,
      ),
      response(),
    ]);
    const error = await client.getAccessToken().catch((e) => e);
    assert.ok(error instanceof SignetOAuthError);
    assert.equal(error.code, 'TOKEN_REQUEST_FAILED');
    assert.equal(error.status, status);
    assert.equal(error.cause, undefined);
    assert.doesNotMatch(
      inspect(error, { depth: 10 }),
      /sensitive-token|secret:/,
    );
    assert.doesNotMatch(JSON.stringify(error), /sensitive-token|secret:/);
    assert.equal(requests.length, 1);
    await client.getAccessToken();
    assert.equal(requests.length, 2);
  });
}

test('network errors and their causes never escape; failed exchanges are shared and then discarded', async () => {
  const raw = new Error(`upstream ${settings.clientSecret} sensitive-token`, {
    cause: settings,
  });
  const { client, requests } = harness([raw, response()]);
  const errors = await Promise.allSettled([
    client.getAccessToken(),
    client.getAccessToken(),
  ]);
  for (const result of errors) {
    assert.equal(result.status, 'rejected');
    assert.equal(result.reason.code, 'TOKEN_REQUEST_FAILED');
    assert.equal(result.reason.cause, undefined);
    assert.doesNotMatch(inspect(result.reason), /sensitive-token|secret:/);
  }
  assert.equal(requests.length, 1);
  await client.getAccessToken();
  assert.equal(requests.length, 2);
});

for (const data of [
  null,
  {},
  token('', 1800),
  token('has spaces'),
  { ...token(), token_type: 'Basic' },
  token('sensitive-token', 0),
  token('sensitive-token', -1),
  { ...token(), expires_in: undefined },
]) {
  test(`rejects malformed response ${JSON.stringify(data)} without caching`, async () => {
    const { client, requests } = harness([response(data), response()]);
    await assert.rejects(client.getAccessToken(), {
      code: 'INVALID_TOKEN_RESPONSE',
    });
    await client.getAccessToken();
    assert.equal(requests.length, 2);
  });
}

test('rejects a token whose useful lifetime elapsed during the exchange', async () => {
  let now = 1_000_000;
  mock.method(Date, 'now', () => now);
  const { client } = harness([
    () => {
      now += 30_000;
      return response(token('sensitive-token', 30));
    },
  ]);
  await assert.rejects(client.getAccessToken(), {
    code: 'INVALID_TOKEN_RESPONSE',
  });
});

test('keeps credentials and cached tokens private even when the client is inspected', async () => {
  const { client } = harness();
  await client.getAccessToken();
  assert.equal(JSON.stringify(client), '{}');
  assert.doesNotMatch(
    inspect(client, { showHidden: true, depth: 10 }),
    /sensitive-token|secret:/,
  );
});

test('accepts numeric expires_in normalized by the protocol library', async () => {
  const { client } = harness([response(token('normalized', '1800'))]);
  assert.equal(await client.getAccessToken(), 'normalized');
});

test('uses the native fetch transport when no override is configured', async () => {
  const fetch = mock.method(globalThis, 'fetch', async () => response());
  const client = new SignetClient(settings);
  assert.equal(await client.getAccessToken(), 'sensitive-token');
  assert.equal(fetch.mock.callCount(), 1);
});

test('aborts the token transport at the configured deadline and returns a safe error', async () => {
  let signal;
  const client = new SignetClient({
    ...settings,
    timeoutMs: 10,
    fetch: async (_url, init) =>
      new Promise((_resolve, reject) => {
        signal = init.signal;
        const keepAlive = setTimeout(
          () => reject(new Error('deadline was not enforced')),
          500,
        );
        signal.addEventListener(
          'abort',
          () => {
            clearTimeout(keepAlive);
            reject(signal.reason);
          },
          { once: true },
        );
      }),
  });
  await assert.rejects(client.getAccessToken(), {
    code: 'TOKEN_REQUEST_FAILED',
  });
  assert.equal(signal.aborted, true);
});

for (const overrides of [
  { tokenUrl: 'http://issuer.example/token' },
  { tokenUrl: 'not a URL' },
  { tokenUrl: 'https://user:password@issuer.example/token' },
  { tokenUrl: 'https://issuer.example/token?audience=wrong' },
  { tokenUrl: 'https://issuer.example/token#fragment' },
  { clientId: '' },
  { clientSecret: '  ' },
  { audience: '' },
  { scope: '' },
  { timeoutMs: 0 },
  { timeoutMs: Infinity },
  { timeoutMs: 0.5 },
  { refreshMarginSeconds: -1 },
  { refreshMarginSeconds: NaN },
  { fetch: 'invalid' },
]) {
  test(`rejects invalid configuration ${JSON.stringify(overrides)}`, () => {
    assert.throws(() => new SignetClient({ ...settings, ...overrides }), {
      code: 'INVALID_CONFIGURATION',
    });
  });
}
