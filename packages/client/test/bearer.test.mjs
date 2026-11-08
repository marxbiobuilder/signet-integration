import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { test } from 'node:test';

import {
  SignetClient,
  SignetOAuthError,
  SignetRequestError,
  executeWithBearer,
  createFetchOperation,
} from '../dist/index.cjs';

const secret = 'SENSITIVE_CLIENT_SECRET';
const accessToken = 'SENSITIVE_ACCESS_TOKEN';
const sensitiveError = (code = 'PRIVATE_CODE', status) =>
  Object.assign(
    new Error(`${secret} ${accessToken}`, {
      cause: { Authorization: `Bearer ${accessToken}` },
    }),
    {
      code,
      status,
      config: { headers: { Authorization: `Bearer ${accessToken}` } },
      response: { status, data: { error_description: secret } },
    },
  );
const assertSafe = (error) => {
  assert.ok(error instanceof SignetRequestError);
  assert.equal(error.cause, undefined);
  assert.equal(error.config, undefined);
  assert.equal(error.response, undefined);
  const output =
    inspect(error, { depth: Infinity, showHidden: true }) +
    JSON.stringify(error);
  for (const value of [
    secret,
    accessToken,
    'Authorization',
    'error_description',
    'PRIVATE_CODE',
  ])
    assert.ok(!output.includes(value), output);
};
const provider = (tokens = ['old-token', 'new-token']) => {
  let calls = 0;
  const invalidated = [];
  return {
    client: {
      getAccessToken: async () => {
        const next = tokens[calls++];
        if (next instanceof Error) throw next;
        return next;
      },
      invalidateToken: (token) => invalidated.push(token),
    },
    invalidated,
    calls: () => calls,
  };
};
const deferred = () => {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
};
const realClient = () => {
  let exchanges = 0;
  return {
    client: new SignetClient({
      clientId: 'service:test:consumer',
      clientSecret: secret,
      audience: 'https://resource.example/api',
      scope: 'test:access',
      fetch: async () =>
        new Response(
          JSON.stringify({
            access_token: ++exchanges === 1 ? 'old-token' : 'new-token',
            token_type: 'Bearer',
            expires_in: 1800,
          }),
          { headers: { 'content-type': 'application/json' } },
        ),
    }),
    exchanges: () => exchanges,
  };
};

test('returns a successful operation result once without disposal or invalidation', async () => {
  const p = provider();
  let calls = 0;
  const value = { ok: true };
  assert.equal(
    await executeWithBearer(p.client, async ({ token, attempt }) => {
      calls++;
      assert.equal(token, 'old-token');
      assert.equal(attempt, 1);
      return {
        status: 200,
        value,
        dispose: () => assert.fail('Successful response is consumer-owned'),
      };
    }),
    value,
  );
  assert.equal(calls, 1);
  assert.equal(p.calls(), 1);
  assert.deepEqual(p.invalidated, []);
});

for (const retryOnUnauthorized of [undefined, false]) {
  test(`invalidates and disposes 401 but does not replay by default (${retryOnUnauthorized})`, async () => {
    const p = provider();
    let sends = 0;
    let disposed = 0;
    const error = await executeWithBearer(
      p.client,
      async () => {
        sends++;
        return {
          status: 401,
          value: sensitiveError(),
          dispose: () => {
            disposed++;
          },
        };
      },
      { retryOnUnauthorized },
    ).catch((e) => e);
    assertSafe(error);
    assert.equal(error.phase, 'resource');
    assert.equal(error.status, 401);
    assert.equal(error.retryExhausted, false);
    assert.equal(error.attempt, 1);
    assert.equal(sends, 1);
    assert.equal(p.calls(), 1);
    assert.equal(disposed, 1);
    assert.deepEqual(p.invalidated, ['old-token']);
  });
}

test('cleans up 401 before notification and refresh, then replays once', async () => {
  const events = [];
  let n = 0;
  const client = {
    getAccessToken: async () => {
      events.push('token');
      return ++n === 1 ? 'old-token' : 'new-token';
    },
    invalidateToken: (token) => events.push(`invalidate:${token}`),
  };
  const result = await executeWithBearer(
    client,
    async ({ token, attempt }) => {
      events.push(`send:${token}`);
      return {
        status: attempt === 1 ? 401 : 200,
        value: 'ok',
        dispose: async () => {
          await Promise.resolve();
          events.push('dispose');
        },
      };
    },
    {
      retryOnUnauthorized: true,
      onRetry: () => {
        events.push('notify');
      },
    },
  );
  assert.equal(result, 'ok');
  assert.deepEqual(events, [
    'token',
    'send:old-token',
    'invalidate:old-token',
    'dispose',
    'notify',
    'token',
    'send:new-token',
  ]);
});

test('second resource 401 invalidates both tokens, disposes both and stops', async () => {
  const p = provider();
  let sends = 0;
  let disposed = 0;
  let notified = 0;
  const error = await executeWithBearer(
    p.client,
    async () => {
      sends++;
      return {
        status: 401,
        value: secret,
        dispose: () => {
          disposed++;
        },
      };
    },
    {
      retryOnUnauthorized: true,
      onRetry: () => {
        notified++;
      },
    },
  ).catch((e) => e);
  assertSafe(error);
  assert.equal(error.code, 'RESOURCE_HTTP_ERROR');
  assert.equal(error.status, 401);
  assert.equal(error.retryExhausted, true);
  assert.equal(error.afterUnauthorized, true);
  assert.equal(error.attempt, 2);
  assert.equal(p.calls(), 2);
  assert.equal(sends, 2);
  assert.equal(disposed, 2);
  assert.equal(notified, 1);
  assert.deepEqual(p.invalidated, ['old-token', 'new-token']);
});

for (const status of [302, 400, 403, 429, 500, 503]) {
  test(`resource HTTP ${status} is classified, disposed and never retried`, async () => {
    const p = provider();
    let sends = 0;
    let disposed = 0;
    const error = await executeWithBearer(
      p.client,
      async () => {
        sends++;
        return {
          status,
          value: { body: secret },
          dispose: () => {
            disposed++;
          },
        };
      },
      { retryOnUnauthorized: true },
    ).catch((e) => e);
    assertSafe(error);
    assert.equal(error.phase, 'resource');
    assert.equal(error.code, 'RESOURCE_HTTP_ERROR');
    assert.equal(error.status, status);
    assert.equal(sends, 1);
    assert.equal(disposed, 1);
    assert.equal(p.calls(), 1);
    assert.deepEqual(p.invalidated, []);
  });
}

for (const code of [
  'ECONNABORTED',
  'ETIMEDOUT',
  'ENOTFOUND',
  'ERR_NETWORK',
  'PRIVATE_CODE',
]) {
  test(`thrown resource failure ${code} never retries or retains sensitive data`, async () => {
    const p = provider();
    let sends = 0;
    const error = await executeWithBearer(
      p.client,
      async () => {
        sends++;
        throw sensitiveError(code, 401);
      },
      { retryOnUnauthorized: true },
    ).catch((e) => e);
    assertSafe(error);
    assert.equal(error.status, undefined);
    assert.equal(
      error.code,
      code === 'PRIVATE_CODE'
        ? 'RESOURCE_REQUEST_FAILED'
        : 'RESOURCE_NETWORK_ERROR',
    );
    assert.equal(
      error.transportCode,
      code === 'PRIVATE_CODE' ? undefined : code,
    );
    assert.equal(sends, 1);
    assert.equal(p.calls(), 1);
    assert.deepEqual(p.invalidated, []);
  });
}

for (const status of [401, 403, 500, undefined]) {
  for (const afterUnauthorized of [false, true]) {
    test(`token failure HTTP ${status} afterUnauthorized=${afterUnauthorized} never enters resource retry`, async () => {
      const failure = Object.assign(
        new SignetOAuthError('TOKEN_REQUEST_FAILED', status),
        { cause: sensitiveError(), message: secret },
      );
      const p = provider(
        afterUnauthorized ? ['old-token', failure] : [failure],
      );
      let sends = 0;
      const error = await executeWithBearer(
        p.client,
        async () => {
          sends++;
          return { status: 401, value: secret };
        },
        { retryOnUnauthorized: true },
      ).catch((e) => e);
      assertSafe(error);
      assert.equal(error.phase, 'token');
      assert.equal(error.code, 'TOKEN_REQUEST_FAILED');
      assert.equal(error.status, status);
      assert.equal(error.afterUnauthorized, afterUnauthorized);
      assert.equal(error.retryExhausted, false);
      assert.equal(sends, afterUnauthorized ? 1 : 0);
      assert.equal(p.calls(), afterUnauthorized ? 2 : 1);
      assert.deepEqual(p.invalidated, afterUnauthorized ? ['old-token'] : []);
    });
  }
}

test('unknown token error codes and status values are discarded', async () => {
  const p = provider([sensitiveError('PRIVATE_CODE', secret)]);
  const error = await executeWithBearer(p.client, async () =>
    assert.fail(),
  ).catch((e) => e);
  assertSafe(error);
  assert.equal(error.phase, 'token');
  assert.equal(error.code, 'TOKEN_REQUEST_FAILED');
  assert.equal(error.status, undefined);
});

for (const token of [
  '',
  undefined,
  null,
  123,
  'has whitespace',
  '\u0000secret',
]) {
  test(`invalid token (${JSON.stringify(token)}) never reaches the operation`, async () => {
    const p = provider([token]);
    const error = await executeWithBearer(p.client, async () =>
      assert.fail(),
    ).catch((e) => e);
    assertSafe(error);
    assert.equal(error.code, 'INVALID_TOKEN_RESPONSE');
    assert.equal(error.phase, 'token');
  });
}

for (const stage of ['dispose', 'notify', 'invalidate']) {
  test(`failure in ${stage} is sanitized and cannot expand the retry budget`, async () => {
    const p = provider();
    let sends = 0;
    let disposed = 0;
    if (stage === 'invalidate')
      p.client.invalidateToken = () => {
        throw sensitiveError();
      };
    const error = await executeWithBearer(
      p.client,
      async () => {
        sends++;
        return {
          status: 401,
          value: secret,
          dispose: () => {
            disposed++;
            if (stage === 'dispose') throw sensitiveError();
          },
        };
      },
      {
        retryOnUnauthorized: true,
        onRetry: () => {
          if (stage === 'notify') throw sensitiveError();
        },
      },
    ).catch((e) => e);
    assertSafe(error);
    assert.equal(
      error.code,
      {
        dispose: 'RESOURCE_DISPOSAL_FAILED',
        notify: 'RETRY_CALLBACK_FAILED',
        invalidate: 'INVALID_CONFIGURATION',
      }[stage],
    );
    assert.equal(p.calls(), 1);
    assert.equal(sends, 1);
    assert.equal(disposed, 1);
  });
}

for (const status of [undefined, 0, 600, 200.5, secret]) {
  test(`malformed resource status ${status} has a safe classification`, async () => {
    const p = provider();
    const error = await executeWithBearer(
      p.client,
      async () => ({ status, value: secret }),
      { retryOnUnauthorized: true },
    ).catch((e) => e);
    assertSafe(error);
    assert.equal(error.code, 'INVALID_RESOURCE_RESPONSE');
    assert.equal(error.status, undefined);
    assert.equal(p.calls(), 1);
  });
}

for (const options of [
  null,
  1,
  [],
  { retryOnUnauthorized: 'yes' },
  { onRetry: secret },
]) {
  test(`invalid replay options ${JSON.stringify(options)} fail before token acquisition`, async () => {
    const p = provider();
    const error = await executeWithBearer(
      p.client,
      async () => assert.fail(),
      options,
    ).catch((e) => e);
    assertSafe(error);
    assert.equal(error.phase, 'configuration');
    assert.equal(p.calls(), 0);
  });
}

test('awaits asynchronous invalidation and sanitizes its rejection', async () => {
  const p = provider();
  let disposed = false;
  p.client.invalidateToken = async () => {
    throw sensitiveError();
  };
  const error = await executeWithBearer(
    p.client,
    async () => ({
      status: 401,
      value: null,
      dispose: () => {
        disposed = true;
      },
    }),
    { retryOnUnauthorized: true },
  ).catch((e) => e);
  assertSafe(error);
  assert.equal(error.phase, 'configuration');
  assert.equal(disposed, true);
  assert.equal(p.calls(), 1);
});

test('malformed response getters cannot leak errors and unused responses are disposed', async () => {
  const p = provider();
  let disposed = false;
  const error = await executeWithBearer(p.client, async () => ({
    status: 200,
    get value() {
      throw sensitiveError();
    },
    dispose() {
      this.released = true;
      disposed = this.released;
    },
  })).catch((e) => e);
  assertSafe(error);
  assert.equal(error.code, 'INVALID_RESOURCE_RESPONSE');
  assert.equal(disposed, true);
});

test('asynchronous response-value rejection is sanitized and disposed', async () => {
  const p = provider();
  let disposed = false;
  const error = await executeWithBearer(p.client, async () => ({
    status: 200,
    value: Promise.reject(sensitiveError()),
    dispose: () => {
      disposed = true;
    },
  })).catch((e) => e);
  assertSafe(error);
  assert.equal(error.code, 'INVALID_RESOURCE_RESPONSE');
  assert.equal(error.status, 200);
  assert.equal(disposed, true);
  assert.equal(p.calls(), 1);
});

test('public safe error constructor never interpolates untrusted runtime values', () => {
  const error = new SignetRequestError(
    secret,
    accessToken,
    secret,
    secret,
    accessToken,
  );
  assertSafe(error);
  assert.equal(error.phase, 'configuration');
  assert.equal(error.code, 'INVALID_CONFIGURATION');
  assert.equal(error.attempt, 1);
});

test('concurrent resource 401s reuse the original SignetClient single-flight', async () => {
  const r = realClient();
  await r.client.getAccessToken();
  const barrier = deferred();
  const ready = deferred();
  let initial = 0;
  let sends = 0;
  const promises = Array.from({ length: 10 }, () =>
    executeWithBearer(
      r.client,
      async ({ token }) => {
        sends++;
        if (token === 'old-token') {
          if (++initial === 10) ready.resolve();
          await barrier.promise;
          return { status: 401, value: null };
        }
        return { status: 200, value: token };
      },
      { retryOnUnauthorized: true },
    ),
  );
  await ready.promise;
  barrier.resolve();
  assert.deepEqual(await Promise.all(promises), Array(10).fill('new-token'));
  assert.equal(sends, 20);
  assert.equal(r.exchanges(), 2);
});

test('late old-token 401 cannot invalidate the refreshed token', async () => {
  const r = realClient();
  await r.client.getAccessToken();
  const late = deferred();
  const started = deferred();
  const slow = executeWithBearer(
    r.client,
    async ({ token }) => {
      if (token === 'old-token') {
        started.resolve();
        await late.promise;
        return { status: 401, value: null };
      }
      return { status: 200, value: token };
    },
    { retryOnUnauthorized: true },
  );
  await started.promise;
  assert.equal(
    await executeWithBearer(
      r.client,
      async ({ token }) => ({
        status: token === 'old-token' ? 401 : 200,
        value: token,
      }),
      { retryOnUnauthorized: true },
    ),
    'new-token',
  );
  late.resolve();
  assert.equal(await slow, 'new-token');
  assert.equal(await r.client.getAccessToken(), 'new-token');
  assert.equal(r.exchanges(), 2);
});

test('fetch adapter rebuilds a readonly POST body, preserves semantics and disposes only failed responses', async () => {
  const p = provider();
  const requests = [];
  let canceled = 0;
  const operation = createFetchOperation(
    () =>
      new Request('https://resource.example/batch-eligibility?q=one&q=two', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-stable': 'same' },
        body: JSON.stringify({ ids: [1, 2] }),
      }),
    async (request) => {
      requests.push({
        method: request.method,
        url: request.url,
        headers: Object.fromEntries(request.headers),
        body: await request.text(),
        redirect: request.redirect,
      });
      return requests.length === 1
        ? new Response(
            new ReadableStream({
              cancel: () => {
                canceled++;
              },
            }),
            { status: 401 },
          )
        : new Response('{"ok":true}', {
            headers: { 'content-type': 'application/json' },
          });
    },
  );
  const response = await executeWithBearer(p.client, operation, {
    retryOnUnauthorized: true,
  });
  assert.equal(canceled, 1);
  assert.equal(response.bodyUsed, false);
  assert.deepEqual(await response.json(), { ok: true });
  assert.equal(requests.length, 2);
  assert.equal(requests[0].headers.authorization, 'Bearer old-token');
  assert.equal(requests[1].headers.authorization, 'Bearer new-token');
  requests.forEach((r) => {
    delete r.headers.authorization;
  });
  assert.deepEqual(requests[0], requests[1]);
  assert.equal(requests[0].redirect, 'error');
});

test('fetch adapter rebuilds consumed streams on each attempt', async () => {
  const p = provider();
  const bodies = [];
  const operation = createFetchOperation(
    () =>
      new Request('https://resource.example/read-only-post', {
        method: 'POST',
        duplex: 'half',
        body: new ReadableStream({
          start(c) {
            c.enqueue(new TextEncoder().encode('same body'));
            c.close();
          },
        }),
      }),
    async (r) => {
      bodies.push(await r.text());
      return new Response(null, { status: bodies.length === 1 ? 401 : 204 });
    },
  );
  await executeWithBearer(p.client, operation, { retryOnUnauthorized: true });
  assert.deepEqual(bodies, ['same body', 'same body']);
});

test('fetch adapter refuses a reused one-shot body before sending it again', async () => {
  const p = provider();
  let sends = 0;
  const request = new Request('https://resource.example/read-only-post', {
    method: 'POST',
    body: 'once',
  });
  const error = await executeWithBearer(
    p.client,
    createFetchOperation(
      () => request,
      async (r) => {
        sends++;
        await r.text();
        return new Response(null, { status: 401 });
      },
    ),
    { retryOnUnauthorized: true },
  ).catch((e) => e);
  assertSafe(error);
  assert.equal(error.code, 'RESOURCE_BODY_UNAVAILABLE');
  assert.equal(error.attempt, 2);
  assert.equal(sends, 1);
  assert.deepEqual(p.invalidated, ['old-token']);
});

test('fetch adapter maps transport rejection to a safe network failure', async () => {
  const p = provider();
  let sends = 0;
  const error = await executeWithBearer(
    p.client,
    createFetchOperation(
      () => new Request('https://resource.example'),
      async () => {
        sends++;
        throw new TypeError(secret, { cause: sensitiveError('ENOTFOUND') });
      },
    ),
    { retryOnUnauthorized: true },
  ).catch((e) => e);
  assertSafe(error);
  assert.equal(error.code, 'RESOURCE_NETWORK_ERROR');
  assert.equal(error.transportCode, 'ENOTFOUND');
  assert.equal(sends, 1);
  assert.deepEqual(p.invalidated, []);
});

test('fetch adapter rejects HTTP endpoints before exposing Bearer credentials', async () => {
  const p = provider();
  const error = await executeWithBearer(
    p.client,
    createFetchOperation(
      () => new Request('http://resource.example'),
      async () => assert.fail(),
    ),
  ).catch((e) => e);
  assertSafe(error);
  assert.equal(error.phase, 'configuration');
});
