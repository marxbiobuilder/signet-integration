# @xignet/client

Signet OAuth **machine client** for Node.js. Uses `openid-client` for the
`client_credentials` protocol and RFC 6749 `client_secret_basic` encoding,
including client IDs containing colons. Independent of NestJS, Passport, Medusa
and the [`@xignet/nest`](../nest/README.md) resource-server package
(formerly `@marxbiotech/signet-integration`).

Requires Node.js **22.22.0 or newer**. Supports CommonJS `require()` and ESM
named imports. The CommonJS entry loads the ESM protocol library with native
dynamic `import()`.

```sh
npm install @xignet/client
```

```ts
import { SignetClient, SignetOAuthError } from '@xignet/client';

const auth = new SignetClient({
  clientId: process.env.SIGNET_CLIENT_ID!, // original ID, NOT pre-encoded
  clientSecret: process.env.SIGNET_CLIENT_SECRET!,
  audience: 'https://stocksync.marxbiotech.com/api/mcp',
  scope: 'stocksync:access',
  timeoutMs: 30_000, // optional
});

const token = await auth.getAccessToken();
// Use Authorization: Bearer <token> with your API client; never add X-API-Key.
// On API 401, invalidate only the rejected token, then retry at most once:
auth.invalidateToken(token);
const replacement = await auth.getAccessToken();
```

Create one client per credentials/audience/scope configuration and reuse it.
The cache is process-local; it is not persisted. A request reuses the cached
token until `expires_in` minus a 60-second margin, capped at half the lifetime
for short-lived tokens. `refreshMarginSeconds` overrides the margin. Time spent
obtaining the token counts towards its lifetime. Concurrent exchanges share a
single promise. Failures clear that promise so a later call can recover.

`audience` and `scope` are sent in the form body. Credentials use Basic auth;
the caller must pass their original values without pre-encoding them. The token
endpoint defaults to `https://xignet.marxbio.tech/oauth2/token`, as advertised by
Xignet's discovery document. No token URL environment variable is needed.
For another deployment, pass the optional `tokenUrl` from its discovery document;
it must use HTTPS and contain no credentials, query or fragment. Redirects are
rejected. This package does not perform runtime discovery, decode the access
token or manage user sessions. `audience` and `scope` remain required.

The low-level token API makes no resource requests. The optional executor below
can manage the resource-401 flow. `invalidateToken(rejectedToken)` cannot evict
a newer token obtained for another request. There is no refresh token in this flow.

`SignetOAuthError` exposes only `code` and optional HTTP `status`. Codes are
`INVALID_CONFIGURATION`, `TOKEN_REQUEST_FAILED` and `INVALID_TOKEN_RESPONSE`.
Raw upstream errors, response bodies and causes are discarded so they cannot
leak credentials or tokens through application logging. The SDK itself emits no
logs. The optional `fetch` transport override receives credentials; treat it as
trusted code, preserve abort handling and do not log request headers or bodies.

## Optional Bearer request executor

`executeWithBearer(auth, operation, options)` reuses the same `SignetClient`.
It adds no cache or refresh lock. The operation receives `{ token, attempt }`
and returns `{ status, value, dispose? }`. Return non-2xx HTTP responses too;
thrown errors mean request/transport failures, not an HTTP-401 response.
Only 2xx returns `value` to the caller. Promise-valued results are awaited inside
the safety boundary; rejected values are disposed and classified as
`INVALID_RESOURCE_RESPONSE`. Parsing/schema validation performed by the consumer
after this call remains the consumer's responsibility.

```ts
import { executeWithBearer, createFetchOperation } from '@xignet/client';

const response = await executeWithBearer(auth, createFetchOperation(() =>
  new Request('https://resource.example/products?limit=50', {
    method: 'GET', headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(10_000),
  }),
), {
  retryOnUnauthorized: true, // explicit assertion: this operation is safe to replay
  onRetry: () => logger.warn('Resource rejected token; refreshing and retrying'),
});
const data: unknown = await response.json(); // validate against your schema
```

### Replay and cleanup contract

- **Default: no replay**, regardless of HTTP method. Every resource 401 still
  invalidates its rejected token and disposes the unused response.
- `retryOnUnauthorized: true` permits **at most two resource sends**: the initial
  attempt and one authentication replay. A second 401 invalidates that token and
  fails; it never acquires a third token. Token acquisition failures, 403, 429,
  5xx and network errors do not trigger automatic replay or API key fallback.
- Each operation invocation must preserve method, URL/query, necessary headers
  and payload semantics, replacing only Bearer authorization. Rebuild one-shot
  bodies in the factory; do not close over an already consumed stream/Request.
  The fetch adapter rejects used, locked or reused bodies before sending them.
- The fetch adapter permits HTTPS only and forces `redirect: 'error'`. It
  overwrites Authorization through `Headers`, preserving other request settings.
  Non-2xx response bodies are canceled before replay or failure. For other
  transports, supply `dispose` when responses own unused resources; buffered
  Axios responses normally need no disposal. Disposal failure stops the flow
  with a safe error and cannot expand the replay budget.
- `onRetry` runs after cleanup, before acquiring the replacement token. It sees
  no credentials. A thrown/rejected notification fails safely without replay.
  SDK code itself never logs. Consumer logging, deadlines/cancellation, endpoint
  selection, domain diagnostics and external HTTP/Nest/MCP mappings stay local.
- **At most one replay is not exactly-once delivery.** This executor provides
  no business idempotency. A POST such as OrderSync's read-only batch-eligibility
  check may be replayable by its business contract; that does not make arbitrary
  POST requests replayable. Omit the replay option when safe replay is unknown.

For a replayable read-only POST, recreate its body each time:

```ts
const operation = createFetchOperation(() => new Request(
  'https://resource.example/batch-eligibility', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ids: selectedIds }), // rebuild on every invocation
  },
));
const response = await executeWithBearer(auth, operation, { retryOnUnauthorized: true });
```

### Axios adapter example (consumer dependency only)

The core package does not depend on Axios. Normalize its HTTP rejections into
responses; let network/unknown failures throw to the executor. Keep domain code
interpretation in this trusted adapter, accepting only explicit known values.
Do not attach the raw response or upstream diagnostic text to a thrown error.

```ts
import axios, { type AxiosResponse } from 'axios';
import { executeWithBearer } from '@xignet/client';

const response = await executeWithBearer<AxiosResponse<unknown>>(auth, async ({ token }) => {
  try {
    const value = await axios.get('https://resource.example/products', {
      params: { limit: 50 }, maxRedirects: 0,
      headers: { accept: 'application/json', Authorization: `Bearer ${token}` },
    });
    return { status: value.status, value };
  } catch (error) {
    if (axios.isAxiosError(error) && error.response) {
      // Optional: interpret a resource-specific code using a literal allow-list here.
      return { status: error.response.status, value: error.response };
    }
    throw error; // executor discards the raw error, config, body and cause
  }
}, { retryOnUnauthorized: true });
// Validate response.data; translate errors to your application's public contract.
```

Operations, request factories, `fetch` overrides and notification callbacks are
**trusted consumer code**. They receive or use Bearer credentials and must not
log, persist or forward them. The executor bounds its own invocations; it cannot
prevent a callback from sending extra requests or changing business semantics.

### Safe request errors

`SignetRequestError` carries only:

| Field | Meaning |
|---|---|
| `phase` | `configuration`, `token`, or `resource` |
| `code` | Fixed SDK classification; never arbitrary upstream code/message |
| `status` | HTTP status when known (integer 100–599) |
| `attempt` | 1 or 2; token and resource failures identify their attempt |
| `afterUnauthorized` | True for the attempt following a resource 401 |
| `retryExhausted` | True only when the replayed resource request also returned 401 |
| `transportCode` | Optional literal allow-listed transport diagnostic |

Codes: `INVALID_CONFIGURATION`, `TOKEN_REQUEST_FAILED`, `INVALID_TOKEN_RESPONSE`,
`RESOURCE_HTTP_ERROR`, `RESOURCE_NETWORK_ERROR`, `RESOURCE_REQUEST_FAILED`,
`INVALID_RESOURCE_RESPONSE`, `RESOURCE_DISPOSAL_FAILED`,
`RESOURCE_BODY_UNAVAILABLE`, `RETRY_CALLBACK_FAILED`.
Token status 401 remains `phase: 'token'`; it is never mistaken for resource 401.
Unknown resource exceptions use `RESOURCE_REQUEST_FAILED`. The fetch adapter
classifies fetch rejection as a network failure; known transport codes (such as
`ETIMEDOUT`/`ENOTFOUND`) are allow-listed, not trusted via a string regex.
Raw URLs, tokens, headers, Axios configs, response bodies, causes and upstream
`error_description` are excluded from the message, properties and stack. Domain
codes such as StockSync's `SERVICE_ACCOUNT_DISABLED` are not SDK classifications.

## Migrating from @xignet/oauth-client

Replace the package dependency and import source with `@xignet/client`.
`SignetClient`, `SignetOAuthError`, configuration and runtime behavior are
unchanged. The previous package remains installable with a deprecation notice.

## Development and release

From the repository root:

```sh
pnpm install
pnpm --filter @xignet/client test
pnpm --filter @xignet/client typecheck
pnpm --filter @xignet/client build
```

Releases are independent of `@xignet/nest`. Bump this package's
version and changelog, then push a matching `client-vX.Y.Z` tag. The
`client-publish.yml` GitHub Actions workflow validates, builds, checks the
packed artifact and publishes to npm with OIDC. Configure its npm Trusted
Publisher as GitHub owner `marxbiobuilder`, repository `signet-integration`,
workflow `client-publish.yml`. A first package publication/registration
and npm organization permissions must be established before relying on OIDC.
Prereleases are published under their first prerelease identifier, not `latest`.
