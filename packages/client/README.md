# @xignet/client

Signet OAuth **machine client** for Node.js. Uses `openid-client` for the
`client_credentials` protocol and RFC 6749 `client_secret_basic` encoding,
including client IDs containing colons. Independent of NestJS, Passport, Medusa
and the existing `@marxbiotech/signet-integration` resource-server package.

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

The SDK does **not** retry token failures or make business API requests. API
401/403 handling belongs to the consumer: invalidate and retry once for 401;
fail immediately for 403. `invalidateToken(rejectedToken)` cannot evict a newer
token obtained for another request. There is no refresh token in this flow.

`SignetOAuthError` exposes only `code` and optional HTTP `status`. Codes are
`INVALID_CONFIGURATION`, `TOKEN_REQUEST_FAILED` and `INVALID_TOKEN_RESPONSE`.
Raw upstream errors, response bodies and causes are discarded so they cannot
leak credentials or tokens through application logging. The SDK itself emits no
logs. The optional `fetch` transport override receives credentials; treat it as
trusted code, preserve abort handling and do not log request headers or bodies.

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

Releases are independent of the existing root package. Bump this package's
version and changelog, then push a matching `client-vX.Y.Z` tag. The
`client-publish.yml` GitHub Actions workflow validates, builds, checks the
packed artifact and publishes to npm with OIDC. Configure its npm Trusted
Publisher as GitHub owner `marxbiobuilder`, repository `signet-integration`,
workflow `client-publish.yml`. A first package publication/registration
and npm organization permissions must be established before relying on OIDC.
Prereleases are published under their first prerelease identifier, not `latest`.
