# @xignet/payload

Xignet resource authorization for Payload v3. The adapter uses the official MCP plugin and applies token scopes together with existing Payload collection, document and field access. This package is under implementation and has not been published. MCP and native-session OIDC are implemented; website rollout and final delivery review remain in progress under the [implementation plan](../../docs/architecture/core-payload-implementation-plan.md).

The current test baseline is Payload and `@payloadcms/plugin-mcp` **3.93.0**. No broad v3 or v4 compatibility is declared. The upstream plugin currently resolves `mcp-handler` 1.1.0 with SDK 1.30.0 despite that handler declaring SDK 1.26.0 as its exact peer; the workspace explicitly acknowledges this one tested combination using pnpm.peerDependencyRules.allowedVersions. Strict-peer pnpm consumers must apply the same narrow rule. This does not permit any other SDK version. Do not infer compatibility with other versions from these fixture results.

```ts
import { createXignetPayload } from '@xignet/payload/v3';

const xignet = createXignetPayload({
  issuer: process.env.XIGNET_ISSUER!,
  jwksUri: process.env.XIGNET_JWKS_URI!,
  resource: 'https://cms.example.com/api/mcp',
  admissionScopes: ['cms:access'],
  userCollection: 'users',
  resolveUser: async ({ identity, payload }) => {
    // Server-side lookup by (identity.issuer, identity.subject), requiring
    // an enabled local user. Do not auto-link by email or infer local roles.
    const user = await resolveExistingLocalUser(payload, identity);
    return user
      ? { status: 'allowed', user: { ...user, collection: 'users' } }
      : { status: 'denied', reason: 'unbound' };
  },
  mcp: {
    enabled: true,
    collections: { bulletins: { find: { scopes: ['cms:read'] } } },
    globals: {},
  },
});

// Add xignet.plugin() once to buildConfig({ plugins: [...] }).
// Mount the metadata GET route using the standard Next.js handler helper:
import { createXignetRouteHandlers } from '@xignet/payload/next';
const handlers = createXignetRouteHandlers(xignet);
export const GET = handlers.metadata;
```

The example's `resolveExistingLocalUser` belongs to the project, not this package. A successful resolver must return a real Payload user with an ID and the configured auth collection discriminator. Resolver failures propagate; they do not become an unbound-user response.

For a resource at `/api/mcp`, mount metadata at `/.well-known/oauth-protected-resource/api/mcp`. The resource origin must match configured `serverURL`, and its path must match the Payload API route plus `/mcp`. Trust settings are fixed configuration, never derived from request Host headers or token claims. Only the MCP routes accept Xignet Bearer; no global authentication strategy or cookie/API-key fallback is installed.

MCP operations require explicit scopes. Unsupported/unlisted operations, entities and experimental tools are closed. Deletion is not supported in this prerelease. The API-key collection added by the official plugin is hidden and denied to API callers; its schema is retained even with MCP disabled, so projects must include it in migrations. `mcp.enabled: false` removes the MCP routes and returns 404 metadata.

## Write policies

```ts
bulletins: {
  find: { scopes: ['cms:read'] },
  update: { scopes: ['cms:write'] },
  mutationPolicy: ({ originalDoc, data, operation, req, identity }) => {
    // This project has no drafts: any write changes public API content.
    return ['cms:publish'];
  },
}
```

Every enabled write requires a mutationPolicy. Return additional required scopes or `false` to refuse; scopes must also be declared in `mcp.scopesSupported` when they cannot be derived from operation policies. The policy runs before document changes and is evaluated for each update in a batch. Globals use update semantics. Project-specific draft, publish, retire and immediate-live behavior belongs here.

The adapter preserves the original Access return value, including Where document filters, after enforcing scopes. Field access remains Payload's responsibility. Official content tools use `overrideAccess: false`. Verified request markers survive Local API context copies but cannot be forged by JSON. These controls apply to `payloadAPI: 'MCP'`; existing public REST/GraphQL and trusted Local API behavior follow the project's existing rules.

## Validation

`pnpm --filter @xignet/payload test` initializes a temporary SQLite Payload database and sends requests through the actual official MCP handler. It verifies Bearer admission, token claims, local binding/disablement, scope-based tool lists, document/field access, user isolation, forged-context rejection, publication scopes, public access preservation and resolver outage propagation. Fixtures disable automatic types/import-map generation and release upstream MCP cleanup timers; they do not force-exit the test process.


## Native-session SSO

Set `login` on the integration:

```ts
login: {
  enabled: true,
  clientId: process.env.XIGNET_WEB_CLIENT_ID!,
  redirectUri: 'https://cms.example.com/auth/xignet/callback',
  scopes: ['openid', 'email'],
  transactionSecret: process.env.XIGNET_LOGIN_TRANSACTION_SECRET!,
  successRedirect: '/admin',
  session: { maxAgeSeconds: 7200, absoluteMaxAgeSeconds: 7200 },
}
```

Use a dedicated public web client with fixed callback and S256 PKCE, separate from MCP clients. The callback must share the configured CMS origin; redirects remain on that origin. `transactionSecret` must contain at least 32 random bytes. The adapter encrypts/authenticates the entire transaction in a short-lived, host-only HttpOnly SameSite=Lax cookie (Secure on HTTPS). It clears the cookie on completion or failure. Access/ID tokens and refresh credentials are not returned to application JavaScript or stored as browser sessions.

```ts
const handlers = createXignetRouteHandlers(xignet, {
  getPayload: async () => getPayload({ config }),
});
// Export GET = handlers.login at /auth/xignet/login.
// Export GET = handlers.callback at /auth/xignet/callback.
// Export GET = handlers.metadata at the resource's well-known path.
```

Provide the app's actual Payload instance lazily. SSO-enabled route factories require this provider. SSO requires the native local auth strategy and `useSessions`; MCP-only consumers may use other auth models. The adapter invokes beforeLogin/afterLogin hooks and composes existing refresh hooks. These HTTP login routes return redirects or generic error responses with no token body.

The plugin adds the private `xignet-sessions` collection even while login is disabled. Include it and the official MCP key collection in database migrations. It stores native SID linkage, absolute expiry and the verified access-token identity from login; it never stores the raw access/ID/refresh token. Metadata is not readable/writable through REST/MCP, including by ordinary admin accounts. The project remains responsible for approved `(issuer, subject)` bindings and local roles.

`resolveUser` receives `channel: 'session'` during subsequent SSO authentication and refresh. This is the historical verified identity stored at login, not a newly verified OAuth token: its OAuth expiry may have elapsed. Resolve current local binding/enablement and roles without treating that historical expiry as the browser session expiry. No Xignet network call is required on each native session request.

Native JWTs remain signed by the project's Payload secret and reference a real SID. Refresh cannot cross the stored absolute deadline. Missing/expired metadata and disabled/unbound users observed during authentication invalidate the native SID persistently. For immediate revocation, projects must call revokeUserSessions with the update request from their binding/enablement change hook; this also prevents a disable/re-enable sequence with no intervening request from reviving an old cookie. `integration.revokeUserSessions({ payload, userId, req? })` explicitly removes that user's SSO sessions while retaining independent local sessions. Native logout cleans the current metadata entry. Global Xignet logout is not an automatic CMS logout.

Login failure rolls back SID/metadata when the adapter supports transactions, or explicitly removes the newly created SID/metadata otherwise. Arbitrary external side effects in custom hooks cannot be rolled back by this package. Existing local-password login retains its native expiration and has no SSO marker.

## Auditing and release

The adapter logs structured MCP operation/transport outcomes with a generated request ID and verified issuer/subject/client/local user, without content bodies or credentials. SSO refusals, service failures and revocation have structured events; unexpected exception messages are not copied into HTTP error responses or logs.

Publish core first, then payload under `payload-vX.Y.Z` using `payload-publish.yml`. Configure npm trusted publishing for both new package names before tagging. Only the exact peer baseline above is supported in this prerelease; Payload's Node requirement is `^22.23.4 || >=24.22.1`; a server runtime is required. Adapter CI verifies Node 22.23.4, 24 and 26.13.1. Core independently supports Node 22.22.0+. The package's Next helpers use standard Request/Response and have no Next.js runtime import.

RPC audit events use the server-generated request ID, principal, allowlisted method/tool target and outcome (success, denied, failed, partial_failure or unobserved). They never include tool arguments, response content, access tokens or exception messages. Inspection retains at most 64 KiB per message. Response bytes are forwarded as the consumer reads them, with terminal audit on EOF, error or cancellation; an open stream does not block delivery. An oversized or unreadable request is recorded as unobserved. Official tool response hooks also report execution failures and partial bulk results, even when the transport returns HTTP 200.

The database adapter must provide read-after-write consistency for login session records. Before issuing the browser cookie, the callback confirms the native SID and private metadata with fresh reads outside the completed transaction, since some adapter commit helpers can suppress an underlying transaction failure. A missing record refuses login instead of issuing an unusable cookie.

For staged rollout, configure the final collection/global policies once and set `mcp.writesEnabled: false` to hide and deny create/update while retaining the same schema. Set it to true after write/publish validation; omission preserves the default of enabling configured operations. `mcp.enabled` and `login.enabled` also retain their private collections when disabled.
