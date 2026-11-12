# @xignet/payload

Xignet resource authorization for Payload v3. The adapter uses the official MCP plugin and applies token scopes together with existing Payload collection, document and field access. This is a preview SDK with MCP and native-session OIDC support; website rollout and final delivery verification remain in progress under the [implementation plan](../../docs/architecture/core-payload-implementation-plan.md).

The current test baseline is Payload and `@payloadcms/plugin-mcp` **3.93.0**. No broad v3 or v4 compatibility is declared. The upstream plugin currently resolves `mcp-handler` 1.1.0 with SDK 1.30.0 despite that handler declaring SDK 1.26.0 as its exact peer; the workspace explicitly acknowledges this one tested combination using pnpm.peerDependencyRules.allowedVersions. Strict-peer pnpm consumers must apply the same narrow rule. This does not permit any other SDK version. Do not infer compatibility with other versions from these fixture results.

## Standard plugin: passwordless managed users

```ts
import { xignetPlugin } from '@xignet/payload';
import { createDirectoryClient } from '@xignet/client/directory';

const xignet = xignetPlugin({
  resource: 'https://cms.example.com/api/mcp',
  admissionScopes: ['cms:access'],
  userCollection: 'users',
  directory: createDirectoryClient({
    clientId: process.env.XIGNET_DIRECTORY_CLIENT_ID!,
    clientSecret: process.env.XIGNET_DIRECTORY_CLIENT_SECRET!,
  }),
  users: {
    canManageBindings: (req) => req.user?.collection === 'users' && req.user.role === 'admin',
    allowUser: (user) => ['admin', 'editor'].includes(user.role),
    revokeOnFields: ['role'],
  },
  mcp: { enabled: true, collections: { bulletins: { find: { scopes: ['cms:read'] } } } },
  login: { /* dedicated web client and session options shown below */ },
});

// Standard Payload plugin: buildConfig({ plugins: [xignet] }).
// The same xignet object works with createXignetRouteHandlers.
```

The shared provider currently uses `https://signet.marxbio.tech`, the issuer advertised by the production Xignet AS. Projects do not repeat issuer/JWKS settings. A paired `provider: { issuer, jwksUri }` override supports tests or self-hosted Xignet; user data and request headers cannot select the trusted provider.

The plugin owns read-only `xignetIssuer`/`xignetSubject`, `xignetEnabled`, a compound unique identity index, a virtual confirmation field, the Directory lookup endpoint and revocation hooks. An administrator enters a company email, queries Xignet, confirms the identity and chooses a local role. The server resolves the email again on save and checks a five-minute signed preview bound to the acting administrator. A changed result requires a new preview; browser-supplied identity values cannot replace the Directory result. An existing binding cannot transfer to another issuer/subject. Email changes for the same subject, enablement, roles and deletion revoke existing sessions.

`POST /api/<userCollection>/xignet/resolve` requires an authenticated binding manager and an Origin matching the configured resource origin. This uses `@xignet/client/directory` server-side credentials, not the admin's CMS access token. SDK clients must never be exposed to browser code. Omitting `directory` disables provisioning and lookup, while allowing existing users to authenticate. Generate the Payload import map for both `@xignet/payload/components` and `@xignet/payload/client`; the latter requires the matching `@payloadcms/ui` peer.

At browser login the verified ID token must include `email_verified: true` and an email matching the bound local account. MCP continues to resolve only the verified `(issuer, sub)` and local eligibility; it does not expect an ID token or email claim. Directory resolves at provisioning time, not on every session/MCP request. This is not continuous synchronization or instant upstream revocation.

Managed users use Payload's supported `disableLocalStrategy: { enableFields: true }`, keeping auth/session fields while disabling local password operations. New records contain no password hash/salt. A custom `xignet-session` strategy accepts only the signed Payload SSO cookie/JWT with a valid native SID, private metadata, current local binding and absolute deadline. It does not accept Xignet access tokens outside MCP. API-key strategies, other auth strategies and automatic Admin login are rejected for this mode. Existing password hashes are retained in additive migrations but cannot authenticate.

Create the first admin through a trusted deployment/seed script using `payload.create` with the approved company email and explicit local role, without a password. Payload's normal public `first-register` password flow is disabled in this mode. An unauthenticated trusted server-side Local API create still resolves Directory but does not need an interactive confirmation. Local API calls carrying a user retain permission and preview checks. After Xignet login, that admin creates subsequent users in the Admin Panel. Generate and review database migrations in each project before enabling the plugin; it never pushes schema at runtime.

## Low-level adapter: custom resolver and mixed authentication

The existing `/v3` API below remains available when a project owns its binding storage or intentionally keeps native password/API-key authentication. Those choices are independent of the standard plugin's Xignet-only policy.

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

Provide the app's actual Payload instance lazily. SSO-enabled route factories require this provider. The low-level adapter's default mixed mode uses native local auth with `useSessions`; the standard plugin uses the dedicated Xignet-only strategy described above. MCP-only low-level consumers may use other auth models. The adapter invokes beforeLogin/afterLogin hooks and composes existing refresh hooks. These HTTP login routes return redirects or generic error responses with no token body.

Next standalone can expose its internal hostname and port in `Request.url`. The Next callback handler uses the trusted Payload `serverURL` as its public origin while retaining the incoming path and query for OIDC validation. Configure `serverURL` to the canonical CMS origin; Host and forwarded-host headers never select that origin. Direct `integration.callback` callers must supply the canonical public request URL themselves.

The plugin adds the private `xignet-sessions` collection even while login is disabled. Include it and the official MCP key collection in database migrations. It stores native SID linkage, absolute expiry and the verified access-token identity from login; it never stores the raw access/ID/refresh token. Metadata is not readable/writable through REST/MCP, including by ordinary admin accounts. The project remains responsible for approved `(issuer, subject)` bindings and local roles.

`resolveUser` receives `channel: 'session'` during subsequent SSO authentication and refresh. This is the historical verified identity stored at login, not a newly verified OAuth token: its OAuth expiry may have elapsed. Resolve current local binding/enablement and roles without treating that historical expiry as the browser session expiry. No Xignet network call is required on each native session request.

Native JWTs remain signed by the project's Payload secret and reference a real SID. Refresh cannot cross the stored absolute deadline. Missing/expired metadata and disabled/unbound users observed during authentication invalidate the native SID persistently. For immediate revocation, projects must call revokeUserSessions with the update request from their binding/enablement change hook; this also prevents a disable/re-enable sequence with no intervening request from reviving an old cookie. `integration.revokeUserSessions({ payload, userId, req? })` explicitly removes that user's SSO sessions while retaining independent local sessions. Native logout cleans the current metadata entry. Global Xignet logout is not an automatic CMS logout.

Login failure rolls back SID/metadata when the adapter supports transactions, or explicitly removes the newly created SID/metadata otherwise. Arbitrary external side effects in custom hooks cannot be rolled back by this package. Existing local-password login retains its native expiration and has no SSO marker.

## Auditing and release

The adapter logs structured MCP operation/transport outcomes with a generated request ID and verified issuer/subject/client/local user, without content bodies or credentials. SSO refusals, service failures and revocation have structured events; unexpected exception messages are not copied into HTTP error responses or logs.

Ensure the required core version is available, publish and verify the new client version through `client-publish.yml`, then publish payload under `payload-vX.Y.Z` using `payload-publish.yml`. Configure npm trusted publishing for both new package names before tagging. Only the exact peer baseline above is supported in this prerelease; Payload's Node requirement is `^22.23.4 || >=24.22.1`; a server runtime is required. Adapter CI verifies Node 22.23.4, 24 and 26.13.1. Core independently supports Node 22.22.0+. The package's Next helpers use standard Request/Response and have no Next.js runtime import.

RPC audit events use the server-generated request ID, principal, allowlisted method/tool target and outcome (success, denied, failed, partial_failure or unobserved). They never include tool arguments, response content, access tokens or exception messages. Inspection retains at most 64 KiB per message. Response bytes are forwarded as the consumer reads them, with terminal audit on EOF, error or cancellation; an open stream does not block delivery. An oversized or unreadable request is recorded as unobserved. Official tool response hooks also report execution failures and partial bulk results, even when the transport returns HTTP 200.

The database adapter must provide read-after-write consistency for login session records. Before issuing the browser cookie, the callback confirms the native SID and private metadata with fresh reads outside the completed transaction, since some adapter commit helpers can suppress an underlying transaction failure. A missing record refuses login instead of issuing an unusable cookie.

For staged rollout, configure the final collection/global policies once and set `mcp.writesEnabled: false` to hide and deny create/update while retaining the same schema. Set it to true after write/publish validation; omission preserves the default of enabling configured operations. `mcp.enabled` and `login.enabled` also retain their private collections when disabled.

## Reusing the adapter

Each CMS supplies its own canonical resource/serverURL, web client, secrets, auth collection, local resolver and collection/global policies. Keep project binding and role rules in that resolver and call `revokeUserSessions` from local lifecycle hooks; mount the shared Next handlers rather than copying the OIDC flow. Tests cover a second CMS profile with a `members` auth collection, separate origin/client/admission scope, native login, refresh and revocation. This fixture verifies configurable reuse; it is not a claim that a second production project has been deployed.

Directory audit records use generated `x-request-id` correlation IDs, local actor/user IDs and fixed operation/outcome/reason fields. Identity values, preview proofs and credentials are not logged. Downstream deployments must preserve the correlation header when forwarding to Directory.
