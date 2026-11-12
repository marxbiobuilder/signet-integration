# @xignet/payload

Xignet resource authorization for Payload v3. The adapter uses the official MCP plugin and applies token scopes together with existing Payload collection, document and field access. This package is under implementation and has not been published. The current checkpoint implements MCP; OIDC routes, native-session lifecycle and website rollout remain in progress under the [implementation plan](../../docs/architecture/core-payload-implementation-plan.md).

The current test baseline is Payload and `@payloadcms/plugin-mcp` **3.93.0**. No broad v3 or v4 compatibility is declared. The upstream plugin currently resolves `mcp-handler` 1.1.0 with SDK 1.30.0 despite that handler declaring SDK 1.26.0 as its exact peer; this upstream mismatch must be accounted for in the final supported install matrix. Do not infer compatibility with other versions from these fixture results.

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
