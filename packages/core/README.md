# @xignet/core

Framework-independent Xignet verification and authorization code + PKCE login for Node.js 22.22+ and 24. The Payload adapter and website integration are tracked in [the implementation plan](../../docs/architecture/core-payload-implementation-plan.md).

```ts
import { createTokenVerifier, hasAllScopes } from '@xignet/core';

const verifier = createTokenVerifier({
  issuer: 'https://xignet.marxbio.tech',
  audience: 'https://cms.example.com/api/mcp',
  jwksUri: process.env.XIGNET_JWKS_URI!,
});
const result = await verifier.verifyAccessToken(accessToken);
if (!result.ok) {
  // invalid_token: reject the credential. verification_unavailable: fail
  // closed and report service availability separately. Do not echo reasons.
} else if (hasAllScopes(result.identity, ['cms:access', 'cms:read'])) {
  // Resolve a local principal by (issuer, subject), then apply local access.
}
```

Create one verifier per process/resource. Configuration is trusted, fixed server configuration; issuer and JWKS must never come from an unverified token. HTTPS is required. `allowInsecureLoopback: true` permits HTTP only on loopback hosts for local fixtures/development. Clock tolerance defaults to 60 seconds and must be an integer from 0 to 300.

`VerifiedIdentity` contains issuer, subject, clientId, deduplicated scopes, expiresAt (Unix seconds) and verified claims. The same verifier exposes `verifyIdToken(token, clientId)` with the same failure categories and a successful `claims` result; it shares the JWKS cache but checks the ID-token client audience. No local role is inferred. The identity and parsed scopes are frozen. Claims are shallowly frozen; consumers must not mutate nested application claims or use them as a substitute for local authorization.

The legacy `JwtVerifier`, result types and `createScopeVocabulary` are exported for Nest compatibility. Their existing contracts remain unchanged, including the caller's responsibility for configuration validation. New consumers should use `createTokenVerifier`. The existing vocabulary's configurable default actions are not an admission rule: check admission scopes separately.

## OAuth metadata and challenges

`@xignet/core/oauth` exports `createProtectedResourceMetadata`, `protectedResourceMetadataUrl`, `createBearerChallenge` and their types. Configure the canonical resource; do not derive it from an untrusted Host header. For `https://cms.example.com/api/mcp`, discovery is at `https://cms.example.com/.well-known/oauth-protected-resource/api/mcp`.

`createBearerChallenge` accepts a resource, requiredScopes and optional `invalid_token` or `insufficient_scope` error. Scope values are checked against the OAuth scope-token grammar. A local authorization refusal should not advertise missing OAuth scopes when the token already has them.

## Interactive OIDC

```ts
import { createOidcClient } from '@xignet/core/oidc';

const client = createOidcClient({
  issuer, audience, jwksUri,
  clientId: 'cms-web',
  redirectUri: 'https://cms.example.com/auth/xignet/callback',
  scopes: ['openid', 'email'],
  admissionScopes: ['cms:access'],
});
const { authorizationUrl, transaction } = await client.begin();
// Server adapter: encrypt and authenticate the entire transaction in a
// short-lived HttpOnly browser-bound cookie, then redirect to authorizationUrl.
const result = await client.complete({ callbackUrl, transaction });
// Resolve result.identity to a local user. ID-token claims accompany it.
// Clear the transaction cookie on success AND failure; create a local session.
```

The transaction contains the secret PKCE verifier and must never be sent to application JavaScript, URL query parameters, plaintext/signed-only cookies or logs. `complete` assumes its adapter obtained the entire transaction from authenticated encrypted storage, not from callback query/body. It validates state, expiry, callback, client/issuer/resource binding, both token signatures and audiences, the access-token client and admission scopes, and matching token subjects. It returns verified identity and ID-token claims, without retaining or exposing the token response. The authorization server's single-use code prevents successful callback replay; clearing a stateless cookie alone is not server-side replay storage.

This public-client flow requires `openid`, excludes `offline_access`, uses S256 PKCE and has no nonce parameter. Network calls do not follow redirects. `OidcError` separates protocol refusals from `verification_unavailable`; its optional `detail` carries only machine-readable verification diagnostics, never tokens or response bodies. discovery/transport errors use the separately exported `LoginDiscoveryError` and `LoginTransportError`. Unexpected process defects propagate. Endpoint discovery is cached until restart after success and retried after failure.

The `login-state` helpers exported from `/oidc` preserve the existing Nest wire format and are low-level compatibility primitives. Their `LoginState` payload is NOT the full `LoginTransaction`; Payload adapters must not attempt to serialize a transaction with `sealLoginState`.

## Packaging and release

CommonJS require and ESM imports are supported, including TypeScript consumers with legacy Node resolution via `typesVersions`. The repository builds core before checking dependent packages. Publish core before a Nest release that depends on it. Configure npm trusted publishing for `core-publish.yml` before pushing the first release tag; no publication is triggered by this implementation PR.

Run `pnpm --filter @xignet/core test` for real local HTTP JWKS/OIDC tests. `pnpm test` also exercises existing Nest and client consumers.
