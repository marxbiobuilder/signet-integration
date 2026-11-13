# Changelog

## 0.1.0-beta.4

- Point the standard plugin provider preset at the deployed `https://xignet.marxbio.tech` issuer and JWKS. Existing Signet bindings are not migrated automatically; pass an explicit provider for that issuer if still needed.

## 0.1.0-beta.3

- Use the CMS `/api/mcp` resource audience for both MCP and opt-in REST access tokens. REST still applies its own admission scopes, route allowlist, operation scopes and local access rules.
- Consumers of the REST adapter must request tokens for the shared CMS resource; tokens for the former `/api` audience are rejected. Existing service client grants may need to be moved to the `/api/mcp` resource.

## 0.1.0-beta.2

- Add opt-in REST Bearer validation with a distinct audience, human binding checks, explicitly approved service principals, operation scopes and an HTTP boundary that prevents anonymous/cookie fallback.
- Add `legacyAPIKeys` as a temporary compatibility switch, independent of passwordless human login. REST does not grant admin, delete, bulk-write, auth or GraphQL capabilities.

- Provision identities through `@xignet/client/directory`: protected Admin lookup, expiring preview confirmation and authoritative revalidation on save.
- Require verified matching email at login; disallow automatic identity reassignment and revoke sessions when email changes.
- Retain collection verification checks in the custom session strategy and isolate the SSO-marker regression test.

- Add a standard `xignetPlugin` with a shared provider preset, managed issuer/subject bindings, Admin login component and lifecycle revocation.
- Support passwordless users with Payload's `disableLocalStrategy` and a dedicated Xignet session strategy; verify native SID, bounded refresh and logout without synthetic passwords.
- Keep the existing `/v3` mixed-auth adapter available for custom integrations.

## 0.1.0-beta.1

- Validate GitHub Actions OIDC publishing after initial package registration.
- Normalize Next standalone callback origins from trusted Payload serverURL while preserving callback path/state validation.

## 0.1.0-beta.0

- Add Xignet verification and scoped authorization around the official Payload 3.93 MCP plugin.
- Preserve native collection/document/field access, apply publication policies and deny undeclared operations.
- Add encrypted OIDC transaction routes and native SID sessions with bounded refresh, local-user revalidation, logout and revocation.
- Verify behavior with real HTTP issuer fixtures, official MCP transport and isolated SQLite Payload databases.
