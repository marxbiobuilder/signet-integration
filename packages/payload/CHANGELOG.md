# Changelog

## 0.1.0-beta.2

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
