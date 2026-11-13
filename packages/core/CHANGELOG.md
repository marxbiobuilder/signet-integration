# Changelog

## 0.1.0

- Release the framework-independent JWT/JWKS, scope and OIDC + PKCE primitives as stable, preserving the extracted Nest compatibility contracts.
- Support CommonJS/ESM entry points and Node.js 22.22.0+.

## 0.1.0-beta.1

- Validate GitHub Actions OIDC publishing after initial package registration.

## 0.1.0-beta.0

- Extract the existing Nest verifier, scope vocabulary and pure login primitives without changing their compatibility contracts.
- Add validated token verification, OAuth resource metadata/challenges and framework-independent OIDC + PKCE flow.
- Cover signatures, claims, cache, issuer outage, token/client bindings, state, replay and CommonJS/ESM entry points with HTTP fixtures.
