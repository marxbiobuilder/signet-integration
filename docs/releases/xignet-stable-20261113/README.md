# Xignet stable release candidate — 2026-11-13

Promote `@xignet/core` to **0.1.0**, `@xignet/client` to **0.3.0**, and `@xignet/payload` to **0.1.0**. `@xignet/nest` already has stable **0.4.0** on npm and is not republished without a package change/version bump; the separate device-adapter PR13 is outside this release.

Candidate source is SDK PR25 `9c203e1ccf9a2e84bc308b5031b7c9e2caa0524c` (Payload beta.9), with only version/release-documentation changes. The published beta archives and candidate archives have byte-identical `dist/` files (core18/client6/payload26). Packed Payload dependencies resolve to `^0.1.0` core and `^0.3.0` client, with no prerelease or workspace references. See `pack-verification.json`.

## Validation

On Node26.13.1 / pnpm9.1.1: frozen install, root lint/typecheck/build, client formatting, root coverage tests and client tests pass. Totals: core13, client105, Payload51, Nest281; **450 passed**, no failures. No SDK source or test file was changed from beta.9.

The preceding SDK CI on the same source passed Node22.23.4/24/26.13.1 adapter tests, Node22.22.0/24 client tests and full validation: [CI](https://github.com/marxbiobuilder/signet-integration/actions/runs/43424229750). The new release commit must also pass its own CI before tags are pushed. SDK [PR25](https://github.com/marxbiobuilder/signet-integration/pull/25) has no remaining critical/important review findings at that source. The website [PR26](https://github.com/marxbiotech/www-marxbiotech-com/pull/26) reports actual beta.9 tarball Postgres baseline +22 integration tests, build and typecheck. Those consumer checks were not independently repeated in this release task and are not a new staging rollout claim.

## Compatibility and publishing

Payload requires the exact 3.93.0 peer baseline and Node `^22.23.4 || >=24.22.1`. Stable 0.1.0 includes beta.9's removal of `xignetEnabled`: eligibility is the verified binding plus the project `allowUser` policy; explicit trusted legacy binding uses `context.xignetBindIdentity: true`. Consumers of beta.8 need the documented column-removal migration and must stop the old binary before applying it. Replacing the website package string alone is insufficient; this release does not deploy that migration or modify another open PR.

Use existing npm OIDC trusted-publisher workflows only; no local npm publish or token is needed. Publish `core-v0.1.0`, verify its registry manifest, then `client-v0.3.0`, verify it, then `payload-v0.1.0`. Verify final `latest` tags, registry dependencies, packaged dist equivalence and provenance. npm artifacts are immutable; do not unpublish or retag old versions to undo a release. A correction requires the next stable version.

No website preview/production deployment, security-setting change, real identity creation, or credential change is part of publishing these packages. Remaining application-specific staged rollout/grant testing is documented in the consumer PR and is distinct from SDK fixture/packaging evidence.

## Clean-consumer correction

The first npm-only consumer exposed a missing runtime peer in Payload MCP3.93.0: `convertCollectionSchemaToZod.js` imports TypeScript, but the MCP package declares no TypeScript dependency. The SDK development workspace supplied it incidentally. Payload0.1.1 explicitly declares required `typescript >=5.7.3 <6`; host React/ReactDOM must also use compatible versions. Adapter runtime source stays unchanged.

The new `pnpm test:packed` creates a consumer outside the monorepo, packs core/client/payload, installs only their archives and the supported Payload/React host stack, then loads CJS/ESM, Directory, Payload and Next entry points. It intentionally does not install TypeScript explicitly. Removing the peer reproduced `ERR_MODULE_NOT_FOUND` for TypeScript; restoring it passed. The gate now runs in CI and before every Payload publication. Payload51 tests, typecheck, lint and both regression directions pass locally. This supersedes the initial0.1.0 packaging result; final npm verification will use0.1.1.
