# Xignet stable releases — 2026-11-13

Published and verified on npm:

| Package | Stable latest | GitHub Release | OIDC publication |
|---|---|---|---|
| @xignet/core | 0.1.0 | [core-v0.1.0](https://github.com/marxbiobuilder/signet-integration/releases/tag/core-v0.1.0) | [43427161605](https://github.com/marxbiobuilder/signet-integration/actions/runs/43427161605) |
| @xignet/client | 0.3.0 | [client-v0.3.0](https://github.com/marxbiobuilder/signet-integration/releases/tag/client-v0.3.0) | [43427542291](https://github.com/marxbiobuilder/signet-integration/actions/runs/43427542291) |
| @xignet/payload | 0.1.1 | [payload-v0.1.1](https://github.com/marxbiobuilder/signet-integration/releases/tag/payload-v0.1.1) | [43430038893](https://github.com/marxbiobuilder/signet-integration/actions/runs/43430038893) |

Nest already has stable0.4.0 and is not republished. The separate device-adapter PR13 is excluded. Work remains on `codex/xignet-stable-release-20261113`; [release PR26](https://github.com/marxbiobuilder/signet-integration/pull/26) is ready for review, with no main merge.

## Source and compatibility

The selected functional baseline is SDK PR25 / Payload beta.9, `9c203e1ccf9a2e84bc308b5031b7c9e2caa0524c`. Core/client publish from `9c29a1b8e5bb842d1bbac615698cafa7d8686fd5`; Payload0.1.1 publishes from `02f81eef55dad7671abe77961338c5462fe219a4`. All50 dist files remain byte-identical to their tested beta artifacts (core18/client6/payload26). Stable Payload dependencies resolve to `@xignet/core ^0.1.0` and `@xignet/client ^0.3.0`; no Xignet prerelease dependency remains.

Payload requires exact3.93.0 peers, Node `^22.23.4 || >=24.22.1`, TypeScript `>=5.7.3 <6`, and a compatible React/ReactDOM host stack. The beta.9 removal of `xignetEnabled` remains: eligibility is the verified binding plus project `allowUser`; trusted legacy binding uses explicit `context.xignetBindIdentity: true`. Beta.8 consumers need the documented schema migration and must stop the old binary before applying it. Changing only the website package string is insufficient. Consumer rollout is tracked by [website PR26](https://github.com/marxbiotech/www-marxbiotech-com/pull/26); this SDK release performs no website deployment or real-identity change.

## Validation and packaging correction

Node26.13.1 / pnpm9.1.1 frozen install, lint, client formatting, typecheck and build pass. Tests: core13, client105, Payload51, Nest281 — **450 passed**. The six-job release CI covers Node22.23.4/24/26.13.1 adapters and Node22.22.0/24 clients: [CI](https://github.com/marxbiobuilder/signet-integration/actions/runs/43429770529). Website beta.9 CI independently passed CMS build/typecheck, a Postgres baseline and22 Xignet integration tests at `1589c155267adac01decaf128c8eedcca124c1e9`; see `website-ci.json`. This is fixture/CI evidence, not a new human staging login claim.

The first clean npm-only consumer exposed the missing TypeScript runtime peer in Payload MCP3.93.0 (`convertCollectionSchemaToZod.js` imports TypeScript). The SDK development workspace had supplied it incidentally. Published Payload0.1.0 is superseded by **0.1.1**, which explicitly declares that existing runtime requirement. Runtime authorization code is unchanged; the0.1.0 GitHub release points users to0.1.1.

The new `pnpm test:packed` creates a consumer outside the monorepo, installs actual packed SDK archives and the supported host stack, without explicitly installing TypeScript, and loads CJS/ESM, Directory, Payload and Next entry points. Removing the peer reproduces `ERR_MODULE_NOT_FOUND`; restoring it passes. The gate is mandatory in CI and before Payload publication; the0.1.1 publication actually passed it. See `packaged-peer-regression.json` and `payload-publish.json`.

After publication, a separate new directory installed **only npm registry versions** (core0.1.0/client0.3.0/payload0.1.1). All entry points load; the dependency graph contains those stable versions and automatically resolves TypeScript5.9.3. Each registry tarball's SHA-512 SRI,50 dist files, and registry-provided SLSA provenance subject/source tag/workflow/commit match the tested candidates. These provenance metadata comparisons are recorded in `registry-verification.json`; the attestation URLs remain public for independent verification.

Exact release URLs, source commits and outcomes: `delivery.json`. SDK release blockers: none. Npm versions remain immutable; the correction uses a new patch rather than replacing or unpublishing0.1.0. The website's migration and application-specific grants/rollout remain its separate delivery work.
