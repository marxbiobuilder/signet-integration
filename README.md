# signet-integration

pnpm monorepo of the npm packages for integrating with Xignet (Signet, an
OAuth 2.1 / OIDC provider on Ory Hydra). Each package is versioned, tagged and
published on its own.

| Package | Directory | Use it for |
|---|---|---|
| [`@xignet/core`](packages/core/README.md) | `packages/core` | Framework-independent JWT/JWKS, scopes, OAuth metadata and OIDC + PKCE. |
| [`@xignet/payload`](packages/payload/README.md) | `packages/payload` | Payload v3 MCP authorization and native-session OIDC login. |
| [`@xignet/nest`](packages/nest/README.md) | `packages/nest` | NestJS resource servers and interactive login: Bearer verification, RFC 6750 challenges, RFC 9728 metadata, deployment profiles, authorization code + PKCE. Formerly `@marxbiotech/signet-integration`. |
| [`@xignet/client`](packages/client/README.md) | `packages/client` | Outbound machine-to-machine OAuth (`client_credentials`), without NestJS or Passport. |

## Development

```sh
pnpm install
pnpm lint && pnpm typecheck && pnpm test && pnpm build
```

The root scripts run each package's script of the same name; a package without
it is skipped. Use `pnpm --filter <package> <script>` for one package.

## Releases

| Package | Tag | Workflow |
|---|---|---|
| `@xignet/core` | `core-vX.Y.Z` | `.github/workflows/core-publish.yml` |
| `@xignet/payload` | `payload-vX.Y.Z` | `.github/workflows/payload-publish.yml` |
| `@xignet/nest` | `nest-vX.Y.Z` | `.github/workflows/nest-publish.yml` |
| `@xignet/client` | `client-vX.Y.Z` | `.github/workflows/client-publish.yml` |

All packages publish with npm trusted publishing (OIDC); see each package's README.
