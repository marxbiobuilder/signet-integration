# @marxbiotech/mcp-device-adapter

A command/stdio MCP server that runs on the agent host and connects to a
Signet-protected Rover or Lander MCP endpoint over HTTPS Streamable HTTP.
The person authorizing signs in on their own phone or computer. No Signet
password or browser session is placed on the agent host.

This package is separate from the NestJS `@marxbiotech/signet-integration`
package. It bundles their shared OAuth primitives and needs no NestJS runtime.

## Install and register

Requires Node.js 22 or newer, npm access, and network access from **the
process running this command** to Signet and the chosen service. For private
services, join that host to the tailnet and configure its DNS, TLS trust and
ACLs first. The adapter does not enroll hosts in Tailscale or expose services
to the internet.

Once version 0.1.0 has been published, register this command with the MCP host:

```sh
npx --yes --package=@marxbiotech/mcp-device-adapter@0.1.0 mcp-device-adapter --service rover --env staging
```

For Lander, register a second command MCP connection with `--service lander`.
Choose `--env production` explicitly when needed; the default is staging.
Keep the package version pinned. Installation and MCP initialization require
no npm login for the public package and no Signet credentials.

In Grok Bot, ask it to add a **command MCP running on its cloud computer**
with the command above. This is different from registering a remote URL
connector: Grok Bot remote connectors run on the provider's connector backend,
which does not automatically inherit the cloud computer's tailnet connection.
Do not substitute Grok Build's CLI configuration for Grok Bot's registration.
See [Grok Bot command MCP](https://docs.x.ai/grok-bot/computer-and-apps#connect-an-app)
and [remote MCP network path](https://docs.x.ai/grok-bot/security#mcp-servers-and-the-network-policy).

For local development, build the repository and register:

```sh
node /absolute/path/to/signet-integration/packages/mcp-device-adapter/dist/main.cjs --service rover --env staging
```

`--help` prints usage and exits. Unknown flags, arbitrary issuers/resources,
and token arguments are refused. Normal operation reserves stdout for MCP.

## Authorize and use

1. Call `signet_auth_begin`. It returns the verification URI, user code and
   expiry immediately; the adapter polls in the background.
2. Give the link and code only to the person requesting this connection. That
   person opens the link on their own device, signs into Signet, checks the
   client, code and requested permissions, and approves. Do not enter codes
   from unsolicited messages or approve a flow you did not initiate.
3. Call `signet_auth_status` in later tool calls. Do not repeatedly call begin
   to poll. The adapter obeys Signet's polling interval and `slow_down`.
4. When the state is `ready`, refresh `tools/list`. The adapter sends
   `notifications/tools/list_changed`. Upstream tools appear with an
   `upstream__` prefix and retain their input/output schemas and annotations.
5. Use those tools normally. Authorization headers are injected internally.
6. Call `signet_auth_disconnect` to cancel a pending flow or forget the
   current credentials. Restarting the process also forgets them.

Host support for command lifecycle and dynamic tool-list refresh must be
verified on the actual Grok Bot account. Restarting the process loses the
in-memory token, so restarting is not a substitute for refreshing its tool
list after authorization.

## Profiles and permissions

| Service | Environment | Client                | Resource                               | Requested scopes              |
| ------- | ----------- | --------------------- | -------------------------------------- | ----------------------------- |
| Rover   | staging     | rover-command-staging | https://rover.marxbiotech.dev/api/mcp  | openid purchase-orders:create |
| Rover   | production  | rover-command         | https://rover.marxbio.tech/api/mcp     | openid purchase-orders:create |
| Lander  | staging     | lander-query-staging  | https://lander.marxbiotech.dev/api/mcp | openid queries:read           |
| Lander  | production  | lander-query          | https://lander.marxbio.tech/api/mcp    | openid queries:read           |

All profiles use `https://signet.marxbio.tech`. Each must be registered as a
public client with the device grant and **one resource**. Signet currently
does not select the device flow's audience from the device POST `resource`
parameter. Sending that parameter is not proof of audience binding. The
adapter checks the PRM, verifies the signed JWT, expected client, audience,
required scope, subject and ERP email, then connects to the fixed resource.
Rover and Lander authorizations are independent; one service's token is never
used for the other. Their server/ERP permission checks still apply.

## Credentials and failure behavior

This initial version uses short-lived access tokens held **only in memory**.
It requests no `offline_access` and does not persist or refresh credentials.
`reauth_required` means start a new flow explicitly. Device-code expiry,
denial and cancellation terminate that flow; errors never trigger endless
new authorization requests.

The client validates TLS normally, refuses cross-origin authorization
endpoints and redirects, and never sends a Bearer token to metadata paths.
Status and tool results contain no access token or device code. Upstream
transport/protocol diagnostics are replaced with fixed messages. A failed
tool call is **not automatically retried**: the operation might already
have been performed. Inspect the original operation/idempotency key before
deciding to retry a write.

Disconnect is local deletion, not guaranteed remote revocation. A previously
issued access token can remain usable until its expiry. ERP results can be
private data and are still sent to the MCP host/model as tool results.

Grok Bot's cloud computer and command MCPs are shared by bots on the same
account. This adapter does not provide a security boundary between them, nor
does keeping a token in process memory protect it from other programs with
the same OS privileges. Treat it as delegation to that account's computer.

## Release

The client has its own version in `packages/mcp-device-adapter/package.json`
and tags `adapter-vX.Y.Z` (`adapter-vX.Y.Z-beta.0` for a prerelease).
The existing NestJS package retains its `vX.Y.Z` release contract.

Before a first client release, a maintainer must establish the npm package
and configure its trusted publisher for repository
`marxbiobuilder/signet-integration`, workflow `publish-adapter.yml`, following
npm's current first-publish/trusted-publisher setup. The existing package's
trusted-publisher registration does not authorize a different npm package.

The workflow validates the tag, runs lint, type checks, tests, builds and a
clean packed-package install/stdio smoke test, then publishes with OIDC and
provenance. Prereleases use their first prerelease identifier as the npm
dist-tag; stable releases use npm's default. Do not publish from a developer
machine or push a release tag merely to test the workflow.
