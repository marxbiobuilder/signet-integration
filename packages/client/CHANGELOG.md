# Changelog

## 0.3.0

- Release the server-only Directory identity lookup API as stable, with deployed Xignet defaults, validated responses, token caching and bounded read-only retry.
- Preserve the existing client-credentials and Bearer request APIs; explicit Signet issuer overrides remain supported.

## 0.3.0-beta.1

- Point Directory defaults at the deployed `https://xignet.marxbio.tech` issuer, audience, token endpoint, and resolve endpoint. Existing callers using the Signet issuer must pass explicit overrides.

## 0.3.0-beta.0

- Add a server-only Directory email-to-sub lookup client, reusing machine authentication, token caching and bounded resource-401 retry.
- Validate authoritative identity responses and expose safe failure codes with bounded response bodies and timeouts.
- Permit explicitly enabled HTTP loopback token endpoints for isolated development fixtures.

## 0.2.1

- Sanitize asynchronous response-value rejections and dispose the unused
  response, matching synchronous value/getter failures.

## 0.2.0

- Add optional `executeWithBearer` and `createFetchOperation` APIs for shared
  resource-401 handling, explicit replay policy and unused-response disposal.
- Add safe `SignetRequestError` classifications for configuration, token and
  resource failures. No Axios/framework dependency or application logging.
- Preserve the existing token acquisition/cache/invalidation API unchanged.

## 0.1.1

- Default the token endpoint to `https://xignet.marxbio.tech/oauth2/token`.
  `tokenUrl` is now optional; explicit HTTPS overrides remain supported.
  Audience and scope are still required.

## 0.1.0

- Publish under the concise `@xignet/client` name. This replaces
  `@xignet/oauth-client`; the runtime API is unchanged.

- Add framework-independent Signet client credentials with `openid-client`.
- Use RFC 6749 encoded Basic authentication and form-body audience/scope.
- Cache tokens with expiry margin, share parallel exchanges and support safe
  invalidation of rejected tokens.
- Keep credentials, response bodies and upstream causes out of errors/logs.
- Support CommonJS and ESM on Node.js >=22.22.0.
