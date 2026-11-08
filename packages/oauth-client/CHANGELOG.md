# Changelog

## 0.1.0

- Add framework-independent Signet client credentials with `openid-client`.
- Use RFC 6749 encoded Basic authentication and form-body audience/scope.
- Cache tokens with expiry margin, share parallel exchanges and support safe
  invalidation of rejected tokens.
- Keep credentials, response bodies and upstream causes out of errors/logs.
- Support CommonJS and ESM on Node.js >=22.22.0.
