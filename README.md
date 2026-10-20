# @marxbiotech/signet-integration

Signet (OAuth 2.1 / OIDC, Ory Hydra) **resource-server** integration for
NestJS: Bearer access-token verification against the issuer's JWKS, RFC 6750
`WWW-Authenticate` challenges, RFC 9728 protected-resource metadata, the
deployment-profile pair check, and token-scope narrowing -- plus the login
(authorization code + PKCE) flow up to a verified identity. Signet is treated as
an **auth provider**: this package proves `(iss, sub)` and hands the claims to
your `SignetPrincipalResolver`; who that is locally, and how the mapping is
stored, is yours.

## Wiring

Two ways in. Both verify the same way, classify the resolver's outcome the same
way (401 / 403 / 503 / 500) and write the same decision log line; pick by where
you want the principal to land.

### A. Your own Passport strategy (`request.user` is your principal)

```ts
// your-signet.options.ts -- your values, one object
export const MY_OPTIONS = {
  admissionScope: 'myservice:access',
  canonicalResourceFor: (host) => `https://${host}/api/mcp`, // or `https://${host}` for a bare origin
  deployedProfiles: {
    production: { host: 'my.example', namespace: 'my-production' },
    staging: { host: 'my.staging.example', namespace: 'my-staging' },
  },
  developmentProfile: { canonicalResource: 'http://localhost/api/mcp', host: 'localhost', namespace: 'development' },
  env: {
    deploymentNamespace: 'SIGNET_DEPLOYMENT_NAMESPACE',
    jwtAudience: 'SIGNET_JWT_AUDIENCE',
    jwtIssuer: 'SIGNET_JWT_ISSUER',
    jwtJwksUri: 'SIGNET_JWT_JWKS_URI',
    jwtClockToleranceS: 'SIGNET_JWT_CLOCK_TOLERANCE_S',
    signetEnabled: 'SIGNET_AUTH_ENABLED',       // omit = the Bearer channel is always on
    legacyApiKeyEnabled: 'LEGACY_API_KEY_ENABLED', // omit = no legacy channel
  },
  realm: 'myservice',
  requestPrincipalKey: 'user',            // route B attaches here; route A leaves it to Passport
  scopesSupported: ['myservice:access'],  // RFC 9728 scopes_supported; must include the admission scope
} as const satisfies SignetIntegrationOptions<'production' | 'staging'>;

// your strategy: Passport's verify callback, with the identity already proven.
// The package's dependencies are property-injected; the constructor is yours.
@Injectable()
export class MySignetStrategy extends SignetPrincipalStrategy<MyUser> {
  constructor(private readonly users: UsersRepository) { super(); }
  async resolve(identity: VerifiedSignetIdentity): Promise<PrincipalResolution<MyUser>> {
    const user = await this.users.findBySignetSubject(identity.subject); // or identity.claims.erp_user_id
    if (!user) return { ok: false, reason: 'unknown_subject' };          // → 403, reason only logged
    return { ok: true, principal: user, logFields: { userId: user.id } }; // logFields render on the decision line
    // throw new PrincipalStoreUnavailableError(cause) when the store is unreachable → 503
  }
}

@Module({
  imports: [UsersModule, SignetIntegrationModule.forPassport({ options: MY_OPTIONS })],
  providers: [
    MySignetStrategy,                                          // registers itself with Passport
    { provide: APP_GUARD, useClass: SignetPassportGuard },     // AuthGuard('signet-jwt') that honours @Public()
    { provide: APP_FILTER, useClass: BearerChallengeFilter },  // RFC 6750 challenges on 401/403
  ],
  controllers: [createProtectedResourceController(MY_OPTIONS), ...yourControllers],
})
export class ApiModule {}
```

`SignetPassportGuard` is `AuthGuard('signet-jwt')` plus `@Public()` and a
uniform 401; any `AuthGuard('signet-jwt')` of your own works too. Handlers read
the principal from `request.user` as they always did.

### B. Module-wired resolver (principal under `requestPrincipalKey`)

The same options and the same `resolve`, as a provider the module binds:

```ts
@Injectable()
export class MyResolver implements SignetPrincipalResolver<MyUser> {
  constructor(private readonly users: UsersRepository) {}
  async resolve(identity: VerifiedSignetIdentity): Promise<PrincipalResolution<MyUser>> { /* as above */ }
}

@Module({
  imports: [
    UsersModule,
    SignetIntegrationModule.forRoot({
      options: MY_OPTIONS,
      resolver: MyResolver,          // a class, or { useFactory, inject } / { useValue } / { useExisting }
      imports: [UsersModule],        // whatever the resolver's constructor needs
    }),
  ],
  exports: [SignetIntegrationModule],
})
export class AuthModule {}

// the process module that serves the resource
@Module({
  imports: [AuthModule],
  controllers: [createProtectedResourceController(MY_OPTIONS), ...yourControllers],
  providers: [
    { provide: APP_GUARD, useClass: SignetBearerGuard },      // honours @Public(); or call it from your own credential dispatcher
    { provide: APP_FILTER, useClass: BearerChallengeFilter }, // or call challengeFor() from your own filter
  ],
})
export class ApiModule {}
```

Here Passport's `request.user` stays the verified identity and the principal
goes under `options.requestPrincipalKey` (`principal`, say), which is what a
consumer with several credential channels and its own dispatcher wants.

### C. Logging users in (authorization code + PKCE)

For a web app that signs people in with Signet and then runs on its own
session: the browser goes through the authorization-code flow, the package
exchanges the code, verifies the **access token** and the **ID token**, and
runs your resolver -- the `SignetPrincipalResolver` contract as above, plus a
second argument carrying the ID token's claims. A class cannot extend both
strategies, so to share one resolver between the channels, inject a resolver
service into each strategy and delegate `resolve` to it. What you do with the
principal (issue a session cookie, redirect) is yours.

```ts
export const WEB_LOGIN = {
  name: 'signet-login', // Passport strategy name; one entry per redirect URI
  redirectUris: {       // verbatim as registered at the IdP; never built from Host;
                        // one per deployed environment in your options, plus development
    production: 'https://app.example.com/auth/signet/callback',
    staging: 'https://app.staging.example.com/auth/signet/callback',
    development: 'http://localhost:3000/auth/signet/callback',
  },
  scopes: ['openid', 'email'], // must include openid; the admission scope is added
} as const satisfies SignetLoginEntry<'production' | 'staging'>;

@Injectable()
export class WebSignetLogin extends SignetLoginStrategy<User>(WEB_LOGIN) { // name <User>: it is not inferred
  constructor(private readonly users: UsersService) { super(); }
  async resolve(
    identity: VerifiedSignetIdentity,       // from the access token, as on the Bearer channel
    { idTokenClaims }: SignetLoginContext,  // from the ID token
  ): Promise<PrincipalResolution<User>> {
    const user = await this.users.findByEmail(idTokenClaims.email as string);
    return user ? { ok: true, principal: user } : { ok: false, reason: 'no_account' };
  }
}

@Injectable()
export class WebSignetCallbackGuard extends AuthGuard(WEB_LOGIN.name) {
  override handleRequest<U>(error: Error | null, user: U): U {
    if (error instanceof SignetLoginError) {
      // error.reason: cancelled, state_invalid, token_exchange_failed, ...
      throw new LoginFailedException(error.reason); // your UI: usually a 302 to the login page
    }
    if (error) throw error; // SignetDecision's 403/503/500, as on the Bearer channel
    return user;
  }
}

@Controller('auth')
export class AuthController {
  constructor(private readonly signetLogin: WebSignetLogin) {}

  @Public() @Get('signet')
  async start(@Res() res: Response) {
    res.redirect(await this.signetLogin.begin(res));
  }

  @Public() @Get('signet/callback') @UseGuards(WebSignetCallbackGuard)
  async callback(@Req() req: Request, @Res() res: Response) { /* your session, then 302 */ }
}

@Module({
  imports: [SignetIntegrationModule.forPassport({ options: APP_OPTIONS })],
  providers: [WebSignetLogin],
  controllers: [AuthController],
})
export class AuthModule {}
```

Name the login variables in `options.env.login`: `{ clientId, stateSecret }`
-- the public client's id, and a secret of 32 random bytes or more (`openssl
rand -base64 32`) that the state cookie is encrypted under. At `onModuleInit`
the strategy checks, whatever the Signet flag: that both names are given,
and that the entry has a redirect URI for each deployed environment and
development, and none for an environment the options do not name. With the
flag on it also reads both values and checks the issuer (refusing an issuer
that is not an http(s) URL, a client id that is empty or padded with
whitespace -- a mounted secret's trailing newline -- or a secret under 32
bytes); with the flag off it reads neither, and both steps throw
`SignetLoginError(DISABLED)`. If your subclass overrides `onModuleInit`, call
`super.onModuleInit()`; without it the flow is still built, at the first
login, and these checks move there.

What to know:

- **Guard the callback with `AuthGuard(entry.name)`** and override
  `handleRequest`, as above. `SignetPassportGuard` and `SignetBearerGuard`
  run the Bearer strategy, not the login one; if one of them is your
  APP_GUARD, mark both login routes `@Public()` (as above), or the browser
  gets a Bearer 401 before the login strategy runs. A `SignetLoginError` that
  escapes `handleRequest` is a bare 401; `BearerChallengeFilter` adds no
  `WWW-Authenticate` to it.
- Unlike the Bearer strategies, the login strategy's `validate()` throws:
  the callback route has one strategy, and the UI must tell "you cancelled"
  from "try again".
- `begin()` must be reached on the same host as the redirect URI: the state
  cookie is host-only and scoped to the redirect URI's path. A front end on
  another host proxies `/auth/*` to the API.
- One login in flight per entry and browser: a second `begin()` (another
  tab) replaces the first's state cookie, so the first tab's callback is
  `STATE_INVALID`. Retrying from the login page is the answer.
- Every environment's redirect URI is checked when the strategy class is
  created (parseable, no fragment or credentials, https outside
  `development`), and the set of environments at `onModuleInit`, so a
  missing, extra, malformed or http production URI fails locally. A
  misspelt host or path still fails only at the IdP.
- The callback checks the state before it reads the IdP's answer, error
  responses included: a forged `?error=access_denied` is `STATE_INVALID`,
  not `CANCELLED`. The state cookie is cleared on every callback with the
  flag on, on the browser only -- the server keeps no record of used states,
  and what stops a replayed callback is the IdP's single-use code. Any
  replica with the same `stateSecret` opens a state another sealed: no
  sticky sessions needed.
- The authorization request carries exactly one `resource`, the profile's
  canonical resource, so the access token's `aud` is what the verifier
  expects. Which claims Signet puts on the access token is its policy's
  business, documented in Signet's resource-server contract
  (`docs/resource-server-contract.md` in marxbiotech/signet-marxbio-tech) --
  `email`, for one, only for a resource marked `erp: true`.
- **Take the user's email from the ID token, not the access token.** Ask for
  the `email` scope (`scopes: ['openid', 'email']`): Signet then puts
  `email`, `email_verified: true` and `hd` on the ID token, and its consent
  screen makes `email` mandatory (Signet's `docs/resource-policy.md`). The
  ID token is checked against the same keys, algorithms, issuer and clock
  tolerance as the access token, its `aud` must include the client id (with
  several audiences, `azp` must be the client id), and its `sub` must equal
  the access token's. No nonce: the code is bound to the browser by PKCE and
  the ID token comes straight from the token endpoint. A missing or failing
  ID token is `TOKEN_REJECTED`, its detail starting `id_token`
  (`id_token_missing`, `id_token_subject_mismatch`, `id_token:<jose code>`).
  `scopes` without `openid` is refused when the strategy class is created.
- The issuer's discovery document is fetched on the first login and kept
  until the process restarts. Signet announces a change of its issuer or
  JWKS address in advance (same contract); if its authorization or token
  endpoint ever moves, logins fail with `discovery_failed` or
  `token_exchange_failed` (`status_404`) until a restart.
- A token without the admission scope (the user unticked it at consent) is
  `ADMISSION_SCOPE_NOT_GRANTED`, not `SignetDecision`'s re-authorise 403.
- The rejection line is `signet login rejected: metric=signet_login_rejected
  reason=<SignetLoginFailure> detail=… entry=… source=… route=<path>`; no
  token, code, state or raw query (`detail` may carry the IdP's `error`
  code, sanitised and clipped). `STATE_INVALID`'s detail tells the operator
  where to look: `cookie_missing` (SameSite, Path, a proxy), `unopenable`
  (replicas with different secrets, a rotation, tampering), `expired`,
  `malformed`, `entry`, `state`. Every reason is a `warn`; alert on the
  reason label (`discovery_failed`, `token_exchange_failed` and
  `token_rejected` are infrastructure, `cancelled` is a user). The decision
  line after a verified identity is `SignetDecision`'s, as on the Bearer
  channel.
- A defect in the package's own code is not a login failure: it propagates
  and Nest answers 500.

### Entry points

- `@marxbiotech/signet-integration` -- everything.
- `@marxbiotech/signet-integration/passport` -- everything except
  `createProtectedResourceController`, whose file needs `@nestjs/swagger` and
  `@nestjs/throttler` (both optional peers). Import from here if you serve the
  metadata document some other way.
- `@marxbiotech/signet-integration/testing` -- see below.

Requirements: `ConfigModule` must be global (the strategy, filter and profile
service inject `ConfigService`); validate the env variables named in `options.env`
in your own config validation (Joi or otherwise), the package only re-checks the
clock tolerance and throws on a missing issuer or JWKS URI -- and, with a login
strategy and the flag on, on an issuer that is not an http(s) URL, a login
client id that is missing, empty or padded with whitespace, or a state secret
that is missing or under 32 bytes.

Handlers get a typed principal through
`createSignetPrincipalDecorator(MY_OPTIONS, isMyPrincipal)`; Nest does not check
the parameter's declared type, so the predicate is the enforcement.

`forRoot` validates the options at construction (admission scope present in
`scopesSupported`, no quote-breaking characters in `realm`/`admissionScope`,
unique namespaces and hosts, one resource path across every profile, no
reserved `requestPrincipalKey`) and `createScopeVocabulary` validates its
encoder (one-to-one, disjoint from the admission scope, defaults inside the
vocabulary).

Testing: `@marxbiotech/signet-integration/testing` exports `startTestIssuer()`
(a local JWKS endpoint plus a signer that mints tokens in the shape Signet
issues), `startJwksServer()`, `FIXTURE_OPTIONS` and `FIXTURE_DEVELOPMENT_PROFILE`,
and for the login flow `startTestAuthorizationServer({ clientId })`: discovery,
and a token endpoint that checks PKCE, `redirect_uri` and `client_id` and
redeems each code once; `authorize(url, grant?)` / `deny(url, error?)` play
the IdP's login page (throwing on a malformed request) and return the
callback URL; `scriptTokenEndpoint()` makes the token endpoint fail (a status
with or without an OAuth error, a raw body such as a proxy's HTML, no
`access_token`, a redirect, no answer, a stalled body) and
`overrideDiscovery()` makes discovery fail (a status, a raw body, no answer,
a stalled body) or replaces its document -- one script shape at a time, the
union rejects mixtures; `sign()` signs any payload with the issuer's key
(`exp` 5 min); `tokenRequests()` and `discoveryRequests()` record what
arrived; an error inside the server itself drops the connection, is kept in
`failures()`, and makes `close()` reject, so a bug in the test server fails
the suite instead of passing as the issuer's answer; `reset()` clears
scripts, override, records and failures (issued codes stay; single-use
anyway).

## What is deliberately NOT here

- How principals are stored (grant tables, a `users` column, a claim): the resolver's business.
- Consumer credential dispatch between Bearer and a legacy channel.
- Config validation of the env variables (see above).
- Beyond a verified identity in the login flow: sessions, logout, refresh, where to return to after login (`returnTo` is an open-redirect surface; the package accepts no URL from a request).
- Confidential clients (`client_secret_*`), nonce, and `/userinfo`: the login flow is a public client with PKCE, the identity comes from the access token, and the ID token (verified, see above) is enough for the user's email.

## Rules a consumer relies on

- A canonical resource WITH a path (an MCP endpoint URI): only that path's 401 carries `resource_metadata`. A BARE-ORIGIN resource: every 401 does.
- The admission scope is checked by the guard (403 with `insufficient_scope`); a 403 carrying `requiredScopes` gets `insufficient_scope`; a resolver refusal is a bare 403.
- Verifier failures (bad signature, wrong audience, unreachable JWKS) are one uniform 401; the reason is only logged.
- `iat` is not required and no `maxTokenAge` is applied; `client_id` is required (RFC 9068 §2.2, Signet issues it always).
- JWKS options are fixed: 3 s timeout, 30 s cooldown, 10 min cache.
- The decision log line is `metric reason <your logFields> clientId environment`, written under your strategy's or guard's class name; the fixed keys are reserved.

## Development and release

```sh
pnpm install
pnpm lint && pnpm typecheck && pnpm test && pnpm build
```

Releases are cut by tag. Write the `CHANGELOG.md` entry, bump `version` in
`package.json` on `main`, then push the matching tag:

```sh
git tag v0.2.0 && git push origin v0.2.0
```

`.github/workflows/publish.yml` refuses a tag that does not equal
`v<package.json version>`, runs lint, tests and build, and publishes with npm
trusted publishing (OIDC). Nothing is published from a developer machine.
