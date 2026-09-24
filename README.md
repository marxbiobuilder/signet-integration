# @marxbiotech/signet-integration

Signet (OAuth 2.1 / OIDC, Ory Hydra) **resource-server** integration for
NestJS: Bearer access-token verification against the issuer's JWKS, RFC 6750
`WWW-Authenticate` challenges, RFC 9728 protected-resource metadata, the
deployment-profile pair check, and token-scope narrowing. Signet is treated as
an **auth provider**: this package proves `(iss, sub)` and hands the claims to
your `SignetPrincipalResolver`; who that is locally, and how the mapping is
stored, is yours.

## Wiring

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
    deploymentNamespace: 'MY_DEPLOYMENT_NAMESPACE',
    jwtAudience: 'MY_JWT_AUDIENCE',
    jwtIssuer: 'MY_JWT_ISSUER',
    jwtJwksUri: 'MY_JWT_JWKS_URI',
    jwtClockToleranceS: 'MY_JWT_CLOCK_TOLERANCE_S',
    signetEnabled: 'SIGNET_AUTH_ENABLED',       // omit = the Bearer channel is always on
    legacyApiKeyEnabled: 'LEGACY_API_KEY_ENABLED', // omit = no legacy channel
  },
  realm: 'myservice',
  requestPrincipalKey: 'user',            // where the guard attaches your principal
  scopesSupported: ['myservice:access'],  // RFC 9728 scopes_supported; must include the admission scope
} as const satisfies SignetIntegrationOptions<'production' | 'staging'>;

// your resolver -- Passport's verify callback, as a Nest provider.
// Annotate the return type: a class method gets no contextual typing from
// `implements`, so without it `ok: true` widens to `boolean` and fails to compile.
@Injectable()
export class MyResolver implements SignetPrincipalResolver<MyPrincipal> {
  constructor(private readonly users: UsersRepository) {}
  async resolve(identity: VerifiedSignetIdentity): Promise<PrincipalResolution<MyPrincipal>> {
    const user = await this.users.findBySignetSubject(identity.subject); // or identity.claims.erp_user_id
    if (!user) return { ok: false, reason: 'unknown_subject' };          // → 403, reason only logged
    return { ok: true, principal: user, logFields: { userId: user.id } }; // logFields render on the decision line
    // throw new PrincipalStoreUnavailableError(cause) when the store is unreachable → 503
  }
}

// your auth module
@Module({
  imports: [
    UsersModule,
    SignetIntegrationModule.forRoot({
      options: MY_OPTIONS,
      resolver: MyResolver,          // a class, or { useFactory, inject } / { useValue } / { useExisting }
      imports: [UsersModule],        // whatever the resolver's constructor needs
    }),
  ],
  exports: [SignetIntegrationModule], // so the process module below can inject the package's providers
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

Requirements: `ConfigModule` must be global (the strategy, filter and profile
service inject `ConfigService`); validate the env variables named in `options.env`
in your own config validation (Joi or otherwise), the package only re-checks the
clock tolerance and throws on a missing issuer or JWKS URI.

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
issues), `startJwksServer()`, `FIXTURE_OPTIONS` and `FIXTURE_DEVELOPMENT_PROFILE`.

## What is deliberately NOT here

- How principals are stored (grant tables, a `users` column, a claim): the resolver's business.
- Consumer credential dispatch between Bearer and a legacy channel.
- Config validation of the env variables (see above).
- The login (OIDC authorization-code) flow. This package is the resource-server side only.

## Rules a consumer relies on

- A canonical resource WITH a path (an MCP endpoint URI): only that path's 401 carries `resource_metadata`. A BARE-ORIGIN resource: every 401 does.
- The admission scope is checked by the guard (403 with `insufficient_scope`); a 403 carrying `requiredScopes` gets `insufficient_scope`; a resolver refusal is a bare 403.
- Verifier failures (bad signature, wrong audience, unreachable JWKS) are one uniform 401; the reason is only logged.
- `iat` is not required and no `maxTokenAge` is applied; `client_id` is required (RFC 9068 §2.2, Signet issues it always).
- JWKS options are fixed: 3 s timeout, 30 s cooldown, 10 min cache.
- The guard's decision log line is `metric reason <your logFields> clientId environment`; the fixed keys are reserved.
