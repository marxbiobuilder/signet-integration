// What a consumer supplies to the integration: its values, behind the
// SIGNET_INTEGRATION_OPTIONS token or as a parameter to the pure functions.
// The mechanism files in this package carry no consumer value of their own.

// The environment variable names the integration reads. Named once by the
// consumer; the readers and the consumer's config validation read these.
export interface SignetEnvNames {
  // The deployment profile pair: the namespace the release is installed into
  // and the canonical resource / JWT audience it must match. Both are read;
  // the pair is checked against `deployedProfiles`.
  readonly deploymentNamespace: string;
  readonly jwtAudience: string;
  readonly jwtClockToleranceS: string;
  readonly jwtIssuer: string;
  readonly jwtJwksUri: string;
  // Consumer credential channels. Absent means the channel has no switch:
  // no `signetEnabled` name means the Bearer channel is always on (a service
  // with no other credential); no `legacyApiKeyEnabled` name means there is
  // no legacy channel.
  readonly legacyApiKeyEnabled?: string;
  readonly signetEnabled?: string;
}

export interface SignetDeployedProfile {
  readonly host: string;
  readonly namespace: string;
}

// The profile a process runs under with neither pair variable set, outside
// NODE_ENV=production: local development and the test suite. `environment`
// is not a field here -- the resolver stamps DEVELOPMENT_ENVIRONMENT, so a
// development process cannot borrow a deployed environment's name.
export interface SignetDevelopmentProfile {
  readonly canonicalResource: string;
  readonly host: string;
  readonly namespace: string;
}

export const DEVELOPMENT_ENVIRONMENT = 'development';

// `E` is the consumer's set of deployed environment names.
export interface SignetIntegrationOptions<E extends string = string> {
  // The OAuth scope that admits a token to the service at all. NOT a
  // business permission: a token carrying it and nothing in the consumer's
  // authorization data is a 403 exactly like one without it. Published in
  // the resource metadata and checked by the Bearer guard.
  readonly admissionScope: string;
  // The OAuth resource identifier and JWT audience for a deployed host. A
  // bare origin (`https://h`) and a resource with a path (`https://h/api/mcp`)
  // are both accepted; RFC 9728 §3.1's metadata URL and the challenge rule
  // follow from which one it is (bearer-challenge.ts).
  readonly canonicalResourceFor: (host: string) => string;
  // The fixed allowlist: which namespace/host pairs the service may be
  // deployed as. Deployment must supply the matching pair through `env`.
  readonly deployedProfiles: Readonly<Record<E, SignetDeployedProfile>>;
  readonly developmentProfile: SignetDevelopmentProfile;
  readonly env: SignetEnvNames;
  // The 403 body when the resolver refuses. It must not say WHICH of the
  // resolver's reasons applied; the default names no service.
  readonly principalRefusalMessage?: string;
  // RFC 6750 `realm` on every challenge the service sends.
  readonly realm: string;
  // The request property the Bearer guard attaches the resolved principal to.
  // Passport writes the verified identity to `user`; a consumer that already
  // reads `request.user` in its handlers names 'user' here, one that keeps
  // the identity and the principal apart names something else. Properties
  // Express and Nest already use are refused at construction.
  readonly requestPrincipalKey: string;
  // `scopes_supported` in the RFC 9728 metadata: every scope a client may ask
  // for, admission scope included.
  readonly scopesSupported: readonly string[];
}

export const SIGNET_INTEGRATION_OPTIONS = Symbol('SIGNET_INTEGRATION_OPTIONS');
