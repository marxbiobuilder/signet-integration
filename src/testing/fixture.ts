import { type SignetIntegrationOptions } from '../options';

// A complete options object for a fictional second service, for tests of
// the mechanism and for consumers' tests that need "some other service".
// Its canonical resource keeps a PATH (`/mcp`) so every derived path and URL
// differs from a bare-origin consumer's. A test that needs the bare-origin
// shape overrides `canonicalResourceFor` AND `developmentProfile.canonicalResource`
// together; the options validation refuses profiles whose paths differ.
export const FIXTURE_OPTIONS: SignetIntegrationOptions<
  'production' | 'staging'
> = {
  admissionScope: 'acme:access',
  canonicalResourceFor: (host) => `https://${host}/mcp`,
  deployedProfiles: {
    production: { host: 'acme.example', namespace: 'acme-production' },
    staging: { host: 'acme.staging.example', namespace: 'acme-staging' },
  },
  developmentProfile: {
    canonicalResource: 'http://localhost/mcp',
    host: 'localhost',
    namespace: 'development',
  },
  env: {
    deploymentNamespace: 'ACME_DEPLOYMENT_NAMESPACE',
    jwtAudience: 'ACME_JWT_AUDIENCE',
    jwtClockToleranceS: 'ACME_JWT_CLOCK_TOLERANCE_S',
    jwtIssuer: 'ACME_JWT_ISSUER',
    jwtJwksUri: 'ACME_JWT_JWKS_URI',
    legacyApiKeyEnabled: 'ACME_LEGACY_ENABLED',
    signetEnabled: 'ACME_SIGNET_ENABLED',
  },
  realm: 'acme',
  requestPrincipalKey: 'principal',
  scopesSupported: ['acme:access', 'widgets:read', 'widgets:write'],
};

export const FIXTURE_DEVELOPMENT_PROFILE = {
  ...FIXTURE_OPTIONS.developmentProfile,
  environment: 'development' as const,
};
