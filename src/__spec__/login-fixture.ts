import { type SignetLoginEntry } from '../login-entry';
import { type SignetIntegrationOptions } from '../options';
import { FIXTURE_OPTIONS } from '../testing/fixture';

// Spec-only: the login entry and options the login specs share, on top of
// FIXTURE_OPTIONS (production and staging, plus development).

export const LOGIN_CLIENT_ID = 'acme-web';
export const LOGIN_STATE_SECRET = 'a-login-state-secret-of-32-bytes!';
export const LOGIN_CALLBACK_PATH = '/auth/signet/callback';

export const LOGIN_ENTRY = {
  name: 'acme-login',
  redirectUris: {
    development: `http://localhost:3000${LOGIN_CALLBACK_PATH}`,
    production: `https://acme.example${LOGIN_CALLBACK_PATH}`,
    staging: `https://acme.staging.example${LOGIN_CALLBACK_PATH}`,
  },
} as const satisfies SignetLoginEntry<'production' | 'staging'>;

export const LOGIN_OPTIONS: SignetIntegrationOptions = {
  ...FIXTURE_OPTIONS,
  env: {
    ...FIXTURE_OPTIONS.env,
    login: {
      clientId: 'ACME_LOGIN_CLIENT_ID',
      stateSecret: 'ACME_LOGIN_STATE_SECRET',
    },
  },
};

// The env a login spec runs under, against a test authorization server.
export function loginEnv(
  server: { issuer: string; jwksUri: string },
  overrides: Record<string, string | undefined> = {},
): Record<string, string | undefined> {
  return {
    ACME_JWT_ISSUER: server.issuer,
    ACME_JWT_JWKS_URI: server.jwksUri,
    ACME_LOGIN_CLIENT_ID: LOGIN_CLIENT_ID,
    ACME_LOGIN_STATE_SECRET: LOGIN_STATE_SECRET,
    ACME_SIGNET_ENABLED: 'true',
    NODE_ENV: 'test',
    ...overrides,
  };
}
