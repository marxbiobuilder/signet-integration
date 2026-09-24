import { type ConfigService } from '@nestjs/config';

import {
  bearerChallenge,
  insufficientScopeChallenge,
  InsufficientScopeException,
  isResourceRequest,
  protectedResourceMetadataPath,
} from './bearer-challenge';
import { readChannelFlags, readSignetAuthConfig } from './config';
import { resolveDeploymentProfile } from './deployment-profile';
import { type SignetIntegrationOptions } from './options';
import {
  FIXTURE_DEVELOPMENT_PROFILE,
  FIXTURE_OPTIONS,
} from './testing/fixture';

// The mechanism under two different consumers' options. Every output must
// derive from the options it was given: a function that quietly hard-coded
// one consumer's value would agree with that consumer's spec and disagree
// here. OTHER differs from the fixture in realm, scopes, variable names,
// resource path and table.
const OTHER: SignetIntegrationOptions<'live' | 'test'> = {
  admissionScope: 'other:enter',
  canonicalResourceFor: (host) => `https://${host}/v2/agent`,
  deployedProfiles: {
    live: { host: 'other.example', namespace: 'other-live' },
    test: { host: 'other.test.example', namespace: 'other-test' },
  },
  developmentProfile: {
    canonicalResource: 'http://localhost/v2/agent',
    host: 'localhost',
    namespace: 'development',
  },
  env: {
    deploymentNamespace: 'OTHER_NS',
    jwtAudience: 'OTHER_AUD',
    jwtClockToleranceS: 'OTHER_TOLERANCE',
    jwtIssuer: 'OTHER_ISSUER',
    jwtJwksUri: 'OTHER_JWKS',
    legacyApiKeyEnabled: 'OTHER_LEGACY',
    signetEnabled: 'OTHER_SIGNET',
  },
  realm: 'other',
  requestPrincipalKey: 'actor',
  scopesSupported: ['other:enter'],
};

function fakeConfig(env: Record<string, string>) {
  const get = jest.fn(
    (key: string, fallback?: unknown) => env[key] ?? fallback,
  );
  const getOrThrow = jest.fn((key: string) => {
    if (env[key] === undefined) throw new Error(`${key} missing`);
    return env[key];
  });
  return {
    get,
    getOrThrow,
    service: { get, getOrThrow } as unknown as ConfigService,
  };
}

describe('the mechanism under two consumers’ options', () => {
  it('resolves each deployment profile from its own table', () => {
    expect(
      resolveDeploymentProfile(FIXTURE_OPTIONS, {
        audience: 'https://acme.example/mcp',
        namespace: 'acme-production',
        nodeEnv: 'production',
      }),
    ).toMatchObject({ ok: true, profile: { environment: 'production' } });
    expect(
      resolveDeploymentProfile(OTHER, {
        audience: 'https://other.example/v2/agent',
        namespace: 'other-live',
        nodeEnv: 'production',
      }),
    ).toMatchObject({ ok: true, profile: { environment: 'live' } });
    // Each table is a stranger to the other's pair.
    expect(
      resolveDeploymentProfile(OTHER, {
        audience: 'https://acme.example/mcp',
        namespace: 'acme-production',
        nodeEnv: 'production',
      }),
    ).toMatchObject({
      ok: false,
      reason: expect.stringContaining('OTHER_NS') as unknown,
    });
  });

  it('names the caller’s own variables in every refusal', () => {
    const mismatch = resolveDeploymentProfile(OTHER, {
      audience: 'https://other.test.example/v2/agent',
      namespace: 'other-live',
      nodeEnv: 'production',
    });
    expect(mismatch).toMatchObject({
      ok: false,
      reason: expect.stringContaining('OTHER_AUD') as unknown,
    });
    expect((mismatch as { reason: string }).reason).toContain(
      'https://other.example/v2/agent',
    );
    expect(
      resolveDeploymentProfile(OTHER, {
        audience: undefined,
        namespace: undefined,
        nodeEnv: 'production',
      }),
    ).toEqual({
      ok: false,
      reason: 'OTHER_NS and OTHER_AUD are required in production',
    });
    expect(
      resolveDeploymentProfile(OTHER, {
        audience: 'x',
        namespace: undefined,
        nodeEnv: 'production',
      }),
    ).toEqual({
      ok: false,
      reason: 'OTHER_NS and OTHER_AUD must be configured together',
    });
  });

  it('stamps the development environment on the caller’s development profile', () => {
    expect(
      resolveDeploymentProfile(OTHER, {
        audience: undefined,
        namespace: undefined,
        nodeEnv: 'test',
      }),
    ).toEqual({
      ok: true,
      profile: { ...OTHER.developmentProfile, environment: 'development' },
    });
  });

  it('reads flags and verifier settings under the caller’s variable names only', () => {
    const fake = fakeConfig({
      // The fixture's names are set too, and must be ignored.
      ACME_JWT_ISSUER: 'https://iss.acme.example',
      ACME_SIGNET_ENABLED: 'false',
      OTHER_ISSUER: 'https://iss.other.example',
      OTHER_JWKS: 'https://iss.other.example/jwks.json',
      OTHER_LEGACY: 'false',
      OTHER_SIGNET: 'true',
    });
    expect(readChannelFlags(OTHER, fake.service)).toEqual({
      legacyApiKeyEnabled: false,
      signetEnabled: true,
    });
    expect(
      readSignetAuthConfig(OTHER, fake.service, {
        ...OTHER.developmentProfile,
        environment: 'development',
      }),
    ).toEqual({
      jwt: {
        audience: 'http://localhost/v2/agent',
        clockToleranceS: 60,
        issuer: 'https://iss.other.example',
        jwksUri: 'https://iss.other.example/jwks.json',
      },
      legacyApiKeyEnabled: false,
      signetEnabled: true,
    });
    for (const [key] of fake.get.mock.calls as [string][]) {
      expect(key.startsWith('OTHER_') || key === 'OTHER_TOLERANCE').toBe(true);
    }
    expect(fake.getOrThrow).not.toHaveBeenCalledWith('ACME_JWT_ISSUER');
  });

  it('names the caller’s variable when a required setting is missing or malformed', () => {
    const missing = fakeConfig({
      OTHER_JWKS: 'https://iss.other.example/jwks.json',
      OTHER_SIGNET: 'true',
    });
    const profile = {
      ...OTHER.developmentProfile,
      environment: 'development' as const,
    };
    expect(() => readSignetAuthConfig(OTHER, missing.service, profile)).toThrow(
      /OTHER_ISSUER/,
    );
    const bad = fakeConfig({
      OTHER_ISSUER: 'https://iss.other.example',
      OTHER_JWKS: 'https://iss.other.example/jwks.json',
      OTHER_SIGNET: 'true',
      OTHER_TOLERANCE: 'none',
    });
    expect(() => readSignetAuthConfig(OTHER, bad.service, profile)).toThrow(
      /OTHER_TOLERANCE/,
    );
  });

  it('renders challenges in the caller’s realm and admission scope, at the caller’s metadata URL', () => {
    const dev = {
      ...OTHER.developmentProfile,
      environment: 'development' as const,
    };
    expect(bearerChallenge(OTHER, dev, { resource: false })).toBe(
      'Bearer realm="other", scope="other:enter"',
    );
    expect(bearerChallenge(OTHER, dev, { resource: true })).toBe(
      'Bearer realm="other", resource_metadata="http://localhost/.well-known/oauth-protected-resource/v2/agent", scope="other:enter"',
    );
    expect(
      bearerChallenge(FIXTURE_OPTIONS, FIXTURE_DEVELOPMENT_PROFILE, {
        resource: false,
      }),
    ).toBe('Bearer realm="acme", scope="acme:access"');
    expect(insufficientScopeChallenge(OTHER, ['other:enter', 'x:y'])).toBe(
      'Bearer realm="other", error="insufficient_scope", scope="other:enter x:y"',
    );
  });

  it('derives the metadata path and the resource predicate from the caller’s resource path', () => {
    expect(protectedResourceMetadataPath(OTHER)).toBe(
      '/.well-known/oauth-protected-resource/v2/agent',
    );
    expect(protectedResourceMetadataPath(FIXTURE_OPTIONS)).toBe(
      '/.well-known/oauth-protected-resource/mcp',
    );
    const dev = {
      ...OTHER.developmentProfile,
      environment: 'development' as const,
    };
    expect(isResourceRequest(dev, '/v2/agent')).toBe(true);
    expect(isResourceRequest(dev, '/v2/agent/')).toBe(true);
    expect(isResourceRequest(dev, '/mcp')).toBe(false);
    expect(isResourceRequest(dev, '/v2/agent/tools')).toBe(false);
  });

  it('builds the door exception from the given admission scope', () => {
    const exception = new InsufficientScopeException(OTHER.admissionScope);
    expect(exception.requiredScopes).toEqual(['other:enter']);
    expect(exception.message).toBe(
      'token does not carry the other:enter scope',
    );
    expect(exception.getStatus()).toBe(403);
  });
});
