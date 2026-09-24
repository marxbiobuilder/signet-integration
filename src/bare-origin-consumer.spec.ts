import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { type ConfigService } from '@nestjs/config';

import {
  challengeFor,
  isResourceRequest,
  protectedResourceMetadataPath,
  protectedResourceMetadataUrl,
} from './bearer-challenge';
import { readChannelFlags } from './config';
import { type DeploymentProfile } from './deployment-profile';
import { JwtVerifier } from './jwt-verifier';
import { type SignetIntegrationOptions } from './options';
import { FIXTURE_OPTIONS } from './testing/fixture';
import { startTestIssuer, type TestIssuer } from './testing/signet-token';

// A consumer whose canonical resource is a BARE ORIGIN, whose Bearer channel
// has no switch and no legacy sibling, and whose authorization key is a
// custom claim the issuer puts on the token. The three rules for that shape
// are pinned here.
const BARE: SignetIntegrationOptions<'production' | 'staging'> = {
  ...FIXTURE_OPTIONS,
  canonicalResourceFor: (host) => `https://${host}`,
  developmentProfile: {
    canonicalResource: 'http://localhost',
    host: 'localhost',
    namespace: 'development',
  },
  env: {
    deploymentNamespace: 'BARE_NS',
    jwtAudience: 'BARE_AUD',
    jwtClockToleranceS: 'BARE_TOLERANCE',
    jwtIssuer: 'BARE_ISSUER',
    jwtJwksUri: 'BARE_JWKS',
    // No signetEnabled, no legacyApiKeyEnabled.
  },
  realm: 'bare',
};

const DEV: DeploymentProfile = {
  ...BARE.developmentProfile,
  environment: 'development',
};

const ON = { legacyApiKeyEnabled: false, signetEnabled: true };

describe('a bare-origin consumer', () => {
  it('appends the well-known segment at the root and mounts the controller there', () => {
    expect(protectedResourceMetadataUrl('https://bare.example')).toBe(
      'https://bare.example/.well-known/oauth-protected-resource',
    );
    expect(protectedResourceMetadataPath(BARE)).toBe(
      '/.well-known/oauth-protected-resource',
    );
  });

  // With a bare-origin resource the whole origin IS the resource, so every
  // 401 carries `resource_metadata`.
  it.each(['/', '/mcp', '/purchase-orders', '/docs'])(
    'treats %s as a resource request and puts resource_metadata on its 401',
    (path) => {
      expect(isResourceRequest(DEV, path)).toBe(true);
      expect(
        challengeFor(BARE, DEV, ON, new UnauthorizedException(), path),
      ).toEqual({
        header:
          'Bearer realm="bare", resource_metadata="http://localhost/.well-known/oauth-protected-resource", scope="acme:access"',
        malformedCarrier: false,
      });
    },
  );

  it('still answers a plain 403 bare and a scope carrier with insufficient_scope', () => {
    expect(
      challengeFor(BARE, DEV, ON, new ForbiddenException('no'), '/mcp'),
    ).toEqual({ header: null, malformedCarrier: false });
    expect(
      challengeFor(
        BARE,
        DEV,
        ON,
        Object.assign(new ForbiddenException('scope'), {
          requiredScopes: ['acme:access'],
        }),
        '/mcp',
      ),
    ).toEqual({
      header:
        'Bearer realm="bare", error="insufficient_scope", scope="acme:access"',
      malformedCarrier: false,
    });
  });

  it('has the Bearer channel always on and no legacy channel when the env names are absent', () => {
    const get = jest.fn();
    expect(readChannelFlags(BARE, { get } as unknown as ConfigService)).toEqual(
      { legacyApiKeyEnabled: false, signetEnabled: true },
    );
    // Nothing was read: there is no variable to read.
    expect(get).not.toHaveBeenCalled();
  });

  describe('a resolver keyed on a custom claim', () => {
    let issuer: TestIssuer;
    beforeAll(async () => {
      issuer = await startTestIssuer();
    });
    afterAll(async () => issuer.close());

    it('finds the claim on the verified identity', async () => {
      const verifier = new JwtVerifier({
        audience: 'https://bare.example',
        clockToleranceS: 60,
        issuer: 'https://iss.bare.invalid',
        jwksUri: issuer.keys.url,
      });
      const token = await issuer.sign({
        aud: ['https://bare.example'],
        client_id: 'bare-cli',
        erp_user_id: '100101',
        iss: 'https://iss.bare.invalid',
        scp: ['acme:access'],
        sub: 'user-1',
      });
      const result = await verifier.verify(token);
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      // What such a consumer's SignetPrincipalResolver reads.
      expect(result.identity.claims.erp_user_id).toBe('100101');
      expect(result.identity.claims.aud).toEqual(['https://bare.example']);
      expect(result.identity.subject).toBe('user-1');
    });
  });
});
