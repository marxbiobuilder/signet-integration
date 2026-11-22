import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import {
  DEVELOPMENT_ENVIRONMENT,
  SIGNET_INTEGRATION_OPTIONS,
  type SignetDeployedProfile,
  type SignetIntegrationOptions,
} from './options';

// The deployment profile identifies which environment a process serves: the
// namespace the release is installed into, paired with the environment's
// canonical resource / JWT audience. Only a known pair is accepted; which
// pairs are known, and what the variables are called, is the consumer's
// business. This file is the rule that checks a pair against that table. The
// env values do not identify the Pod's actual deployment target.

export interface DeploymentProfile<E extends string = string> {
  // The OAuth resource identifier and JWT audience for this environment.
  readonly canonicalResource: string;
  readonly environment: E | typeof DEVELOPMENT_ENVIRONMENT;
  readonly host: string;
  readonly namespace: string;
}

export type DeploymentProfileResolution<E extends string> =
  { ok: false; reason: string } | { ok: true; profile: DeploymentProfile<E> };

export interface DeploymentProfileInput {
  audience: string | undefined;
  namespace: string | undefined;
  nodeEnv: string | undefined;
}

// Pure, so the consumer's boot-time validation and the runtime service
// evaluate the identical rule. Exact string matches throughout: no
// trailing-slash tolerance or case folding.
export function resolveDeploymentProfile<E extends string>(
  options: SignetIntegrationOptions<E>,
  input: DeploymentProfileInput,
): DeploymentProfileResolution<E> {
  const { audience, namespace, nodeEnv } = input;
  const { deploymentNamespace: namespaceEnv, jwtAudience: audienceEnv } =
    options.env;
  if (namespace === undefined && audience === undefined) {
    if (nodeEnv === 'production') {
      return {
        ok: false,
        reason: `${namespaceEnv} and ${audienceEnv} are required in production`,
      };
    }
    return {
      ok: true,
      profile: {
        ...options.developmentProfile,
        environment: DEVELOPMENT_ENVIRONMENT,
      },
    };
  }
  if (namespace === undefined || audience === undefined) {
    return {
      ok: false,
      reason: `${namespaceEnv} and ${audienceEnv} must be configured together`,
    };
  }
  const candidates = (
    Object.entries(options.deployedProfiles) as [E, SignetDeployedProfile][]
  )
    .filter(([, profile]) => profile.namespace === namespace)
    .map(([environment, { host }]) => ({
      environment,
      host,
      canonicalResource: options.canonicalResourceFor(host),
    }));
  if (candidates.length === 0) {
    return {
      ok: false,
      reason: `${namespaceEnv} names no known deployment (got a value not in the deployed profiles table)`,
    };
  }
  if (
    candidates.length > 1 &&
    !options.sharedDeploymentNamespaces?.includes(namespace)
  ) {
    return {
      ok: false,
      reason: `${namespaceEnv}=${namespace} matches multiple profiles and is not explicitly shared`,
    };
  }
  const matches = candidates.filter(
    ({ canonicalResource }) => audience === canonicalResource,
  );
  if (matches.length === 0) {
    // These resources are public identifiers. Label multiple candidates to
    // make the expected configuration clear.
    const expected =
      candidates.length === 1
        ? candidates[0].canonicalResource
        : `one of ${candidates.map(({ environment, canonicalResource }) => `${environment}=${canonicalResource}`).join(', ')}`;
    return {
      ok: false,
      reason: `${audienceEnv} does not match ${namespaceEnv}=${namespace} (expected ${expected})`,
    };
  }
  // Options passed directly to the pure resolver may not have been validated.
  if (matches.length > 1) {
    return {
      ok: false,
      reason: `${namespaceEnv} and ${audienceEnv} match multiple deployed profiles`,
    };
  }
  return {
    ok: true,
    profile: { ...matches[0], namespace },
  };
}

// Runtime access to the profile the consumer's config validation already
// checked at boot. Resolved once, at construction, from the same pure
// function -- so a process whose config bypassed that validation still cannot
// obtain a profile it should not have: it throws here instead.
//
// A consumer that wants `profile.environment` typed as its own union
// subclasses this, re-declares `profile` with the narrower type and checks
// it in its constructor; the DI token cannot carry the type parameter.
@Injectable()
export class SignetDeploymentProfileService {
  readonly profile: Readonly<DeploymentProfile>;

  constructor(
    configService: ConfigService,
    @Inject(SIGNET_INTEGRATION_OPTIONS) options: SignetIntegrationOptions,
  ) {
    const resolution = resolveDeploymentProfile(options, {
      audience: configService.get<string>(options.env.jwtAudience),
      namespace: configService.get<string>(options.env.deploymentNamespace),
      nodeEnv: configService.get<string>('NODE_ENV'),
    });
    if (!resolution.ok) {
      throw new Error(`deployment profile rejected: ${resolution.reason}`);
    }
    this.profile = resolution.profile;
  }
}
