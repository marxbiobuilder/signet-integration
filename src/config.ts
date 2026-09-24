import { type ConfigService } from '@nestjs/config';

import { type DeploymentProfile } from './deployment-profile';
import { type SignetIntegrationOptions } from './options';

// The variable NAMES come from the options, never from this file.
export type SignetEnvOptions = Pick<SignetIntegrationOptions, 'env'>;

export interface JwtSettings {
  // The expected `aud`: the deployment profile's canonical resource. The
  // audience variable is only cross-checked against the namespace at boot
  // and is never read here.
  readonly audience: string;
  readonly clockToleranceS: number;
  readonly issuer: string;
  readonly jwksUri: string;
}

export interface ChannelFlags {
  readonly legacyApiKeyEnabled: boolean;
  readonly signetEnabled: boolean;
}

// The verifier settings are tied to the Signet flag by the type itself. In
// an intersection a field is readonly only if every declaration says so.
export type SignetAuthConfig = ChannelFlags &
  (
    | { readonly jwt: JwtSettings; readonly signetEnabled: true }
    | { readonly jwt: null; readonly signetEnabled: false }
  );

// The channel switches alone -- what a credential dispatcher needs. Never
// touches the verifier settings, so a dispatcher can be built (and tested)
// without an issuer. A channel with no variable name has no switch: Signet
// is then always on, and there is no legacy channel.
export function readChannelFlags(
  options: SignetEnvOptions,
  configService: ConfigService,
): ChannelFlags {
  const { legacyApiKeyEnabled, signetEnabled } = options.env;
  return {
    legacyApiKeyEnabled:
      legacyApiKeyEnabled !== undefined &&
      configService.get<string>(legacyApiKeyEnabled, 'true') === 'true',
    signetEnabled:
      signetEnabled === undefined ||
      configService.get<string>(signetEnabled, 'false') === 'true',
  };
}

// The clock tolerance, re-checked here rather than trusted. `Number('')` and
// `Number('none')` differ: the
// first is 0, the second is NaN, and jose compares `exp` as
// `exp <= now - clockTolerance`, which is false for every token once the
// tolerance is NaN. A token would then never expire, silently. Nothing in the
// type system says a ConfigService was built through validation, and this
// function takes one from anywhere.
function readClockTolerance(
  options: SignetEnvOptions,
  configService: ConfigService,
): number {
  const raw = configService.get<string | number>(
    options.env.jwtClockToleranceS,
    60,
  );
  const seconds =
    typeof raw === 'string' && raw.trim() === '' ? Number.NaN : Number(raw);
  if (!Number.isInteger(seconds) || seconds < 0 || seconds > 300) {
    throw new Error(
      `${options.env.jwtClockToleranceS} must be an integer between 0 and 300`,
    );
  }
  return seconds;
}

// Reads the channel flags and the verifier settings. The consumer's config
// validation is the gate for the issuer and the JWKS URI: this never fills a
// default for either, so an enabled channel with missing settings must have
// failed at boot -- and throws here if it did not.
export function readSignetAuthConfig(
  options: SignetEnvOptions,
  configService: ConfigService,
  profile: DeploymentProfile,
): SignetAuthConfig {
  const { legacyApiKeyEnabled, signetEnabled } = readChannelFlags(
    options,
    configService,
  );
  if (!signetEnabled) {
    return { jwt: null, legacyApiKeyEnabled, signetEnabled };
  }
  const issuer = configService.getOrThrow<string>(options.env.jwtIssuer);
  const jwksUri = configService.getOrThrow<string>(options.env.jwtJwksUri);
  const clockToleranceS = readClockTolerance(options, configService);
  return {
    jwt: {
      audience: profile.canonicalResource,
      clockToleranceS,
      issuer,
      jwksUri,
    },
    legacyApiKeyEnabled,
    signetEnabled,
  };
}
