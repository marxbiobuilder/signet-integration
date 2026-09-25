import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { type Request } from 'express';
import { Strategy } from 'passport-custom';

import { readSignetAuthConfig } from './config';
import { SignetDeploymentProfileService } from './deployment-profile';
import { JwtVerifier, type VerifiedSignetIdentity } from './jwt-verifier';
import { REFUSAL_ROUTE_MAX, sanitiseLogToken, truncate } from './log-sanitise';
import {
  SIGNET_INTEGRATION_OPTIONS,
  type SignetIntegrationOptions,
} from './options';

export const SIGNET_JWT_STRATEGY = 'signet-jwt';

// What a Signet strategy does before anything consumer-specific: read the
// channel's settings once, build the verifier once (the remote JWKS cache
// lives on it), and turn a request into a verified identity or a logged
// `false`. SignetJwtStrategy and SignetPrincipalStrategy both hold one.
//
// Failure is `false`, never a throw. Passport moves to the next strategy only
// on fail(); error() short-circuits the chain, and Nest turns a thrown
// validate() into error(). A throw would also replace the guard's uniform 401
// with whatever the exception said.
//
// The log line carries the reason and the source address and NOTHING derived
// from the token: no fingerprint, no sub.
export class SignetBearerVerification {
  private readonly verifier: JwtVerifier | null;

  constructor(
    configService: ConfigService,
    profiles: SignetDeploymentProfileService,
    options: SignetIntegrationOptions,
    private readonly logger: Logger,
  ) {
    const config = readSignetAuthConfig(
      options,
      configService,
      profiles.profile,
    );
    if (config.signetEnabled) {
      this.verifier = new JwtVerifier(config.jwt);
      this.logger.log(
        `signet jwt verification loaded: iss=${config.jwt.issuer} aud=${config.jwt.audience}`,
      );
    } else {
      this.verifier = null;
    }
  }

  async verify(request: Request): Promise<VerifiedSignetIdentity | false> {
    if (this.verifier === null) return this.reject(request, 'signet_disabled');
    const token = bearerToken(request);
    if (token === undefined) {
      const present = typeof request.headers.authorization === 'string';
      return this.reject(
        request,
        present ? 'header_malformed' : 'header_missing',
      );
    }
    const result = await this.verifier.verify(token);
    if (!result.ok) return this.reject(request, result.reason);
    return result.identity;
  }

  // Every false path goes through here, so there is no unlogged rejection.
  private reject(request: Request, reason: string): false {
    this.logger.warn(
      `signet auth rejected: metric=signet_auth_rejected reason=${sanitiseLogToken(reason)} source=${sanitiseLogToken(request.ip ?? 'none')} method=${sanitiseLogToken(request.method)} route=${sanitiseLogToken(truncate(request.originalUrl, REFUSAL_ROUTE_MAX))}`,
    );
    return false;
  }
}

// The strategy behind SignetBearerGuard: validate() is verification alone,
// and the verified identity is what Passport leaves on request.user. The
// guard then runs the module-wired resolver.
//
// passport-custom rather than passport-jwt: passport-jwt is a second JWT
// implementation (jsonwebtoken) with its own JWKS story, and two verifiers
// means two places to get the algorithm allowlist right. Only Passport's
// registration and dispatch are borrowed; the cryptography stays in one place.
@Injectable()
export class SignetJwtStrategy extends PassportStrategy(
  Strategy,
  SIGNET_JWT_STRATEGY,
) {
  private readonly verification: SignetBearerVerification;

  constructor(
    configService: ConfigService,
    profiles: SignetDeploymentProfileService,
    @Inject(SIGNET_INTEGRATION_OPTIONS) options: SignetIntegrationOptions,
  ) {
    super();
    this.verification = new SignetBearerVerification(
      configService,
      profiles,
      options,
      new Logger(SignetJwtStrategy.name),
    );
  }

  validate(request: Request): Promise<VerifiedSignetIdentity | false> {
    return this.verification.verify(request);
  }
}

// `authorization` is `string | undefined` on IncomingHttpHeaders -- Node
// discards duplicates of this header, so a dispatcher that must refuse
// repeats counts them on rawHeaders instead. Scheme matching is
// case-insensitive per RFC 7235; the token is taken verbatim.
export function bearerToken(request: Request): string | undefined {
  return /^Bearer +(\S+)$/i.exec(
    request.headers.authorization?.trim() ?? '',
  )?.[1];
}
