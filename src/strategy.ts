import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { type Request } from 'express';
import { Strategy } from 'passport-custom';

import { readSignetAuthConfig } from './config';
import { SignetDeploymentProfileService } from './deployment-profile';
import {
  JwtVerifier,
  type VerifiedSignetIdentity,
  type VerifyResult,
} from './jwt-verifier';
import { REFUSAL_ROUTE_MAX, sanitiseLogToken, truncate } from './log-sanitise';
import {
  SIGNET_INTEGRATION_OPTIONS,
  type SignetIntegrationOptions,
} from './options';

export const SIGNET_JWT_STRATEGY = 'signet-jwt';

// The rejection reasons this file produces, alongside the verifier's own
// (JwtRejectionEnum, jose's ERR_* codes). None is a JWT check: the channel is
// off, or the request carried no usable Bearer header.
export const SignetBearerRejectionEnum = {
  DISABLED: 'signet_disabled',
  HEADER_MALFORMED: 'header_malformed',
  HEADER_MISSING: 'header_missing',
} as const;
export type SignetBearerRejection =
  (typeof SignetBearerRejectionEnum)[keyof typeof SignetBearerRejectionEnum];

// What a Signet strategy does before anything consumer-specific: read the
// channel's settings once, build the verifier once (the remote JWKS cache
// lives on it), and verify. Two ways in:
//
//   verify(request)     a request's Bearer header → a verified identity or a
//                       LOGGED `false`
//   verifyToken(token)  a token from anywhere else → a VerifyResult, logged by
//                       no one but the caller
//
// SignetJwtStrategy and SignetPrincipalStrategy both hold one.
//
// A rejected credential is `false` / `{ ok: false }`, never a throw. Passport
// moves to the next strategy only on fail(); error() short-circuits the
// chain, and Nest turns a thrown validate() into error(). A throw would also
// replace the guard's uniform 401 with whatever the exception said. Only a
// defect in this process still throws (see JwtVerifier), so it surfaces as a
// 500 rather than as a bad token.
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

  // False when the channel's flag is off: a caller that must decide before
  // it has a token (a login flow, before exchanging a code) asks here.
  get enabled(): boolean {
    return this.verifier !== null;
  }

  async verify(request: Request): Promise<VerifiedSignetIdentity | false> {
    // Before the header, not left to verifyToken: with the channel off, a
    // request without a header is signet_disabled, not header_missing.
    if (this.verifier === null) {
      return this.reject(request, SignetBearerRejectionEnum.DISABLED);
    }
    const token = bearerToken(request);
    if (token === undefined) {
      const present = typeof request.headers.authorization === 'string';
      return this.reject(
        request,
        present
          ? SignetBearerRejectionEnum.HEADER_MALFORMED
          : SignetBearerRejectionEnum.HEADER_MISSING,
      );
    }
    const result = await this.verifyToken(token);
    if (!result.ok) return this.reject(request, result.reason);
    return result.identity;
  }

  // The verification step itself, shared with verify(); called directly for
  // a token that did not arrive in a header -- one a login flow received
  // from the token endpoint. It writes NO line, so a direct caller owes
  // three things:
  //
  //   - log every { ok: false }, signet_disabled included, under its own
  //     metric and with whatever request context it has;
  //   - sanitise `reason` before it reaches a key=value line, as reject()
  //     does: it is open (jose's ERR_* codes, Node's errno strings verbatim);
  //   - let a throw propagate: it is a defect in this process, not a bad
  //     token, and must become a 500.
  async verifyToken(token: string): Promise<VerifyResult> {
    if (this.verifier === null) {
      return { ok: false, reason: SignetBearerRejectionEnum.DISABLED };
    }
    return this.verifier.verify(token);
  }

  // Every false that verify() returns goes through here, so the header path
  // has no unlogged rejection. verifyToken() bypasses it by design.
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
