import { Inject, Injectable, Logger, type OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { type Request } from 'express';
import { Strategy } from 'passport-custom';

import { SignetDecision } from './decision';
import { SignetDeploymentProfileService } from './deployment-profile';
import { type VerifiedSignetIdentity } from './jwt-verifier';
import {
  SIGNET_INTEGRATION_OPTIONS,
  type SignetIntegrationOptions,
} from './options';
import {
  type PrincipalResolution,
  type SignetPrincipalResolver,
} from './principal-resolver';
import { SIGNET_JWT_STRATEGY, SignetBearerVerification } from './strategy';

// The Passport-native shape: a strategy whose validate() ends with the
// consumer's principal, which Passport then leaves on request.user. Subclass
// it and implement `resolve` -- Passport's verify callback, with the
// identity already proven -- and register the subclass as a provider; the
// package's dependencies are property-injected, so the subclass's
// constructor is its own.
//
//   @Injectable()
//   class MyStrategy extends SignetPrincipalStrategy<User> {
//     constructor(private readonly users: UsersService) { super(); }
//     async resolve(identity) { ... }   // see SignetPrincipalResolver
//   }
//
// Verification and the outcome's classification are the same code
// SignetBearerGuard runs (SignetBearerVerification, SignetDecision), so a
// consumer on this path gets the same 401/403/503/500 contract and the same
// decision log line, written under the subclass's name. Guard it with
// SignetPassportGuard, or any AuthGuard(SIGNET_JWT_STRATEGY).
@Injectable()
export abstract class SignetPrincipalStrategy<P>
  extends PassportStrategy(Strategy, SIGNET_JWT_STRATEGY)
  implements SignetPrincipalResolver<P>, OnModuleInit
{
  protected readonly logger = new Logger(this.constructor.name);

  @Inject(ConfigService)
  private readonly configService!: ConfigService;
  @Inject(SignetDeploymentProfileService)
  private readonly profiles!: SignetDeploymentProfileService;
  @Inject(SIGNET_INTEGRATION_OPTIONS)
  private readonly options!: SignetIntegrationOptions;
  @Inject(SignetDecision)
  private readonly decision!: SignetDecision;
  private verification: SignetBearerVerification | undefined;

  abstract resolve(
    identity: VerifiedSignetIdentity,
  ): Promise<PrincipalResolution<P>>;

  // Property injection lands after construction, so the verifier (and its
  // startup line) is built here rather than in the constructor.
  onModuleInit(): void {
    this.verification = new SignetBearerVerification(
      this.configService,
      this.profiles,
      this.options,
      this.logger,
    );
  }

  async validate(request: Request): Promise<P | false> {
    if (this.verification === undefined) {
      throw new Error(
        `${this.constructor.name}: onModuleInit has not run; register the strategy as a provider`,
      );
    }
    const identity = await this.verification.verify(request);
    if (identity === false) return false;
    return this.decision.decide(identity, this, {
      logger: this.logger,
      source: request.ip,
    });
  }
}
