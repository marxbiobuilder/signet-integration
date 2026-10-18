import { Inject, Injectable, Logger, type OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { type Request, type Response } from 'express';
import { Strategy } from 'passport-custom';

import { SignetDecision } from './decision';
import { SignetDeploymentProfileService } from './deployment-profile';
import { type VerifiedSignetIdentity } from './jwt-verifier';
import { type SignetLoginEntry, validateLoginEntryName } from './login-entry';
import { SignetLoginFlow } from './login-flow';
import {
  SIGNET_INTEGRATION_OPTIONS,
  type SignetIntegrationOptions,
} from './options';
import {
  type PrincipalResolution,
  type SignetPrincipalResolver,
} from './principal-resolver';

// The shape a SignetLoginStrategy(entry) subclass extends: the type the mixin
// returns, declared here so the declaration files name it. There is no
// runtime class by this name -- export it as a type only.
export declare abstract class SignetLoginStrategyBase<P>
  implements SignetPrincipalResolver<P>, OnModuleInit
{
  // Public rather than protected: the declared shape and the mixin's class
  // are different declarations, and TypeScript matches protected members by
  // declaration.
  readonly logger: Logger;
  abstract resolve(
    identity: VerifiedSignetIdentity,
  ): Promise<PrincipalResolution<P>>;
  // Writes the state cookie and returns the authorization URL; the handler
  // redirects to it. Throws SignetLoginError (DISABLED, DISCOVERY_FAILED).
  begin(response: Response): Promise<string>;
  onModuleInit(): void;
  validate(request: Request): Promise<P>;
}

// The login (authorization code + PKCE) strategy for one entry. Subclass it,
// implement `resolve` -- the same SignetPrincipalResolver contract the Bearer
// channel uses, so one resolver serves both -- and register the subclass as
// a provider next to SignetIntegrationModule.forPassport:
//
//   @Injectable()
//   class WebSignetLogin extends SignetLoginStrategy<User>(WEB_LOGIN) {
//     constructor(private readonly users: UsersService) { super(); }
//     async resolve(identity) { ... }
//   }
//
// A mixin because Passport takes the strategy's name when the class is
// built; the entry, and its redirect URIs, are fixed with it, so begin()
// and the callback cannot disagree about which entry they serve.
//
// Unlike the Bearer strategies, validate() THROWS: SignetLoginError with its
// reason before an identity is verified, SignetDecision's exceptions after.
// "Failure is false" exists so Passport can try the next strategy and so
// every refusal is one 401; a callback route has one strategy, and its UI
// must tell "you cancelled" from "try again". Guard the callback with
// AuthGuard(entry.name) and override handleRequest -- NOT with
// SignetPassportGuard, which folds every 401 into a bare one and would drop
// the reason.
export function SignetLoginStrategy<P>(
  entry: SignetLoginEntry,
): typeof SignetLoginStrategyBase<P> {
  validateLoginEntryName(entry.name);

  @Injectable()
  abstract class SignetLogin
    extends PassportStrategy(Strategy, entry.name)
    implements SignetPrincipalResolver<P>, OnModuleInit
  {
    readonly logger = new Logger(this.constructor.name);

    @Inject(ConfigService)
    private readonly configService!: ConfigService;
    @Inject(SignetDeploymentProfileService)
    private readonly profiles!: SignetDeploymentProfileService;
    @Inject(SIGNET_INTEGRATION_OPTIONS)
    private readonly options!: SignetIntegrationOptions;
    @Inject(SignetDecision)
    private readonly decision!: SignetDecision;
    private flow: SignetLoginFlow | undefined;

    abstract resolve(
      identity: VerifiedSignetIdentity,
    ): Promise<PrincipalResolution<P>>;

    // Property injection lands after construction, so the flow -- its
    // settings read, its env checked -- is built here.
    onModuleInit(): void {
      this.flow = new SignetLoginFlow(
        entry,
        this.configService,
        this.profiles,
        this.options,
        this.logger,
      );
    }

    begin(response: Response): Promise<string> {
      return this.ready().begin(response);
    }

    async validate(request: Request): Promise<P> {
      const identity = await this.ready().complete(request);
      return this.decision.decide(identity, this, {
        logger: this.logger,
        source: request.ip,
      });
    }

    private ready(): SignetLoginFlow {
      if (this.flow === undefined) {
        throw new Error(
          `${this.constructor.name}: onModuleInit has not run; register the strategy as a provider`,
        );
      }
      return this.flow;
    }
  }
  return SignetLogin;
}
