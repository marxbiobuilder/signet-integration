import { Inject, Injectable, Logger, type OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { type Request, type Response } from 'express';
import { Strategy } from 'passport-custom';

import { SignetDecision } from './decision';
import { SignetDeploymentProfileService } from './deployment-profile';
import { type VerifiedSignetIdentity } from './jwt-verifier';
import { type SignetLoginEntry, validateLoginEntry } from './login-entry';
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
  // Builds the flow and checks the entry and the login variables at boot.
  // A subclass that overrides it should call super.onModuleInit(); one that
  // does not still works, with those checks moved to the first login.
  onModuleInit(): void;
  validate(request: Request): Promise<P>;
}

// The login (authorization code + PKCE) strategy for one entry. Subclass it,
// implement `resolve` -- the SignetPrincipalResolver contract the Bearer
// channel uses too, so a resolver service injected into both strategies can
// serve both, each delegating `resolve` to it -- and register the subclass
// as a provider next to SignetIntegrationModule.forPassport:
//
//   @Injectable()
//   class WebSignetLogin extends SignetLoginStrategy<User>(WEB_LOGIN) {
//     constructor(private readonly users: UsersService) { super(); }
//     async resolve(identity) { ... }
//   }
//
// Name the principal type: `P` appears only in what the mixin returns, so
// TypeScript cannot infer it, and a bare SignetLoginStrategy(WEB_LOGIN) makes
// it `unknown`.
//
// A mixin because Passport takes the strategy's name when the class is
// built; the entry, and its redirect URIs, are fixed with it (a frozen copy),
// so begin() and the callback cannot disagree about which entry they serve.
//
// Unlike the Bearer strategies, validate() THROWS: SignetLoginError with its
// reason before an identity is verified, SignetDecision's exceptions after.
// "Failure is false" exists so Passport can try the next strategy and so
// every refusal is one 401; a callback route has one strategy, and its UI
// must tell "you cancelled" from "try again". Guard the callback with
// AuthGuard(entry.name) and override handleRequest. SignetPassportGuard and
// SignetBearerGuard run the Bearer strategy, not this one; mounted as an
// APP_GUARD they must let both login routes through with @Public().
export function SignetLoginStrategy<P>(
  entry: SignetLoginEntry,
): typeof SignetLoginStrategyBase<P> {
  const frozen = validateLoginEntry(entry);

  @Injectable()
  abstract class SignetLogin
    extends PassportStrategy(Strategy, frozen.name)
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
    // settings read, its env checked -- is built here, at boot.
    onModuleInit(): void {
      this.flow = this.build();
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

    // Lazily as well: a subclass that overrides onModuleInit without calling
    // super still gets a working flow, its checks at the first login instead
    // of at boot.
    private ready(): SignetLoginFlow {
      this.flow ??= this.build();
      return this.flow;
    }

    private build(): SignetLoginFlow {
      // Undefined only when Nest never injected them: the subclass was
      // constructed by hand, or is not a provider of a module that imports
      // SignetIntegrationModule.forPassport.
      if (
        this.configService === undefined ||
        this.profiles === undefined ||
        this.options === undefined ||
        this.decision === undefined
      ) {
        throw new Error(
          `${this.constructor.name}: its dependencies were not injected; register it as a provider in a module that imports SignetIntegrationModule.forPassport`,
        );
      }
      return new SignetLoginFlow(
        frozen,
        this.configService,
        this.profiles,
        this.options,
        this.logger,
      );
    }
  }
  return SignetLogin;
}
