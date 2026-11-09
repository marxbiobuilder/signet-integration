import {
  type ExecutionContext,
  Inject,
  Injectable,
  Logger,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';

import { SignetDecision } from './decision';
import { type VerifiedSignetIdentity } from './jwt-verifier';
import {
  SIGNET_INTEGRATION_OPTIONS,
  type SignetIntegrationOptions,
} from './options';
import {
  ownConstructorParametersRequired,
  SignetPassportGuard,
} from './passport-guard';
import {
  SIGNET_PRINCIPAL_RESOLVER,
  type SignetPrincipalResolver,
} from './principal-resolver';

// The Bearer channel's guard for the module-wired resolver: SignetJwtStrategy
// leaves the verified identity on request.user, the resolver bound to
// SIGNET_PRINCIPAL_RESOLVER turns it into the consumer's principal, and the
// principal goes under options.requestPrincipalKey (which may also be `user`,
// in which case the identity is overwritten by the principal). The
// classification of the resolver's outcome is SignetDecision's.
@Injectable()
@ownConstructorParametersRequired()
export class SignetBearerGuard extends SignetPassportGuard {
  // The subclass's name when a consumer subclasses this guard, so its log
  // `context` keeps the name the consumer's operators filter on.
  private readonly logger = new Logger(this.constructor.name);

  constructor(
    @Inject(SIGNET_PRINCIPAL_RESOLVER)
    private readonly resolver: SignetPrincipalResolver,
    private readonly decision: SignetDecision,
    // `signetOptions` leaves `options` to AuthGuard. That mixin property-injects
    // Passport's AuthModuleOptions there when PassportModule is registered;
    // a parameter property of the same name is overwritten with it.
    @Inject(SIGNET_INTEGRATION_OPTIONS)
    private readonly signetOptions: SignetIntegrationOptions,
    reflector: Reflector,
  ) {
    super(reflector);
  }

  override async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = await this.authenticate<VerifiedSignetIdentity>(context);
    if (request === 'public') return true;
    await this.decision.decide(request.user, this.resolver, {
      attach: (principal) => {
        request[this.signetOptions.requestPrincipalKey] = principal;
      },
      logger: this.logger,
      source: request.ip,
    });
    return true;
  }
}
