import {
  type ExecutionContext,
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { type Request } from 'express';

import { logFailure } from './decision';
import { IS_PUBLIC_ROUTE } from './public.decorator';
import { SIGNET_JWT_STRATEGY } from './strategy';

// Nest's OPTIONAL_DEPS_METADATA. `@nestjs/common` does not re-export it.
const OPTIONAL_PARAMTYPES = 'optional:paramtypes';

// AuthGuard's mixin marks its constructor parameter 0 `@Optional()`.
// `Reflect.getMetadata` walks the constructor prototype chain, so a subclass
// that never writes its own list treats ITS parameter 0 as optional.
// `@Optional()` on a later parameter copies that inherited list onto this
// constructor before appending its own index. Parameter decorators run
// before this one, so the copy is already own metadata by the time this
// drops index 0 (and writes a list when absent).
export function ownConstructorParametersRequired(): ClassDecorator {
  return (target) => {
    const own: unknown = Reflect.getOwnMetadata(OPTIONAL_PARAMTYPES, target);
    const optionalIndexes = Array.isArray(own)
      ? own.filter((index) => index !== 0)
      : [];
    Reflect.defineMetadata(OPTIONAL_PARAMTYPES, optionalIndexes, target);
  };
}

// The request after Passport ran the strategy: `user` is whatever the
// strategy's validate() returned -- the verified identity for
// SignetJwtStrategy, the consumer's principal for a SignetPrincipalStrategy.
// Express types `user` for Passport's augmentation; here it is the caller's
// own type.
export type AuthenticatedRequest<U = unknown> = Omit<Request, 'user'> & {
  user: U;
  [key: string]: unknown;
};

// Passport's AuthGuard for the Signet strategy plus the two things every
// consumer of it needs: a route marked `@Public()` (on the handler or its
// class) is let through without running the strategy, so this can be an
// APP_GUARD on its own; and a strategy refusal is ONE indistinguishable 401,
// whatever Passport's own exception said.
//
// This is the whole guard for a consumer whose strategy already resolves the
// principal (SignetPrincipalStrategy): Passport has put it on request.user.
// SignetBearerGuard extends it for the module-wired resolver.
@Injectable()
@ownConstructorParametersRequired()
export class SignetPassportGuard extends AuthGuard(SIGNET_JWT_STRATEGY) {
  private readonly passportLogger = new Logger(this.constructor.name);

  constructor(private readonly reflector: Reflector) {
    super();
  }

  override async canActivate(context: ExecutionContext): Promise<boolean> {
    await this.authenticate(context);
    return true;
  }

  // 'public' when the route opted out; otherwise the request with Passport's
  // user attached. A consumer with a credential dispatcher of its own decides
  // `@Public()` there and never hands a public route to this guard.
  protected async authenticate<U = unknown>(
    context: ExecutionContext,
  ): Promise<AuthenticatedRequest<U> | 'public'> {
    if (
      this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_ROUTE, [
        context.getHandler(),
        context.getClass(),
      ]) === true
    ) {
      return 'public';
    }
    // Typed unknown: the base declares boolean | Promise<boolean> |
    // Observable<boolean>, and anything other than a literal true is treated
    // as "did not pass".
    let passed: unknown;
    try {
      passed = await super.canActivate(context);
    } catch (error) {
      // Passport's own UnauthorizedException carries a message; the contract
      // is one indistinguishable 401. Anything else is a programming error
      // and must not be dressed up as an authentication failure.
      if (error instanceof UnauthorizedException) {
        throw new UnauthorizedException();
      }
      throw error;
    }
    const request = context
      .switchToHttp()
      .getRequest<AuthenticatedRequest<U | undefined>>();
    if (passed !== true || request.user === undefined) {
      logFailure(
        this.passportLogger,
        'signet strategy did not pass cleanly',
        'signet_identity_missing',
        'none',
      );
      throw new InternalServerErrorException(
        'signet strategy did not pass cleanly',
      );
    }
    return request as AuthenticatedRequest<U>;
  }
}
