import {
  type ExecutionContext,
  ForbiddenException,
  HttpException,
  Inject,
  Injectable,
  InternalServerErrorException,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { type Request } from 'express';

import { InsufficientScopeException } from './bearer-challenge';
import { SignetDeploymentProfileService } from './deployment-profile';
import { type VerifiedSignetIdentity } from './jwt-verifier';
import { sanitiseLogToken } from './log-sanitise';
import {
  SIGNET_INTEGRATION_OPTIONS,
  type SignetIntegrationOptions,
} from './options';
import {
  type PrincipalResolution,
  PrincipalStoreUnavailableError,
  SIGNET_PRINCIPAL_RESOLVER,
  type SignetPrincipalResolver,
} from './principal-resolver';
import { IS_PUBLIC_ROUTE } from './public.decorator';
import { SIGNET_JWT_STRATEGY } from './strategy';

// The decision line's own keys. A resolver's `logFields` may not reuse them:
// a second `metric=` or `clientId=` on one line is whichever copy the log
// parser keeps, and operators alert on these.
const RESERVED_LOG_KEYS: ReadonlySet<string> = new Set([
  'metric',
  'reason',
  'clientId',
  'environment',
]);

// Nest's OPTIONAL_DEPS_METADATA. `@nestjs/common` does not re-export it.
const OPTIONAL_PARAMTYPES = 'optional:paramtypes';

// AuthGuard's mixin marks its constructor parameter 0 `@Optional()`.
// `Reflect.getMetadata` walks the constructor prototype chain, so a subclass
// that never writes its own list treats ITS parameter 0 — the principal
// resolver — as optional. `@Optional()` on a later parameter copies that
// inherited list onto this constructor before appending its own index.
// Parameter decorators run before this one, so the copy is already own
// metadata by the time this drops index 0 (and writes a list when absent).
function requirePrincipalResolver(): ClassDecorator {
  return (target) => {
    const own: unknown = Reflect.getOwnMetadata(OPTIONAL_PARAMTYPES, target);
    const optionalIndexes = Array.isArray(own)
      ? own.filter((index) => index !== 0)
      : [];
    Reflect.defineMetadata(OPTIONAL_PARAMTYPES, optionalIndexes, target);
  };
}

// The request after Passport ran the strategy: `user` is the verified
// identity; the principal goes under options.requestPrincipalKey (which may
// also be `user`, in which case the identity is overwritten by the principal).
interface SignetRequest extends Request {
  user?: VerifiedSignetIdentity;
  [key: string]: unknown;
}

// The Bearer channel's guard: Passport dispatches SignetJwtStrategy, and a
// false from it is a uniform 401. A route marked `@Public()` (on the handler
// or its class) is let through first, so the guard can be an APP_GUARD on
// its own; a consumer with a credential dispatcher of its own decides
// `@Public()` there and never hands a public route to this guard. What
// follows is the layer on top:
//
//   token lacks the admission scope         → 403 (service scope), with an
//                                             insufficient_scope challenge
//   resolver says { ok: false }             → 403, bare
//   resolver throws PrincipalStoreUnavailableError → 503, fail closed
//   resolver throws an HttpException        → its own status
//   resolver throws anything else           → 500, the error under its own name
//   Passport passed but attached no user    → 500, programming error
//
// None of these are 401: the token was valid. The 403 messages distinguish
// "get a token with the right scope" from "ask an administrator" without
// naming what the caller does not hold. The 500 is deliberately NOT a 503:
// a bug in the resolver must not send the operator to check the database.
@Injectable()
@requirePrincipalResolver()
export class SignetBearerGuard extends AuthGuard(SIGNET_JWT_STRATEGY) {
  // The subclass's name when a consumer subclasses this guard, so its log
  // `context` keeps the name the consumer's operators filter on.
  private readonly logger = new Logger(this.constructor.name);

  constructor(
    @Inject(SIGNET_PRINCIPAL_RESOLVER)
    private readonly resolver: SignetPrincipalResolver,
    private readonly profiles: SignetDeploymentProfileService,
    // `signetOptions` leaves `options` to AuthGuard. That mixin property-injects
    // Passport's AuthModuleOptions there when PassportModule is registered;
    // a parameter property of the same name is overwritten with it.
    @Inject(SIGNET_INTEGRATION_OPTIONS)
    private readonly signetOptions: SignetIntegrationOptions,
    private readonly reflector: Reflector,
  ) {
    super();
  }

  override async canActivate(context: ExecutionContext): Promise<boolean> {
    if (
      this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_ROUTE, [
        context.getHandler(),
        context.getClass(),
      ]) === true
    ) {
      return true;
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
    const request = context.switchToHttp().getRequest<SignetRequest>();
    const identity = request.user;
    if (passed !== true || identity === undefined) {
      this.logFailure(
        'signet strategy did not pass cleanly',
        'signet_identity_missing',
        'none',
      );
      throw new InternalServerErrorException(
        'signet strategy did not pass cleanly',
      );
    }

    const { admissionScope } = this.signetOptions;
    if (!identity.scopes.includes(admissionScope)) {
      this.logger.warn(
        `signet token lacks service scope: metric=signet_scope_missing source=${sanitiseLogToken(request.ip ?? 'none')}`,
      );
      // A 403 a client CAN fix by re-authorising (RFC 6750 §3.1); the
      // resolver's refusals below stay bare, because a wider OAuth scope
      // would not supply a missing local authorization.
      throw new InsufficientScopeException(admissionScope);
    }

    const environment = this.profiles.profile.environment;
    let resolution: PrincipalResolution<unknown>;
    try {
      resolution = await this.resolver.resolve(identity);
    } catch (error) {
      // An HttpException is a decision already taken below us; it is neither
      // the store nor a bug, and it must reach the caller with its own status.
      if (error instanceof HttpException) throw error;
      if (error instanceof PrincipalStoreUnavailableError) {
        // The line names what actually failed (the cause's class), not the
        // wrapper; the driver's message travels in the stack, never on the
        // key=value line.
        this.logFailure(
          'authorization store unavailable',
          'auth_store_unavailable',
          error.causeName,
          error.causeStack,
        );
        throw new ServiceUnavailableException(
          'authorization store unavailable',
        );
      }
      const errorName =
        error instanceof Error && error.name ? error.name : typeof error;
      const stack = error instanceof Error ? error.stack : undefined;
      // A bug: rethrow unchanged so Nest answers 500 and the error keeps its
      // own name in the exception filter.
      this.logFailure(
        'authorization load failed',
        'auth_store_error',
        errorName,
        stack,
      );
      throw error;
    }
    if (!resolution.ok) {
      // The reason is logged for the operator and NOT returned.
      this.logDecision('refused', identity.clientId, environment, resolution);
      throw new ForbiddenException(
        this.signetOptions.principalRefusalMessage ??
          'this identity holds no authorization in this service',
      );
    }
    this.logDecision('authorized', identity.clientId, environment, resolution);
    request[this.signetOptions.requestPrincipalKey] = resolution.principal;
    return true;
  }

  // The one rendering of this guard's authorization DECISION: the line that
  // lets a request through and the line that refuses one, so their field set
  // and its order cannot drift apart -- metric, reason, the resolver's
  // logFields in the order given, clientId, environment.
  //
  // What these lines disclose about the caller: the client id (software, not
  // a person; a registration identifier, not a credential) and whatever the
  // resolver chose to put in `logFields`. No `sub`, no issuer.
  //
  // Levels: a refusal is a `warn`, an authorization a `log` (info). One line
  // per authorized request is the price of having any record of which client
  // acted; it is paid deliberately, because the alternative is no record.
  private logDecision(
    outcome: 'authorized' | 'refused',
    clientId: string,
    environment: string,
    resolution: PrincipalResolution<unknown>,
  ): void {
    const consumerFields = Object.entries(resolution.logFields ?? {});
    for (const [key] of consumerFields) {
      if (RESERVED_LOG_KEYS.has(key)) {
        // A programming error in the resolver, not a decision: surfaces as
        // a 500 under its own name rather than a forged log line.
        throw new Error(
          `resolver logFields must not use the reserved key ${key}`,
        );
      }
    }
    const pairs: [string, string][] = [
      ['reason', resolution.ok ? 'none' : resolution.reason],
      ...consumerFields,
      ['clientId', clientId],
      ['environment', environment],
    ];
    const rendered = pairs
      .map(
        ([key, value]) => `${sanitiseLogToken(key)}=${sanitiseLogToken(value)}`,
      )
      .join(' ');
    if (outcome === 'refused') {
      this.logger.warn(
        `signet principal refused: metric=signet_principal_refused ${rendered}`,
      );
      return;
    }
    this.logger.log(
      `signet principal authorized: metric=signet_principal_authorized ${rendered}`,
    );
  }

  // The one rendering of this guard's failure lines. Only the error's class
  // name goes into the key=value line: the driver's message can carry the
  // DSN or the SQL, so it travels in the stack as the SECOND argument, where
  // a structured logger renders it after the filterable fields.
  private logFailure(
    message: string,
    metric:
      'auth_store_error' | 'auth_store_unavailable' | 'signet_identity_missing',
    errorName: string,
    stack?: string,
  ): void {
    this.logger.error(
      `${message}: metric=${metric} errorName=${sanitiseLogToken(errorName)}`,
      stack,
    );
  }
}
