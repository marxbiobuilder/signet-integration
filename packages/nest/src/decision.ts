import {
  ForbiddenException,
  HttpException,
  Inject,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';

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
  type SignetPrincipalResolver,
} from './principal-resolver';

// The decision line's own keys. A resolver's `logFields` may not reuse them:
// a second `metric=` or `clientId=` on one line is whichever copy the log
// parser keeps, and operators alert on these.
const RESERVED_LOG_KEYS: ReadonlySet<string> = new Set([
  'metric',
  'reason',
  'clientId',
  'environment',
]);

export interface DecisionContext<P> {
  // Runs with the principal BEFORE the authorized line is written, so an
  // attachment that throws leaves no "authorized" record behind. The Bearer
  // guard attaches under options.requestPrincipalKey here; a strategy that
  // returns the principal to Passport needs nothing.
  readonly attach?: (principal: P) => void;
  // The logger the decision lines go through. A guard or strategy passes its
  // own so the line's `context` keeps the name its operators filter on.
  readonly logger?: Logger;
  // The caller's address, for the scope-missing line.
  readonly source?: string;
}

// The layer between a verified identity and a request that may proceed: the
// admission scope, the consumer's resolver, and the one rendering of the
// outcome as an HTTP status and a log line. Both the package's Bearer guard
// and a consumer's own Passport strategy go through here, so the
// classification cannot drift between them:
//
//   token lacks the admission scope         → 403 (service scope), with an
//                                             insufficient_scope challenge
//   resolver says { ok: false }             → 403, bare
//   resolver throws PrincipalStoreUnavailableError → 503, fail closed
//   resolver throws an HttpException        → its own status
//   resolver throws anything else           → 500, the error under its own name
//   resolver logFields reuses a fixed key   → 500, resolver_contract_error
//
// None of these are 401: the token was valid. The 403 messages distinguish
// "get a token with the right scope" from "ask an administrator" without
// naming what the caller does not hold. The 500 is deliberately NOT a 503:
// a bug in the resolver must not send the operator to check the database.
//
// The resolver is a parameter, not something the caller runs first: a
// consumer that wrapped its own call in try/catch could turn a store outage
// into a 401, which is the silent failure this layer exists to prevent.
@Injectable()
export class SignetDecision {
  private readonly logger = new Logger(SignetDecision.name);

  constructor(
    @Inject(SIGNET_INTEGRATION_OPTIONS)
    private readonly options: SignetIntegrationOptions,
    private readonly profiles: SignetDeploymentProfileService,
  ) {}

  async decide<P>(
    identity: VerifiedSignetIdentity,
    resolver: SignetPrincipalResolver<P>,
    context: DecisionContext<P> = {},
  ): Promise<P> {
    const logger = context.logger ?? this.logger;
    const { admissionScope } = this.options;
    if (!identity.scopes.includes(admissionScope)) {
      logger.warn(
        `signet token lacks service scope: metric=signet_scope_missing source=${sanitiseLogToken(context.source ?? 'none')}`,
      );
      // A 403 a client CAN fix by re-authorising (RFC 6750 §3.1); the
      // resolver's refusals below stay bare, because a wider OAuth scope
      // would not supply a missing local authorization.
      throw new InsufficientScopeException(admissionScope);
    }

    const environment = this.profiles.profile.environment;
    let resolution: PrincipalResolution<P>;
    try {
      resolution = await resolver.resolve(identity);
    } catch (error) {
      // An HttpException is a decision already taken below us; it is neither
      // the store nor a bug, and it must reach the caller with its own status.
      if (error instanceof HttpException) throw error;
      if (error instanceof PrincipalStoreUnavailableError) {
        // The line names what actually failed (the cause's class), not the
        // wrapper; the driver's message travels in the stack, never on the
        // key=value line.
        logFailure(
          logger,
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
      logFailure(
        logger,
        'authorization load failed',
        'auth_store_error',
        errorName,
        stack,
      );
      throw error;
    }
    if (!resolution.ok) {
      // The reason is logged for the operator and NOT returned.
      logDecision(
        logger,
        'refused',
        identity.clientId,
        environment,
        resolution,
      );
      throw new ForbiddenException(
        this.options.principalRefusalMessage ??
          'this identity holds no authorization in this service',
      );
    }
    context.attach?.(resolution.principal);
    logDecision(
      logger,
      'authorized',
      identity.clientId,
      environment,
      resolution,
    );
    return resolution.principal;
  }
}

// The one rendering of the authorization DECISION: the line that lets a
// request through and the line that refuses one, so their field set and its
// order cannot drift apart -- metric, reason, the resolver's logFields in the
// order given, clientId, environment.
//
// What these lines disclose about the caller: the client id (software, not
// a person; a registration identifier, not a credential) and whatever the
// resolver chose to put in `logFields`. No `sub`, no issuer.
//
// Levels: a refusal is a `warn`, an authorization a `log` (info). One line
// per authorized request is the price of having any record of which client
// acted; it is paid deliberately, because the alternative is no record.
function logDecision(
  logger: Logger,
  outcome: 'authorized' | 'refused',
  clientId: string,
  environment: string,
  resolution: PrincipalResolution<unknown>,
): void {
  const consumerFields = Object.entries(resolution.logFields ?? {});
  for (const [key] of consumerFields) {
    if (RESERVED_LOG_KEYS.has(key)) {
      // A programming error in the resolver, not a decision: one alertable
      // line, then a 500 under its own name rather than a forged log line.
      logFailure(
        logger,
        'resolver logFields invalid',
        'resolver_contract_error',
        'Error',
      );
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
    logger.warn(
      `signet principal refused: metric=signet_principal_refused ${rendered}`,
    );
    return;
  }
  logger.log(
    `signet principal authorized: metric=signet_principal_authorized ${rendered}`,
  );
}

// The one rendering of the failure lines. Only the error's class name goes
// into the key=value line: the driver's message can carry the DSN or the
// SQL, so it travels in the stack as the SECOND argument, where a structured
// logger renders it after the filterable fields.
export function logFailure(
  logger: Logger,
  message: string,
  metric:
    | 'auth_store_error'
    | 'auth_store_unavailable'
    | 'resolver_contract_error'
    | 'signet_identity_missing',
  errorName: string,
  stack?: string,
): void {
  logger.error(
    `${message}: metric=${metric} errorName=${sanitiseLogToken(errorName)}`,
    stack,
  );
}
