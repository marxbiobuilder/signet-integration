import { type VerifiedSignetIdentity } from './jwt-verifier';

// The consumer's half of authentication: turning a verified identity into
// whatever the consumer calls a principal. Signet is an auth PROVIDER here --
// it proves `(iss, sub)` and hands over the claims; who that is locally, and
// how that mapping is stored, is the consumer's business. The shape is
// Passport's verify callback.
//
//   { ok: true, principal }   → attached under options.requestPrincipalKey
//   { ok: false, reason }     → 403; `reason` is logged for the operator and
//                               NOT returned (which of several reasons applied
//                               is an oracle about the consumer's store)
//   throw PrincipalStoreUnavailableError → 503, fail closed
//   throw anything else        → 500 under its own name; a bug is not dressed
//                               up as an authentication or availability failure
//   throw an HttpException     → passed through with its own status
export interface SignetPrincipalResolver<P = unknown> {
  resolve(identity: VerifiedSignetIdentity): Promise<PrincipalResolution<P>>;
}

// `logFields` are consumer identifiers the guard renders on its decision
// line between `reason` and `clientId`, in the order given (a local principal
// id, a binding id, ...). Values only; never anything derived from the token.
// A refusal supplies the same keys with `none`, so the two lines of a pair
// keep one field set.
export type PrincipalResolution<P> =
  | { logFields?: Readonly<Record<string, string>>; ok: false; reason: string }
  | { logFields?: Readonly<Record<string, string>>; ok: true; principal: P };

export const SIGNET_PRINCIPAL_RESOLVER = Symbol('SIGNET_PRINCIPAL_RESOLVER');

// Thrown by a resolver when its STORE could not be reached, as opposed to when
// it answered. Which errors mean "unreachable" is the resolver's knowledge:
// a socket error, a DNS failure, a driver exception are facts about HOW its
// store is queried, and this package carries no driver import.
//
// `causeName` and `causeStack` are captured at construction, in the same form
// the guard's 500 branch uses for an unwrapped error, so the 503 log line
// reads the cause's class and stack.
export class PrincipalStoreUnavailableError extends Error {
  readonly causeName: string;
  readonly causeStack: string | undefined;

  constructor(cause: unknown) {
    super('authorization store unavailable', { cause });
    this.name = 'PrincipalStoreUnavailableError';
    this.causeName =
      cause instanceof Error && cause.name ? cause.name : typeof cause;
    this.causeStack = cause instanceof Error ? cause.stack : undefined;
  }
}
