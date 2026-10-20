import { UnauthorizedException } from '@nestjs/common';

// Why a login did not reach a verified identity. Each is something the
// consumer's UI says differently ("you cancelled" is not "try again"), which
// is why the login path throws with a reason where the Bearer path answers
// one indistinguishable 401 (see SignetLoginStrategy).
//
//   DISABLED                     the Signet channel's flag is off
//   CANCELLED                    the user declined at the IdP (access_denied)
//   IDP_ERROR                    the IdP answered with any other error, or
//                                with neither a code nor an error
//                                (both only once the state checked out)
//   STATE_INVALID                no state cookie, one not sealed under this
//                                stateSecret, expired, for another
//                                entry, or a state that does not match the
//                                query's -- checked before the IdP's answer
//                                is read, error responses included
//   DISCOVERY_FAILED             the issuer's metadata could not be fetched
//                                or did not pass its checks
//   TOKEN_EXCHANGE_FAILED        the token endpoint refused, failed or did
//                                not answer in time, or returned no token
//   TOKEN_REJECTED               the access token failed verification or
//                                was issued to another client; or the ID
//                                token was missing, failed verification, or
//                                names another `sub`
//   ADMISSION_SCOPE_NOT_GRANTED  the token is valid but lacks the admission
//                                scope: the user unticked it at consent, or
//                                the client's policy does not allow it
//
// What happens after a verified identity -- the resolver's refusal, a store
// outage, a resolver bug -- is SignetDecision's, with its own exceptions. A
// defect in this package's own code is neither: it propagates as a 500.
export const SignetLoginFailureEnum = {
  ADMISSION_SCOPE_NOT_GRANTED: 'admission_scope_not_granted',
  CANCELLED: 'cancelled',
  DISABLED: 'disabled',
  DISCOVERY_FAILED: 'discovery_failed',
  IDP_ERROR: 'idp_error',
  STATE_INVALID: 'state_invalid',
  TOKEN_EXCHANGE_FAILED: 'token_exchange_failed',
  TOKEN_REJECTED: 'token_rejected',
} as const;
export type SignetLoginFailure =
  (typeof SignetLoginFailureEnum)[keyof typeof SignetLoginFailureEnum];

// The body stays bare: the reason is for the consumer's callback guard to
// map onto its own UI, not for a response it forgot to handle.
// BearerChallengeFilter writes no `WWW-Authenticate` for it -- a browser
// login is not a Bearer request.
export class SignetLoginError extends UnauthorizedException {
  constructor(readonly reason: SignetLoginFailure) {
    super();
    this.name = 'SignetLoginError';
  }
}
