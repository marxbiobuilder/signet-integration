import { ForbiddenException, UnauthorizedException } from '@nestjs/common';

import { type ChannelFlags } from './config';
import { type DeploymentProfile } from './deployment-profile';
import { type SignetIntegrationOptions } from './options';

// RFC 9728 §3.1: for a resource identifier WITH a path, the well-known
// segment is inserted between host and path --
//   https://h/api/mcp → https://h/.well-known/oauth-protected-resource/api/mcp
// -- and for a bare origin it is appended at the root.
export function protectedResourceMetadataUrl(
  canonicalResource: string,
): string {
  const url = new URL(canonicalResource);
  if (url.search !== '' || url.hash !== '') {
    throw new Error(
      `canonical resource must not carry a query or fragment: ${canonicalResource}`,
    );
  }
  const path = url.pathname === '/' ? '' : url.pathname;
  return `${url.origin}/.well-known/oauth-protected-resource${path}`;
}

// The metadata path relative to the origin, taken from the same builder the
// challenge uses and read off the development profile. Assumes every
// profile's canonical resource carries the same path; the consumer pins that
// for its own table. The metadata controller mounts its route on it.
export function protectedResourceMetadataPath(
  options: SignetIntegrationOptions,
): string {
  return new URL(
    protectedResourceMetadataUrl(options.developmentProfile.canonicalResource),
  ).pathname;
}

// The request paths whose 401 may carry `resource_metadata`: the ones that
// ARE the canonical resource. With a resource that carries a path (an MCP
// endpoint URI), only that path qualifies -- any other path's 401 must not
// announce it. With a bare-origin resource the whole origin is the resource,
// so every request qualifies. Express serves the trailing-slash spelling too,
// so the two spellings reach the same decision.
export function isResourceRequest(
  profile: DeploymentProfile,
  requestPath: string,
): boolean {
  const resourcePath = new URL(profile.canonicalResource).pathname;
  if (resourcePath === '/') return true;
  const trim = (value: string) => value.replace(/\/+$/, '');
  return trim(requestPath) === trim(resourcePath);
}

// RFC 6750 §3 challenge for a 401. `scope` names the SERVICE scope the token
// must carry; a client that already holds it and is still refused has a
// local-authorization problem no re-authorisation solves, which is why the
// 403 for that case carries no challenge at all (see carriesScopeChallenge).
export function bearerChallenge(
  options: SignetIntegrationOptions,
  profile: DeploymentProfile,
  request: { resource: boolean },
): string {
  const parts = [`Bearer realm="${options.realm}"`];
  if (request.resource) {
    parts.push(
      `resource_metadata="${protectedResourceMetadataUrl(profile.canonicalResource)}"`,
    );
  }
  parts.push(`scope="${options.admissionScope}"`);
  return parts.join(', ');
}

// RFC 6750 §3.1 `insufficient_scope`: the token is valid but does not carry
// the scope the request needs. This IS solvable by re-authorising with the
// right scope, so it says so -- and the 403s that carry it are the only ones
// that do. `scopes` is what the caller must carry, not what it is missing.
export function insufficientScopeChallenge(
  options: SignetIntegrationOptions,
  scopes: readonly string[],
): string {
  return `Bearer realm="${options.realm}", error="insufficient_scope", scope="${scopes.join(' ')}"`;
}

// The field BearerChallengeFilter reads off a 403 to write an
// `insufficient_scope` challenge: the complete scope set the caller must
// re-authorise with. A field rather than a base class, because a consumer's
// per-action refusal usually has to stay in the consumer's own exception
// hierarchy (so its other code can catch it by that class). The filter is
// protocol code that knows RFC 6750 and nothing about the consumer's
// authorization, so it reads the field and never names a consumer class.
//
// Design Decision: a plain property name, not a Symbol-keyed field. Any
// ForbiddenException carrying a well-formed `requiredScopes` therefore earns
// the challenge, third-party ones included. A Symbol exported by this package
// would close accidental matches without a base class.
export interface ScopeChallengeCarrier {
  readonly requiredScopes: readonly string[];
}

// Checked for shape, not presence: a `requiredScopes` that is not a
// non-empty string array would render an unusable `scope=`. A plain
// authorization refusal carries no field at all. The filter logs the
// malformed case; this predicate only decides.
export function carriesScopeChallenge(
  exception: ForbiddenException,
): exception is ForbiddenException & ScopeChallengeCarrier {
  const { requiredScopes } = exception as Partial<ScopeChallengeCarrier>;
  return (
    Array.isArray(requiredScopes) &&
    requiredScopes.length > 0 &&
    requiredScopes.every((scope) => typeof scope === 'string')
  );
}

// A valid token without the admission scope. Takes the scope, not the
// options: the message and `requiredScopes` are both built from it here, so
// the guard cannot spell one without the other.
export class InsufficientScopeException
  extends ForbiddenException
  implements ScopeChallengeCarrier
{
  readonly requiredScopes: readonly string[];

  constructor(admissionScope: string) {
    super(`token does not carry the ${admissionScope} scope`);
    this.requiredScopes = [admissionScope];
  }
}

export type ChallengeDecision =
  | { header: null; malformedCarrier: boolean }
  | { header: string; malformedCarrier: false };

// The whole of the `WWW-Authenticate` decision, as a pure function, so a
// consumer with an exception filter of its own (a catch-all that renders its
// own bodies, guards streaming responses, ...) can make the same decision
// BearerChallengeFilter does and set the header itself.
//
//   Signet channel off            → no header: advertising a closed channel
//                                   sends clients to log in for nothing
//   403 carrying requiredScopes   → insufficient_scope (re-authorising fixes it)
//   403 with a malformed field    → no header, malformedCarrier: true (a bug
//                                   in a carrier; the caller should log it)
//   any other 403                 → no header: a wider OAuth scope supplies
//                                   no local authorization
//   401                           → Bearer challenge; resource_metadata only
//                                   when the request IS the resource
export function challengeFor(
  options: SignetIntegrationOptions,
  profile: DeploymentProfile,
  channels: ChannelFlags,
  exception: ForbiddenException | UnauthorizedException,
  requestPath: string,
): ChallengeDecision {
  if (!channels.signetEnabled) return { header: null, malformedCarrier: false };
  if (exception instanceof ForbiddenException) {
    if (carriesScopeChallenge(exception)) {
      return {
        header: insufficientScopeChallenge(options, exception.requiredScopes),
        malformedCarrier: false,
      };
    }
    return {
      header: null,
      malformedCarrier: 'requiredScopes' in exception,
    };
  }
  return {
    header: bearerChallenge(options, profile, {
      resource: isResourceRequest(profile, requestPath),
    }),
    malformedCarrier: false,
  };
}
