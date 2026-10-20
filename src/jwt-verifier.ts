import {
  createRemoteJWKSet,
  errors,
  type JWTPayload,
  jwtVerify,
  type RemoteJWKSetOptions,
} from 'jose';

import { type JwtSettings } from './config';

// Asymmetric signatures only. Allowing HS* opens alg confusion: an attacker
// signs with our PUBLIC key bytes as the HMAC secret, and a verifier that
// follows the header's alg accepts it. jose's JWKS path already refuses
// non-RS/PS/ES/Ed algorithms and only imports public keys, but the keys
// arrive from a remote endpoint rather than from configuration we read, so
// the explicit allowlist stays as the second, stated line.
const ASYMMETRIC_ALGORITHMS = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
];

// The remote JWKS options, spelled out rather than left to jose's defaults so
// the contract is fixed. A longer cooldownDuration only delays the refetch an
// unknown kid triggers after a rotation, and buys no failure backoff -- a
// failed fetch clears the pending fetch and the next request tries again
// regardless.
export const REMOTE_JWKS_OPTIONS = {
  cacheMaxAge: 600_000,
  cooldownDuration: 30_000,
  timeoutDuration: 3_000,
} as const satisfies RemoteJWKSetOptions;

// What a verified access token asserts about its bearer, and nothing more:
// no role, no local id. The Bearer guard hands this to the consumer's
// SignetPrincipalResolver, which turns it into whatever the consumer calls a
// principal. Passport leaves it on `request.user`.
export interface VerifiedSignetIdentity {
  // The verified payload, frozen, for a resolver whose authorization key is
  // a claim the issuer puts on the token (an ERP user id, say). `sub`,
  // `client_id` and the scope claims also appear parsed below; the parsed
  // fields are what this package reads.
  readonly claims: Readonly<JWTPayload>;
  readonly clientId: string;
  readonly issuer: string;
  readonly scopes: readonly string[];
  readonly subject: string;
}

// This package's own rejection codes, alongside the ERR_* codes jose throws.
export const JwtRejectionEnum = {
  AZP_MISMATCH: 'ERR_JWT_AZP_MISMATCH',
  BAD_SCOPE: 'ERR_JWT_BAD_SCOPE',
  JWKS_PARSE: 'ERR_JOSE_GENERIC:jwks_parse',
  JWKS_STATUS: 'ERR_JOSE_GENERIC:jwks_status',
  NO_CLIENT_ID: 'ERR_JWT_NO_CLIENT_ID',
  NO_EXP: 'ERR_JWT_NO_EXP',
  NO_SUB: 'ERR_JWT_NO_SUB',
} as const;
export type JwtRejection =
  (typeof JwtRejectionEnum)[keyof typeof JwtRejectionEnum];

// `reason` is open: jose's ERR_* codes and Node's errno strings pass through
// verbatim. JwtRejectionEnum names the codes this file produces.
export type VerifyResult =
  | { ok: false; reason: string }
  | { ok: true; identity: VerifiedSignetIdentity };

// A verified OIDC ID token's payload, frozen. `reason` as in VerifyResult.
export type IdTokenVerifyResult =
  { claims: Readonly<JWTPayload>; ok: true } | { ok: false; reason: string };

// jose reports both JWKS transport failures -- a non-200 status and an
// unparseable body -- as JOSEError with the same ERR_JOSE_GENERIC code; only
// the message tells them apart, and an operator reading logs during an
// outage needs to.
function joseRejection(error: errors.JOSEError): string {
  if (error.code !== 'ERR_JOSE_GENERIC') return error.code;
  if (error.message.includes('Expected 200 OK')) {
    return JwtRejectionEnum.JWKS_STATUS;
  }
  if (error.message.includes('Failed to parse')) {
    return JwtRejectionEnum.JWKS_PARSE;
  }
  return error.code;
}

// Hydra's JWT access tokens carry the granted scopes as `scp` (an array);
// RFC 9068 §2.2.3 spells the same thing `scope` (a space-delimited string).
// Both are read. Neither present is an EMPTY scope set, which the guard
// refuses with a 403 for lacking the admission scope; either present with the
// wrong shape is null, a contract violation the caller answers with 401.
function scopesOf(payload: JWTPayload): string[] | null {
  const { scope, scp } = payload;
  const scopes: string[] = [];
  if (scope !== undefined) {
    if (typeof scope !== 'string') return null;
    scopes.push(...scope.split(' ').filter((value) => value !== ''));
  }
  if (scp !== undefined) {
    if (!Array.isArray(scp)) return null;
    for (const value of scp) {
      if (typeof value !== 'string') return null;
      scopes.push(value);
    }
  }
  return scopes;
}

// Verifies a Signet access token against the trusted issuer's JWKS and the
// deployment's canonical resource.
//
// Returns a result rather than throwing: the caller logs the reason and
// answers a uniform 401, so a rejection never tells the client WHICH check
// failed. Key fetch failures land in the same catch -- unreachable JWKS
// refuses, never admits.
//
// One instance for the life of the process: the remote key set's cache,
// cooldown and pending-fetch state live on it, so constructing one per
// request would refetch the whole JWKS on every request and defeat the
// cache.
export class JwtVerifier {
  private readonly keys: ReturnType<typeof createRemoteJWKSet>;

  constructor(private readonly settings: JwtSettings) {
    this.keys = createRemoteJWKSet(
      new URL(settings.jwksUri),
      REMOTE_JWKS_OPTIONS,
    );
  }

  async verify(token: string): Promise<VerifyResult> {
    // audience accepts a string or an array containing the expected value;
    // the issuer's fixed client policy is what keeps a token single-audience.
    const checked = await this.signedPayload(token, this.settings.audience);
    if (!checked.ok) return checked;
    const { payload, subject } = checked;
    // RFC 9068 §2.2 makes client_id a required claim of a JWT access token
    // and Signet issues it on every token, dynamically registered clients
    // included -- so a token without one is not the shape this contract
    // accepts, and its absence is an access-token contract failure (401). It
    // is NOT a lookup key: the guard logs it as the software that presented
    // the credential.
    if (typeof payload.client_id !== 'string' || payload.client_id === '') {
      return { ok: false, reason: JwtRejectionEnum.NO_CLIENT_ID };
    }
    const scopes = scopesOf(payload);
    if (scopes === null) {
      return { ok: false, reason: JwtRejectionEnum.BAD_SCOPE };
    }
    // iat is deliberately not required and no maxTokenAge is applied.
    // Business roles the token might carry are ignored here: authorization
    // is the consumer's resolver's alone.
    return {
      identity: {
        claims: Object.freeze(payload),
        clientId: payload.client_id,
        issuer: this.settings.issuer,
        scopes,
        subject,
      },
      ok: true,
    };
  }

  // Verifies an OIDC ID token for `clientId` (OIDC Core §3.1.3.7): the same
  // keys, algorithms, issuer and clock tolerance as an access token, its
  // `aud` containing the client instead of the resource. No nonce: the login
  // flow is authorization code + PKCE and the token comes straight from the
  // token endpoint over TLS, where §3.1.2.1 makes it optional. Matching its
  // `sub` to the access token's is the caller's.
  async verifyIdToken(
    token: string,
    clientId: string,
  ): Promise<IdTokenVerifyResult> {
    const checked = await this.signedPayload(token, clientId);
    if (!checked.ok) return checked;
    const { payload } = checked;
    // §3.1.3.7 step 4: a token for several audiences names the one it was
    // issued to.
    if (
      Array.isArray(payload.aud) &&
      payload.aud.length > 1 &&
      payload.azp !== clientId
    ) {
      return { ok: false, reason: JwtRejectionEnum.AZP_MISMATCH };
    }
    return { claims: Object.freeze(payload), ok: true };
  }

  // The checks every token gets: signature, issuer, audience, exp / nbf
  // (jose's), then exp present and sub non-empty (this file's).
  private async signedPayload(
    token: string,
    audience: string,
  ): Promise<
    | { ok: false; reason: string }
    | { ok: true; payload: JWTPayload; subject: string }
  > {
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, this.keys, {
        algorithms: ASYMMETRIC_ALGORITHMS,
        audience,
        clockTolerance: this.settings.clockToleranceS,
        issuer: this.settings.issuer,
      }));
    } catch (error) {
      if (error instanceof errors.JOSEError) {
        return { ok: false, reason: joseRejection(error) };
      }
      // Errors from the JWKS fetch that are not jose's own -- Node system
      // errors (ECONNREFUSED, ENOTFOUND, ETIMEDOUT, ...) and a key that Node
      // cannot import (crypto's ERR_CRYPTO_* codes) -- carry a string code and
      // refuse like any other unusable issuer. Matched by shape: Node creates
      // them outside a test runner's vm realm, where instanceof Error is
      // false.
      const { code } = (error ?? {}) as { code?: unknown };
      if (typeof code === 'string') return { ok: false, reason: code };
      // Anything else is a defect in this process, not a bad token: it must
      // surface as a 500, not hide behind a 401.
      throw error;
    }

    // jose does not require exp: a token without one never expires, which
    // is a long-lived credential minted by omission.
    if (typeof payload.exp !== 'number') {
      return { ok: false, reason: JwtRejectionEnum.NO_EXP };
    }
    const { sub } = payload;
    if (typeof sub !== 'string' || sub.length === 0) {
      return { ok: false, reason: JwtRejectionEnum.NO_SUB };
    }
    return { ok: true, payload, subject: sub };
  }
}
