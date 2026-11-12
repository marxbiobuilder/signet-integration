import { JwtVerifier, type VerifiedSignetIdentity } from './jwt-verifier';

export interface VerifiedIdentity extends VerifiedSignetIdentity {
  readonly expiresAt: number;
}

export type VerificationResult =
  | { readonly ok: true; readonly identity: VerifiedIdentity }
  | {
      readonly ok: false;
      readonly kind: 'invalid_token' | 'verification_unavailable';
      readonly reason: string;
    };

export interface TokenVerifier {
  verifyAccessToken(token: string): Promise<VerificationResult>;
}

export interface TokenVerifierOptions {
  readonly issuer: string;
  readonly audience: string;
  readonly jwksUri: string;
  readonly clockToleranceSeconds?: number;
  /** Only for local HTTP fixtures and local development. */
  readonly allowInsecureLoopback?: boolean;
}

export function trustedUrl(value: string, allowInsecureLoopback = false): URL {
  const url = new URL(value);
  if (
    value !== value.trim() ||
    url.username ||
    url.password ||
    url.hash ||
    url.search ||
    (url.protocol !== 'https:' &&
      !(
        allowInsecureLoopback &&
        url.protocol === 'http:' &&
        ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
      ))
  ) {
    throw new Error(
      'Expected a trusted HTTPS URL without credentials, query or fragment',
    );
  }
  return url;
}

function unavailable(reason: string): boolean {
  return (
    reason.startsWith('ERR_JOSE_GENERIC:') ||
    [
      'ERR_JWKS_TIMEOUT',
      'ECONNREFUSED',
      'ECONNRESET',
      'ENOTFOUND',
      'EAI_AGAIN',
      'ETIMEDOUT',
      'ERR_TLS_CERT_ALTNAME_INVALID',
      'CERT_HAS_EXPIRED',
      'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
      'DEPTH_ZERO_SELF_SIGNED_CERT',
    ].includes(reason)
  );
}

/** One instance per trusted resource: jose keeps the JWKS cache on it. */
export function createTokenVerifier(
  options: TokenVerifierOptions,
): TokenVerifier {
  for (const url of [options.issuer, options.audience, options.jwksUri]) {
    trustedUrl(url, options.allowInsecureLoopback);
  }
  const tolerance = options.clockToleranceSeconds ?? 60;
  if (!Number.isInteger(tolerance) || tolerance < 0 || tolerance > 300) {
    throw new Error(
      'clockToleranceSeconds must be an integer between 0 and 300',
    );
  }
  const verifier = new JwtVerifier({
    issuer: options.issuer,
    audience: options.audience,
    jwksUri: options.jwksUri,
    clockToleranceS: tolerance,
  });
  return {
    async verifyAccessToken(token) {
      const result = await verifier.verify(token);
      if (!result.ok) {
        return {
          ...result,
          kind: unavailable(result.reason)
            ? 'verification_unavailable'
            : 'invalid_token',
        };
      }
      const scopes = Object.freeze([...new Set(result.identity.scopes)]);
      return {
        ok: true,
        identity: Object.freeze({
          ...result.identity,
          scopes,
          expiresAt: result.identity.claims.exp!,
        }),
      };
    },
  };
}

export function hasAllScopes(
  identity: Pick<VerifiedSignetIdentity, 'scopes'>,
  required: readonly string[],
): boolean {
  return required.every((scope) => identity.scopes.includes(scope));
}
