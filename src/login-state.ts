import { createHash, hkdfSync, randomBytes } from 'node:crypto';

import { EncryptJWT, jwtDecrypt } from 'jose';

// The state of one login in flight, carried by the browser between begin()
// and the callback: the `state` the IdP echoes back, the PKCE verifier, and
// the entry it was issued for.
//
// Encrypted, not merely signed: the verifier is the half of PKCE a party
// that intercepts the code does not have, and a signed cookie would carry it
// in the clear. `dir` + A256GCM under a key derived from the consumer's
// secret, through jose's JWT decryption with both algorithms pinned. This is
// symmetric by design and deliberately NOT JwtVerifier, whose asymmetric
// allowlist stays as it is.

export const LOGIN_STATE_TTL_S = 600;
export const LOGIN_STATE_SECRET_MIN_BYTES = 32;

export interface LoginState {
  readonly entry: string;
  readonly state: string;
  readonly verifier: string;
}

// The secret is at least 32 bytes of the consumer's choosing; HKDF turns it
// into exactly the 32-byte key A256GCM takes, bound to this one use.
export function loginStateKey(secret: string): Uint8Array {
  if (Buffer.byteLength(secret, 'utf8') < LOGIN_STATE_SECRET_MIN_BYTES) {
    throw new Error(
      `the login state secret must be at least ${LOGIN_STATE_SECRET_MIN_BYTES} bytes`,
    );
  }
  return new Uint8Array(
    hkdfSync(
      'sha256',
      secret,
      new Uint8Array(0),
      '@marxbiotech/signet-integration login state',
      32,
    ),
  );
}

export function newLoginState(entry: string): LoginState {
  return {
    entry,
    state: randomBytes(32).toString('base64url'),
    // 43 characters of the RFC 7636 §4.1 alphabet.
    verifier: randomBytes(32).toString('base64url'),
  };
}

// RFC 7636 §4.2, S256.
export function codeChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

export function sealLoginState(
  key: Uint8Array,
  state: LoginState,
): Promise<string> {
  return new EncryptJWT({ ...state })
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .setIssuedAt()
    .setExpirationTime(`${LOGIN_STATE_TTL_S}s`)
    .encrypt(key);
}

// Null for anything that is not a state this process sealed in the last ten
// minutes; the caller does not need to know which.
export async function openLoginState(
  key: Uint8Array,
  sealed: string,
): Promise<LoginState | null> {
  try {
    const { payload } = await jwtDecrypt(sealed, key, {
      contentEncryptionAlgorithms: ['A256GCM'],
      keyManagementAlgorithms: ['dir'],
      requiredClaims: ['exp'],
    });
    const { entry, state, verifier } = payload;
    if (
      typeof entry !== 'string' ||
      typeof state !== 'string' ||
      typeof verifier !== 'string'
    ) {
      return null;
    }
    return { entry, state, verifier };
  } catch {
    return null;
  }
}

export function loginStateCookieName(entry: string): string {
  return `signet_login.${entry}`;
}

// Scoped to the redirect URI's path, so the cookie travels only to the
// callback. SameSite=Lax because the IdP's redirect back is a cross-site
// top-level GET, which Strict would strip it from.
export function loginStateCookie(
  name: string,
  value: string,
  redirectUri: URL,
  maxAgeS: number,
): string {
  const attributes = [
    `${name}=${value}`,
    `Path=${redirectUri.pathname}`,
    `Max-Age=${maxAgeS}`,
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (redirectUri.protocol === 'https:') attributes.push('Secure');
  return attributes.join('; ');
}

// Read straight off the header, so a consumer need not install
// cookie-parser. When the name appears more than once (a stale cookie on a
// wider path), every value is returned; the caller tries each.
export function readCookie(header: string | undefined, name: string): string[] {
  if (header === undefined) return [];
  const values: string[] = [];
  for (const pair of header.split(';')) {
    const separator = pair.indexOf('=');
    if (separator === -1) continue;
    if (pair.slice(0, separator).trim() === name) {
      values.push(pair.slice(separator + 1).trim());
    }
  }
  return values;
}
