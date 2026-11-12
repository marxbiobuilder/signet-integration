export {
  codeChallenge,
  LOGIN_STATE_SECRET_MIN_BYTES,
  LOGIN_STATE_TTL_S,
  type LoginState,
  loginStateKey,
  type LoginStateOpenFailure,
  type LoginStateOpening,
  newLoginState,
  openLoginState,
  sealLoginState,
} from '@xignet/core/oidc';

export function loginStateCookieName(entry: string): string {
  return `signet_login.${entry}`;
}

// Scoped to the redirect URI's path, so the cookie travels only to the
// callback's path (and, Path being a prefix match, anything below it). SameSite=Lax because the IdP's redirect back is a cross-site
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
