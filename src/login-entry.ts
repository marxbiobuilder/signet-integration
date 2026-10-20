import { DEVELOPMENT_ENVIRONMENT } from './options';
import { SIGNET_JWT_STRATEGY } from './strategy';

// One way into the login flow: one redirect URI per environment, registered
// at the IdP verbatim. A service with two front-end hosts on one API has two
// entries, each its own Passport strategy.
//
// The profile's `host` is not used to build the URI: it names the canonical
// resource, and one deployment may serve several front-end hosts. Nothing
// from the request -- Host, X-Forwarded-Host -- is ever used either.
export interface SignetLoginEntry<E extends string = string> {
  // The Passport strategy name, and the suffix of the state cookie's name.
  // Lowercase letters, digits and hyphens, starting with a letter.
  readonly name: string;
  // Deployed environments: https. Development: http on a loopback host
  // (localhost, 127.0.0.1, [::1]) or https.
  readonly redirectUris: Readonly<
    Record<E | typeof DEVELOPMENT_ENVIRONMENT, string>
  >;
  // Requested scopes; the admission scope is always added. Default
  // ['openid']. `offline_access` buys nothing here: the package keeps no
  // refresh token.
  readonly scopes?: readonly string[];
}

const ENTRY_NAME = /^[a-z][a-z0-9-]*$/;
// RFC 6749 §3.3 scope-token: no space (the list separator), no quote or
// backslash, at least one character.
const SCOPE_TOKEN = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set([
  'localhost',
  '127.0.0.1',
  '[::1]',
]);

// Checked when the strategy class is created, env-free: the name, the
// scopes, and every environment's redirect URI -- so a malformed or
// non-https production URI fails on a developer's machine (a misspelt host
// or path still fails only at the IdP). Returns a frozen copy, which is all
// the strategy keeps: the Passport name is taken now, the cookie name and
// the URIs later, and a caller mutating its own object in between must not
// pull them apart.
export function validateLoginEntry(entry: SignetLoginEntry): SignetLoginEntry {
  const { name } = entry;
  if (!ENTRY_NAME.test(name)) {
    throw new Error(
      `invalid SignetLoginEntry: name ${JSON.stringify(name)} must be lowercase letters, digits and hyphens, starting with a letter`,
    );
  }
  if (name === SIGNET_JWT_STRATEGY) {
    throw new Error(
      `invalid SignetLoginEntry: name ${name} is the Bearer strategy's`,
    );
  }
  for (const scope of entry.scopes ?? []) {
    if (!SCOPE_TOKEN.test(scope)) {
      throw new Error(
        `invalid SignetLoginEntry ${name}: scope ${JSON.stringify(scope)} is not a scope token (RFC 6749 §3.3)`,
      );
    }
  }
  for (const [environment, raw] of Object.entries(entry.redirectUris)) {
    checkRedirectUri(name, environment, raw);
  }
  return Object.freeze({
    name,
    redirectUris: Object.freeze({ ...entry.redirectUris }),
    ...(entry.scopes === undefined
      ? {}
      : { scopes: Object.freeze([...entry.scopes]) }),
  });
}

// The entry's environments against the options': one redirect URI for each
// deployed environment and for development, and none for an environment the
// options do not know (a misspelling such as `prodution`). Env-free, so it
// runs with the Signet flag off too.
export function checkLoginEntryEnvironments(
  entry: SignetLoginEntry,
  deployedEnvironments: readonly string[],
): void {
  const expected = new Set([...deployedEnvironments, DEVELOPMENT_ENVIRONMENT]);
  const given = new Set(Object.keys(entry.redirectUris));
  const missing = [...expected].filter((e) => !given.has(e));
  const unknown = [...given].filter((e) => !expected.has(e));
  if (missing.length > 0) {
    throw new Error(
      `invalid SignetLoginEntry ${entry.name}: no redirect URI for ${missing.join(', ')}`,
    );
  }
  if (unknown.length > 0) {
    throw new Error(
      `invalid SignetLoginEntry ${entry.name}: redirect URI for an environment the options do not name: ${unknown.join(', ')}`,
    );
  }
}

export interface LoginRedirectUri {
  // Parsed, for the cookie's Path and Secure.
  readonly url: URL;
  // Verbatim, for `redirect_uri`: what the IdP compares is what was
  // registered, and URL parsing normalises (a bare origin gains a slash).
  readonly value: string;
}

// The redirect URI this process uses.
export function loginRedirectUri(
  entry: SignetLoginEntry,
  environment: string,
): LoginRedirectUri {
  const raw: string | undefined = entry.redirectUris[environment];
  if (raw === undefined) {
    throw new Error(
      `invalid SignetLoginEntry ${entry.name}: no redirect URI for environment ${environment}`,
    );
  }
  return checkRedirectUri(entry.name, environment, raw);
}

// Every environment but development is deployed (the options validation
// refuses a deployed environment by that name), so its URI must be https.
function checkRedirectUri(
  name: string,
  environment: string,
  raw: string,
): LoginRedirectUri {
  const fail = (reason: string): never => {
    throw new Error(`invalid SignetLoginEntry ${name}: ${reason}`);
  };
  const development = environment === DEVELOPMENT_ENVIRONMENT;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return fail(`redirect URI for ${environment} is not a URL: ${raw}`);
  }
  if (url.hash !== '' || raw.includes('#')) {
    fail(`redirect URI for ${environment} must not carry a fragment`);
  }
  if (url.username !== '' || url.password !== '') {
    fail(`redirect URI for ${environment} must not carry credentials`);
  }
  const https = url.protocol === 'https:';
  const loopbackHttp =
    url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname);
  if (!https && !(development && loopbackHttp)) {
    fail(
      development
        ? `redirect URI for ${environment} must be https, or http on a loopback host`
        : `redirect URI for ${environment} must be https`,
    );
  }
  return { url, value: raw };
}
