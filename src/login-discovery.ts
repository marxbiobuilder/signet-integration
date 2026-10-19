import {
  fetchJson,
  type JsonResponse,
  LoginTransportError,
} from './login-http';

// The issuer's two endpoints the login flow calls, read from its OpenID
// Provider metadata on first use and kept for the life of the process.
//
// Checks: the document's `issuer` is the configured one verbatim (RFC 8414
// §3.3 -- a document for another issuer is a mix-up, not a typo to
// tolerate), and both endpoints are https outside development. A failure is
// not cached: the next login tries again.
//
// Design Decision: a success IS cached for good, with no TTL. Moving an
// endpoint is a breaking change on Signet's side, announced to every
// resource server in advance (its resource-server contract), and a restart
// picks the new document up; a TTL would add a refetch path to get wrong for
// a change that does not happen silently.

export interface LoginEndpoints {
  readonly authorizationEndpoint: string;
  readonly tokenEndpoint: string;
}

// Why discovery failed, for the log line. Never the response body.
export class LoginDiscoveryError extends Error {
  constructor(readonly detail: string) {
    super(`signet discovery failed: ${detail}`);
    this.name = 'LoginDiscoveryError';
  }
}

// OpenID Connect Discovery §4: the well-known path is appended to the issuer
// with any trailing slash removed first.
export function discoveryUrl(issuer: string): string {
  return `${issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`;
}

export class LoginDiscovery {
  private pending: Promise<LoginEndpoints> | undefined;

  constructor(
    private readonly issuer: string,
    private readonly requireHttps: boolean,
    private readonly timeoutMs: number,
  ) {}

  // Rejects with LoginDiscoveryError for every failure on the issuer's side;
  // any other rejection is a defect in this process.
  endpoints(): Promise<LoginEndpoints> {
    // One fetch in flight however many logins start at once; dropped on
    // failure so the next call refetches.
    this.pending ??= this.fetch().catch((error: unknown) => {
      this.pending = undefined;
      throw error;
    });
    return this.pending;
  }

  private async fetch(): Promise<LoginEndpoints> {
    let response: JsonResponse;
    try {
      response = await fetchJson(discoveryUrl(this.issuer), {}, this.timeoutMs);
    } catch (error) {
      if (error instanceof LoginTransportError) {
        throw new LoginDiscoveryError(error.detail);
      }
      throw error;
    }
    if (!response.ok) {
      throw new LoginDiscoveryError(`status_${response.status}`);
    }
    if (!response.json) throw new LoginDiscoveryError('body_not_json');
    const { authorization_endpoint, issuer, token_endpoint } = (response.body ??
      {}) as Record<string, unknown>;
    if (issuer !== this.issuer) {
      throw new LoginDiscoveryError('issuer_mismatch');
    }
    return {
      authorizationEndpoint: this.endpoint(
        authorization_endpoint,
        'authorization_endpoint',
      ),
      tokenEndpoint: this.endpoint(token_endpoint, 'token_endpoint'),
    };
  }

  private endpoint(value: unknown, field: string): string {
    if (typeof value !== 'string') {
      throw new LoginDiscoveryError(`${field}_missing`);
    }
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new LoginDiscoveryError(`${field}_invalid`);
    }
    const allowed =
      url.protocol === 'https:' ||
      (url.protocol === 'http:' && !this.requireHttps);
    if (!allowed) throw new LoginDiscoveryError(`${field}_not_https`);
    return value;
  }
}
