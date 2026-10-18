// The issuer's two endpoints the login flow calls, read from its OpenID
// Provider metadata on first use and kept for the life of the process.
//
// Checks: the document's `issuer` is the configured one verbatim (RFC 8414
// §3.3 -- a document for another issuer is a mix-up, not a typo to
// tolerate), and both endpoints are https outside development. A failure is
// not cached: the next login tries again.

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
    let response: Response;
    try {
      response = await fetch(discoveryUrl(this.issuer), {
        headers: { accept: 'application/json' },
        redirect: 'error',
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw new LoginDiscoveryError(transportFailure(error));
    }
    if (!response.ok) {
      throw new LoginDiscoveryError(`status_${response.status}`);
    }
    let document: unknown;
    try {
      document = await response.json();
    } catch {
      throw new LoginDiscoveryError('body_not_json');
    }
    const { authorization_endpoint, issuer, token_endpoint } = (document ??
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
    if (
      url.protocol !== 'https:' &&
      !(url.protocol === 'http:' && !this.requireHttps)
    ) {
      throw new LoginDiscoveryError(`${field}_not_https`);
    }
    return value;
  }
}

// A fetch that never produced a response: the error's name (TimeoutError,
// TypeError) and, for Node's network errors, the errno code on its cause.
// Never the message, which can carry the URL. Matched by shape: undici's
// DOMException and Node's system errors are created outside a test runner's
// vm realm, where instanceof Error is false.
export function transportFailure(error: unknown): string {
  const { cause, name } = (error ?? {}) as {
    cause?: { code?: unknown };
    name?: unknown;
  };
  const label = typeof name === 'string' && name !== '' ? name : 'unknown';
  return typeof cause?.code === 'string' ? `${label}:${cause.code}` : label;
}
