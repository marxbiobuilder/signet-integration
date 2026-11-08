export interface SignetClientOptions {
  /** Explicit token_endpoint from the issuer's discovery document. HTTPS only. */
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  /** Signet/Hydra expects audience in the form body, not resource or query. */
  audience: string;
  /** Required: use the scopes configured for this resource/client. */
  scope: string;
  timeoutMs?: number;
  refreshMarginSeconds?: number;
  /** Optional transport override for proxy integration and isolated tests. */
  fetch?: typeof globalThis.fetch;
}

export type SignetOAuthErrorCode =
  'INVALID_CONFIGURATION' | 'TOKEN_REQUEST_FAILED' | 'INVALID_TOKEN_RESPONSE';

/** Contains no upstream body, URL, credentials, token or raw cause. Safe to log. */
export class SignetOAuthError extends Error {
  readonly code: SignetOAuthErrorCode;
  readonly status?: number;

  constructor(code: SignetOAuthErrorCode, status?: number) {
    super(`Signet OAuth: ${code}${status ? ` (HTTP ${status})` : ''}`);
    this.name = 'SignetOAuthError';
    this.code = code;
    this.status = status;
  }
}

/**
 * One instance per client/audience/scope configuration. Holds a single token in
 * process memory. No timers, persistent storage, logging or API retries.
 */
export class SignetClient {
  readonly #options: Readonly<SignetClientOptions>;
  #cached?: { value: string; expiresAt: number };
  #inFlight?: Promise<string>;

  constructor(options: SignetClientOptions) {
    const invalid = () => new SignetOAuthError('INVALID_CONFIGURATION');
    for (const value of [
      options.tokenUrl,
      options.clientId,
      options.clientSecret,
      options.audience,
      options.scope,
    ]) {
      if (typeof value !== 'string' || !value.trim()) throw invalid();
    }
    let url: URL;
    try {
      url = new URL(options.tokenUrl);
    } catch {
      throw invalid();
    }
    if (
      url.protocol !== 'https:' ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    )
      throw invalid();
    const timeout = options.timeoutMs ?? 30_000;
    const margin = options.refreshMarginSeconds ?? 60;
    if (
      !Number.isSafeInteger(timeout) ||
      timeout <= 0 ||
      timeout > 2_147_483_647 ||
      !Number.isFinite(margin) ||
      margin < 0 ||
      (options.fetch !== undefined && typeof options.fetch !== 'function')
    )
      throw invalid();
    this.#options = Object.freeze({
      ...options,
      timeoutMs: timeout,
      refreshMarginSeconds: margin,
    });
  }

  async getAccessToken(): Promise<string> {
    if (this.#cached && Date.now() < this.#cached.expiresAt)
      return this.#cached.value;
    if (this.#inFlight) return this.#inFlight;
    // A finally on the shared promise avoids rejected promises being retained.
    this.#inFlight = this.#requestToken().finally(() => {
      this.#inFlight = undefined;
    });
    return this.#inFlight;
  }

  /**
   * Invalidate only the rejected token. A late 401 must not evict a newer token
   * already obtained for another request. Does not cancel an in-flight exchange.
   */
  invalidateToken(rejectedToken: string): void {
    if (this.#cached?.value === rejectedToken) this.#cached = undefined;
  }

  async #requestToken(): Promise<string> {
    let status: number | undefined;
    try {
      // Keep ESM import native in the CommonJS build for Node.js >=22.22.
      const oidc = await import('openid-client');
      const options = this.#options;
      const config = new oidc.Configuration(
        {
          issuer: new URL(options.tokenUrl).origin,
          token_endpoint: options.tokenUrl,
        },
        options.clientId,
        { token_endpoint_auth_method: 'client_secret_basic' },
        oidc.ClientSecretBasic(options.clientSecret),
      );
      // The protocol library uses redirect:error. Preserve it to avoid forwarding
      // credentials to redirected endpoints; share a deadline across transport.
      const signal = AbortSignal.timeout(options.timeoutMs!);
      const transport = options.fetch ?? globalThis.fetch;
      config[oidc.customFetch] = async (url, init) => {
        // This SDK only performs form-encoded client credentials requests.
        if (!(init.body instanceof URLSearchParams)) {
          throw new SignetOAuthError('TOKEN_REQUEST_FAILED');
        }
        const response = await transport(url, {
          ...init,
          body: init.body,
          redirect: 'error',
          signal,
        });
        status = response.status;
        return response;
      };
      const requestedAt = Date.now();
      const data = await oidc.clientCredentialsGrant(config, {
        audience: options.audience,
        scope: options.scope,
      });
      if (
        !data.access_token ||
        /\s/.test(data.access_token) ||
        data.token_type.toLowerCase() !== 'bearer' ||
        typeof data.expires_in !== 'number' ||
        !Number.isFinite(data.expires_in) ||
        data.expires_in <= 0
      )
        throw new SignetOAuthError('INVALID_TOKEN_RESPONSE');
      const margin = Math.min(
        options.refreshMarginSeconds!,
        data.expires_in / 2,
      );
      const expiresAt = requestedAt + (data.expires_in - margin) * 1000;
      if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
        throw new SignetOAuthError('INVALID_TOKEN_RESPONSE');
      }
      this.#cached = { value: data.access_token, expiresAt };
      return data.access_token;
    } catch (error) {
      if (error instanceof SignetOAuthError) throw error;
      // Discard openid-client errors: cause/response/error_description may be sensitive.
      throw new SignetOAuthError(
        status === 200 ? 'INVALID_TOKEN_RESPONSE' : 'TOKEN_REQUEST_FAILED',
        status,
      );
    }
  }
}
