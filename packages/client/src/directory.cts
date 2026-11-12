import { randomUUID } from 'node:crypto';
import {
  SignetClient,
  executeWithBearer,
  SignetRequestError,
} from './index.cjs';

export const XIGNET_DIRECTORY_DEFAULTS = Object.freeze({
  issuer: 'https://signet.marxbio.tech',
  resource: 'https://signet.marxbio.tech/directory',
  tokenEndpoint: 'https://signet.marxbio.tech/oauth2/token',
  resolveEndpoint: 'https://signet.marxbio.tech/directory/users/resolve',
});
export interface DirectoryIdentity {
  readonly issuer: string;
  readonly sub: string;
  readonly email: string;
}
export interface DirectoryClient {
  resolve(
    email: string,
    context?: { readonly requestId: string },
  ): Promise<DirectoryIdentity>;
}
export type DirectoryErrorCode =
  | 'invalid_email'
  | 'not_found'
  | 'unauthorized'
  | 'forbidden'
  | 'rate_limited'
  | 'unavailable'
  | 'invalid_response';
/** Fixed classifications only; never retains credentials, body, URL or cause. */
export class DirectoryError extends Error {
  constructor(readonly code: DirectoryErrorCode) {
    super(`Xignet directory: ${code}`);
    this.name = 'DirectoryError';
  }
}
export interface DirectoryClientOptions {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly issuer?: string;
  readonly resource?: string;
  readonly tokenEndpoint?: string;
  readonly resolveEndpoint?: string;
  readonly timeoutMs?: number;
  readonly allowInsecureLoopback?: boolean;
  /** Trusted transport override for tests or proxies; never from browser input. */
  readonly fetch?: typeof globalThis.fetch;
}
/** Matches Xignet's lowercase mailbox convention; never folds aliases. */
export function canonicalEmail(value: unknown): string {
  if (typeof value !== 'string') throw new DirectoryError('invalid_email');
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    throw new DirectoryError('invalid_email');
  return email;
}

/** One reusable, server-only client. Token acquisition/cache stays in SignetClient. */
export function createDirectoryClient(
  input: DirectoryClientOptions,
): DirectoryClient {
  const options = Object.freeze({ ...XIGNET_DIRECTORY_DEFAULTS, ...input });
  const timeout = options.timeoutMs ?? 5000;
  const trustedUrl = (value: string) => {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      throw new Error('Invalid Directory endpoint configuration');
    }
    if (
      value !== value.trim() ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      (url.protocol !== 'https:' &&
        !(
          options.allowInsecureLoopback &&
          url.protocol === 'http:' &&
          ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
        ))
    )
      throw new Error('Directory requires trusted HTTPS endpoints');
    return url;
  };
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 30000)
    throw new Error('Invalid Directory timeoutMs');
  if (
    typeof options.clientId !== 'string' ||
    !options.clientId.startsWith('service:') ||
    !options.clientSecret ||
    /\s/.test(options.clientId)
  )
    throw new Error('Directory requires service client credentials');
  const issuer = trustedUrl(options.issuer);
  const resource = trustedUrl(options.resource);
  if (
    trustedUrl(options.tokenEndpoint).origin !== issuer.origin ||
    trustedUrl(options.resolveEndpoint).origin !== resource.origin
  )
    throw new Error(
      'Directory endpoints must match their trusted issuer/resource origins',
    );
  const transport = options.fetch ?? globalThis.fetch;
  const client = new SignetClient({
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    tokenUrl: options.tokenEndpoint,
    audience: options.resource,
    scope: 'directory:access directory:read',
    timeoutMs: timeout,
    allowInsecureLoopback: options.allowInsecureLoopback,
    fetch: transport,
  });
  return Object.freeze({
    async resolve(
      value: string,
      context?: { readonly requestId: string },
    ): Promise<DirectoryIdentity> {
      const email = canonicalEmail(value);
      const requestId = context?.requestId ?? randomUUID();
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(requestId))
        throw new DirectoryError('invalid_response');
      try {
        const response = await executeWithBearer(
          client,
          async ({ token }) => {
            const response = await transport(options.resolveEndpoint, {
              method: 'POST',
              headers: {
                authorization: `Bearer ${token}`,
                'x-request-id': requestId,
                'content-type': 'application/json',
                accept: 'application/json',
              },
              body: JSON.stringify({ email }),
              redirect: 'error',
              cache: 'no-store',
              signal: AbortSignal.timeout(timeout),
            });
            return {
              status: response.status,
              value: response,
              dispose: () => response.body?.cancel(),
            };
          },
          { retryOnUnauthorized: true },
        );
        const reader = response.body?.getReader();
        if (!reader) throw new DirectoryError('invalid_response');
        const chunks: Uint8Array[] = [];
        let size = 0;
        for (;;) {
          const { done, value: chunk } = await reader.read();
          if (done) break;
          size += chunk.byteLength;
          if (size > 16384) {
            await reader.cancel();
            throw new DirectoryError('invalid_response');
          }
          chunks.push(chunk);
        }
        let body: Record<string, unknown> | null;
        try {
          body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<
            string,
            unknown
          > | null;
        } catch {
          throw new DirectoryError('invalid_response');
        }
        if (
          !body ||
          body.issuer !== options.issuer ||
          typeof body.sub !== 'string' ||
          !body.sub ||
          body.sub.length > 255 ||
          /\s/.test(body.sub) ||
          body.sub.startsWith('service:') ||
          body.email !== email
        )
          throw new DirectoryError('invalid_response');
        return Object.freeze({
          issuer: body.issuer as string,
          sub: body.sub,
          email,
        });
      } catch (error) {
        if (error instanceof DirectoryError) throw error;
        if (error instanceof SignetRequestError) {
          const codes: Record<number, DirectoryErrorCode> = {
            401: 'unauthorized',
            403: 'forbidden',
            404: 'not_found',
            429: 'rate_limited',
          };
          throw new DirectoryError(
            error.phase === 'resource' && error.status
              ? (codes[error.status] ?? 'unavailable')
              : 'unavailable',
          );
        }
        throw new DirectoryError('unavailable');
      }
    },
  });
}
