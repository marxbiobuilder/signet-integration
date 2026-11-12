import { timingSafeEqual } from 'node:crypto';

import { type JWTPayload } from 'jose';

import { JwtVerifier } from './jwt-verifier';
import { LoginDiscovery } from './login-discovery';
import { fetchJson } from './login-http';
import { codeChallenge, newLoginState } from './login-state';
import { validateScopes } from './oauth';
import {
  createTokenVerifier,
  hasAllScopes,
  trustedUrl,
  type VerifiedIdentity,
  type TokenVerifierOptions,
} from './verification';

export * from './login-discovery';
export * from './login-http';
export * from './login-state';

export interface LoginTransaction {
  readonly state: string;
  readonly verifier: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly issuer: string;
  readonly resource: string;
  readonly expiresAt: number;
}

export interface OidcClientOptions extends TokenVerifierOptions {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scopes: readonly string[];
  readonly admissionScopes: readonly string[];
  readonly timeoutMs?: number;
}

export class OidcError extends Error {
  constructor(
    readonly reason:
      | 'state_invalid'
      | 'cancelled'
      | 'idp_error'
      | 'token_exchange_failed'
      | 'token_rejected',
  ) {
    super(`OIDC login refused: ${reason}`);
    this.name = 'OidcError';
  }
}

export interface OidcClient {
  begin(): Promise<{ authorizationUrl: string; transaction: LoginTransaction }>;
  complete(input: {
    callbackUrl: string;
    transaction: LoginTransaction;
  }): Promise<{
    identity: VerifiedIdentity;
    idTokenClaims: Readonly<JWTPayload>;
  }>;
}

/** Public-client authorization code flow. The adapter seals the transaction. */
export function createOidcClient(options: OidcClientOptions): OidcClient {
  // Pin trust and policy for the lifetime of the client, including arrays
  // supplied by JavaScript callers that can still mutate readonly values.
  options = Object.freeze({
    ...options,
    scopes: Object.freeze([...options.scopes]),
    admissionScopes: Object.freeze([...options.admissionScopes]),
  });
  const verifier = createTokenVerifier(options);
  const redirect = trustedUrl(
    options.redirectUri,
    options.allowInsecureLoopback,
  );
  validateScopes([...options.scopes, ...options.admissionScopes]);
  if (
    !options.scopes.includes('openid') ||
    options.scopes.includes('offline_access')
  ) {
    throw new Error(
      'Interactive login requires openid and does not retain offline credentials',
    );
  }
  if (!options.clientId || options.clientId !== options.clientId.trim())
    throw new Error('Invalid clientId');
  const timeout = options.timeoutMs ?? 5000;
  if (!Number.isInteger(timeout) || timeout < 1 || timeout > 30000)
    throw new Error('Invalid timeoutMs');
  const discovery = new LoginDiscovery(
    options.issuer,
    !options.allowInsecureLoopback,
    timeout,
  );
  const idVerifier = new JwtVerifier({
    issuer: options.issuer,
    audience: options.audience,
    jwksUri: options.jwksUri,
    clockToleranceS: options.clockToleranceSeconds ?? 60,
  });
  const scopes = [...new Set([...options.scopes, ...options.admissionScopes])];
  const endpoints = async () => {
    const result = await discovery.endpoints();
    trustedUrl(result.authorizationEndpoint, options.allowInsecureLoopback);
    trustedUrl(result.tokenEndpoint, options.allowInsecureLoopback);
    return result;
  };
  const one = (url: URL, key: string) =>
    url.searchParams.getAll(key).length === 1
      ? url.searchParams.get(key)
      : null;
  return {
    async begin() {
      const discovered = await endpoints();
      const state = newLoginState(options.clientId);
      const transaction = Object.freeze({
        state: state.state,
        verifier: state.verifier,
        clientId: options.clientId,
        redirectUri: options.redirectUri,
        issuer: options.issuer,
        resource: options.audience,
        expiresAt: Math.floor(Date.now() / 1000) + 600,
      });
      const url = new URL(discovered.authorizationEndpoint);
      for (const [key, value] of Object.entries({
        response_type: 'code',
        client_id: options.clientId,
        redirect_uri: options.redirectUri,
        resource: options.audience,
        scope: scopes.join(' '),
        state: state.state,
        code_challenge: codeChallenge(state.verifier),
        code_challenge_method: 'S256',
      }))
        url.searchParams.set(key, value);
      return { authorizationUrl: url.toString(), transaction };
    },
    async complete({ callbackUrl, transaction: tx }) {
      const url = new URL(callbackUrl);
      const state = one(url, 'state');
      if (
        url.origin !== redirect.origin ||
        url.pathname !== redirect.pathname ||
        url.username !== '' ||
        url.password !== '' ||
        url.hash !== '' ||
        tx.clientId !== options.clientId ||
        tx.redirectUri !== options.redirectUri ||
        tx.issuer !== options.issuer ||
        tx.resource !== options.audience ||
        !Number.isFinite(tx.expiresAt) ||
        tx.expiresAt <= Date.now() / 1000 ||
        tx.expiresAt > Date.now() / 1000 + 600 ||
        typeof tx.verifier !== 'string' ||
        !/^[A-Za-z0-9_-]{43}$/.test(tx.verifier) ||
        typeof tx.state !== 'string' ||
        !/^[A-Za-z0-9_-]{43}$/.test(tx.state) ||
        state === null ||
        Buffer.byteLength(state) !== Buffer.byteLength(tx.state) ||
        !timingSafeEqual(Buffer.from(state), Buffer.from(tx.state))
      )
        throw new OidcError('state_invalid');
      if (url.searchParams.has('error'))
        throw new OidcError(
          one(url, 'error') === 'access_denied' ? 'cancelled' : 'idp_error',
        );
      const code = one(url, 'code');
      if (!code) throw new OidcError('idp_error');
      const discovered = await endpoints();
      const response = await fetchJson(
        discovered.tokenEndpoint,
        {
          method: 'POST',
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: options.clientId,
            redirect_uri: options.redirectUri,
            code,
            code_verifier: tx.verifier,
          }),
        },
        timeout,
      );
      const body = response.body as Record<string, unknown> | null;
      if (
        !response.ok ||
        !response.json ||
        !body ||
        typeof body.access_token !== 'string' ||
        typeof body.id_token !== 'string'
      )
        throw new OidcError('token_exchange_failed');
      const identity = await verifier.verifyAccessToken(body.access_token);
      if (
        !identity.ok ||
        identity.identity.clientId !== options.clientId ||
        !hasAllScopes(identity.identity, options.admissionScopes)
      )
        throw new OidcError('token_rejected');
      const id = await idVerifier.verifyIdToken(
        body.id_token,
        options.clientId,
      );
      if (!id.ok || id.claims.sub !== identity.identity.subject)
        throw new OidcError('token_rejected');
      return { identity: identity.identity, idTokenClaims: id.claims };
    },
  };
}
