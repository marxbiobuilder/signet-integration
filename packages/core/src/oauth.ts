import { trustedUrl } from './verification';

export interface ProtectedResourceMetadata {
  readonly authorization_servers: readonly string[];
  readonly bearer_methods_supported: readonly string[];
  readonly resource: string;
  readonly scopes_supported: readonly string[];
}

export function validateScopes(scopes: readonly string[]): void {
  // RFC 6749 scope-token: printable ASCII excluding quote and backslash.
  if (scopes.some((scope) => !/^[\x21\x23-\x5B\x5D-\x7E]+$/.test(scope))) {
    throw new Error('Expected non-empty OAuth scope tokens');
  }
}

export function protectedResourceMetadataUrl(resource: string): string {
  const url = trustedUrl(resource, true);
  return `${url.origin}/.well-known/oauth-protected-resource${url.pathname === '/' ? '' : url.pathname}`;
}

export function createProtectedResourceMetadata(options: {
  resource: string;
  issuer: string;
  scopesSupported: readonly string[];
  allowInsecureLoopback?: boolean;
}): ProtectedResourceMetadata {
  trustedUrl(options.resource, options.allowInsecureLoopback);
  trustedUrl(options.issuer, options.allowInsecureLoopback);
  validateScopes(options.scopesSupported);
  return Object.freeze({
    authorization_servers: Object.freeze([options.issuer]),
    bearer_methods_supported: Object.freeze(['header']),
    resource: options.resource,
    scopes_supported: Object.freeze([...new Set(options.scopesSupported)]),
  });
}

export function createBearerChallenge(options: {
  resource: string;
  requiredScopes: readonly string[];
  error?: 'invalid_token' | 'insufficient_scope';
}): string {
  validateScopes(options.requiredScopes);
  const metadata = protectedResourceMetadataUrl(options.resource);
  // URL serialization protects the HTTP quoted-string boundary as well.
  const parts = [`Bearer resource_metadata="${metadata}"`];
  if (options.error) parts.push(`error="${options.error}"`);
  if (options.requiredScopes.length)
    parts.push(`scope="${options.requiredScopes.join(' ')}"`);
  return parts.join(', ');
}
