import { createHash, randomBytes } from 'node:crypto';
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http';
import { type AddressInfo } from 'node:net';

import { type JWTPayload } from 'jose';

import { startTestIssuer } from './signet-token';

// An authorization server for login-flow tests: discovery, a token endpoint
// that holds the codes it issued to the PKCE, redirect URI and client they
// were issued for, and the issuer's JWKS. Real HTTP on 127.0.0.1, so the
// flow's own fetches, timeouts and redirects are what is exercised.
//
// There is no browser: authorize() plays the IdP's login page. Hand it the
// URL begin() returned; it checks the request the way Signet would and
// returns the URL the IdP would redirect to, code and state on it.
//
// Tokens have the shape Signet issues: `aud` the single requested resource
// (no `resource` in the request: no `aud`, like a client with several
// audiences that did not pick one), scopes in `scp`, `client_id` present.
// The issuer is this server's origin, which is also what discovery reports.

export interface TestAuthorizationServerOptions {
  // The public client the flow is configured with. A request for another
  // client is refused at authorize() and at the token endpoint.
  readonly clientId: string;
}

// What the user granted. Defaults: subject `test-user`, the requested
// scopes, no extra claims.
export interface TestGrant {
  readonly claims?: JWTPayload;
  readonly scopes?: readonly string[];
  readonly subject?: string;
}

// The token endpoint's answer while a script is set, whatever the request:
//   { status, error? }  that status, with an OAuth `error` body when given
//   { body }            200 with this JSON body (e.g. without access_token)
//   { hang: true }      no answer at all, until close()
//   { hang: 'body' }    200 and its headers, then a body that never ends
export type TokenEndpointScript =
  | { readonly body: unknown }
  | { readonly error?: string; readonly status: number }
  | { readonly hang: 'body' | true };

export interface TestAuthorizationServer {
  readonly authorize: (authorizationUrl: string, grant?: TestGrant) => string;
  readonly close: () => Promise<void>;
  readonly deny: (authorizationUrl: string, error?: string) => string;
  // Replaces the discovery document; null restores the server's own.
  readonly discovery: (document: Record<string, unknown> | null) => void;
  readonly issuer: string;
  readonly jwksUri: string;
  readonly scriptTokenEndpoint: (script: TokenEndpointScript | null) => void;
  // Signs any payload with the issuer's key, for a scripted token endpoint
  // to return a token the flow would not get from a real one.
  readonly sign: (payload: JWTPayload) => Promise<string>;
  // Every token request received, its form fields as sent.
  readonly tokenRequests: () => readonly Readonly<Record<string, string>>[];
}

interface IssuedCode {
  readonly challenge: string;
  readonly grant: Required<TestGrant>;
  readonly redirectUri: string;
  readonly resource: string | undefined;
}

export async function startTestAuthorizationServer(
  options: TestAuthorizationServerOptions,
): Promise<TestAuthorizationServer> {
  const keys = await startTestIssuer();
  const codes = new Map<string, IssuedCode>();
  const received: Record<string, string>[] = [];
  let script: TokenEndpointScript | null = null;
  let discoveryOverride: Record<string, unknown> | null = null;
  let issuer = '';

  const json = (response: ServerResponse, status: number, body: unknown) => {
    response.writeHead(status, { 'content-type': 'application/json' });
    response.end(JSON.stringify(body));
  };

  const token = async (request: IncomingMessage, response: ServerResponse) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const form = Object.fromEntries(
      new URLSearchParams(Buffer.concat(chunks).toString('utf8')),
    );
    received.push(form);
    if (script !== null) {
      if ('hang' in script) {
        if (script.hang === 'body') {
          response.writeHead(200, { 'content-type': 'application/json' });
          response.write('{"access_token":');
        }
        return;
      }
      if ('body' in script) return json(response, 200, script.body);
      return json(
        response,
        script.status,
        script.error === undefined ? {} : { error: script.error },
      );
    }
    const issued = codes.get(form.code ?? '');
    // Single use, as a real server holds it.
    codes.delete(form.code ?? '');
    if (
      form.grant_type !== 'authorization_code' ||
      issued === undefined ||
      form.client_id !== options.clientId ||
      form.redirect_uri !== issued.redirectUri ||
      typeof form.code_verifier !== 'string' ||
      createHash('sha256').update(form.code_verifier).digest('base64url') !==
        issued.challenge
    ) {
      return json(response, 400, { error: 'invalid_grant' });
    }
    const { claims, scopes, subject } = issued.grant;
    const accessToken = await keys.sign({
      ...claims,
      ...(issued.resource === undefined ? {} : { aud: [issued.resource] }),
      client_id: options.clientId,
      iss: issuer,
      scp: [...scopes],
      sub: subject,
    });
    json(response, 200, {
      access_token: accessToken,
      expires_in: 300,
      token_type: 'bearer',
    });
  };

  const server = createServer((request, response) => {
    const path = new URL(request.url ?? '/', issuer).pathname;
    if (
      request.method === 'GET' &&
      path === '/.well-known/openid-configuration'
    ) {
      return json(
        response,
        200,
        discoveryOverride ?? {
          authorization_endpoint: `${issuer}/oauth2/auth`,
          code_challenge_methods_supported: ['S256'],
          issuer,
          jwks_uri: keys.keys.url,
          token_endpoint: `${issuer}/oauth2/token`,
        },
      );
    }
    if (request.method === 'POST' && path === '/oauth2/token') {
      token(request, response).catch(() => json(response, 500, {}));
      return;
    }
    json(response, 404, {});
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  // The checks the IdP makes before showing a login page. A malformed
  // request throws: in a test it is the flow under test that is wrong.
  const read = (authorizationUrl: string) => {
    const url = new URL(authorizationUrl);
    const query = url.searchParams;
    const fail = (reason: string): never => {
      throw new Error(
        `test authorization server refused the request: ${reason}`,
      );
    };
    if (`${url.origin}${url.pathname}` !== `${issuer}/oauth2/auth`) {
      fail('not this server’s authorization endpoint');
    }
    if (query.get('response_type') !== 'code') fail('response_type');
    if (query.get('client_id') !== options.clientId) fail('client_id');
    if (query.get('code_challenge_method') !== 'S256') {
      fail('code_challenge_method');
    }
    const redirectUri = query.get('redirect_uri') ?? fail('redirect_uri');
    const challenge = query.get('code_challenge') ?? fail('code_challenge');
    const state = query.get('state') ?? fail('state');
    const resources = query.getAll('resource');
    // Signet: at most one resource per request.
    if (resources.length > 1) fail('more than one resource');
    const scopes = (query.get('scope') ?? '').split(' ').filter(Boolean);
    return { challenge, redirectUri, resource: resources[0], scopes, state };
  };

  return {
    authorize: (authorizationUrl, grant = {}) => {
      const request = read(authorizationUrl);
      const code = randomBytes(16).toString('base64url');
      codes.set(code, {
        challenge: request.challenge,
        grant: {
          claims: grant.claims ?? {},
          scopes: grant.scopes ?? request.scopes,
          subject: grant.subject ?? 'test-user',
        },
        redirectUri: request.redirectUri,
        resource: request.resource,
      });
      const back = new URL(request.redirectUri);
      back.searchParams.set('code', code);
      back.searchParams.set('state', request.state);
      return back.toString();
    },
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await keys.close();
    },
    deny: (authorizationUrl, error = 'access_denied') => {
      const request = read(authorizationUrl);
      const back = new URL(request.redirectUri);
      back.searchParams.set('error', error);
      back.searchParams.set('state', request.state);
      return back.toString();
    },
    discovery: (document) => {
      discoveryOverride = document;
    },
    issuer,
    jwksUri: keys.keys.url,
    scriptTokenEndpoint: (next) => {
      script = next;
    },
    sign: (payload) => keys.sign(payload),
    tokenRequests: () => [...received],
  };
}
