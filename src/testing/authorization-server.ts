import { createHash, randomBytes } from 'node:crypto';
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http';
import { type AddressInfo } from 'node:net';

import { type JWTPayload } from 'jose';

import { startTestIssuer } from './signet-token';

// An authorization server for login-flow tests: discovery, and a token
// endpoint that holds each code it issued to the PKCE challenge and redirect
// URI it was issued for, checks the client against `clientId`, and redeems a
// code once. The JWKS is served by a separate test issuer (`jwksUri`). Real
// HTTP on 127.0.0.1, so the flow's own fetches, timeouts and redirects are
// what is exercised.
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

// One member of a script union, with every other member's keys forbidden,
// so `{ body, status }` is a type error rather than a silent pick.
type Exclusive<T extends object, K extends PropertyKey> = T & {
  readonly [P in Exclude<K, keyof T>]?: never;
};

type TokenScriptKey = 'body' | 'error' | 'hang' | 'location' | 'status';

// The token endpoint's answer while a script is set, whatever the request:
//   { status, error? }      that status, with an OAuth `error` body if given
//   { body }                200 with this JSON body (e.g. no access_token)
//   { hang: true }          no answer at all, until close()
//   { hang: 'body' }        200 and its headers, then a body that never ends
//   { status: 307, location }  a redirect, which the flow must not follow
export type TokenEndpointScript =
  | Exclusive<{ readonly body: unknown }, TokenScriptKey>
  | Exclusive<
      { readonly error?: string; readonly status: number },
      TokenScriptKey
    >
  | Exclusive<{ readonly hang: 'body' | true }, TokenScriptKey>
  | Exclusive<
      { readonly location: string; readonly status: 307 | 308 },
      TokenScriptKey
    >;

type DiscoveryScriptKey = 'document' | 'hang' | 'raw' | 'status';

// Discovery's answer while an override is set:
//   { document }        200 with this document instead of the server's own
//   { status }          that status, empty body
//   { raw }             200 with this exact body (e.g. not JSON)
//   { hang: true }      no answer at all, until close()
//   { hang: 'body' }    200 and its headers, then a body that never ends
export type DiscoveryScript =
  | Exclusive<
      { readonly document: Record<string, unknown> },
      DiscoveryScriptKey
    >
  | Exclusive<{ readonly status: number }, DiscoveryScriptKey>
  | Exclusive<{ readonly raw: string }, DiscoveryScriptKey>
  | Exclusive<{ readonly hang: 'body' | true }, DiscoveryScriptKey>;

export interface TestAuthorizationServer {
  readonly authorize: (authorizationUrl: string, grant?: TestGrant) => string;
  readonly close: () => Promise<void>;
  readonly deny: (authorizationUrl: string, error?: string) => string;
  // How many discovery requests arrived.
  readonly discoveryRequests: () => number;
  readonly issuer: string;
  readonly jwksUri: string;
  // Replaces discovery's answer; null restores the server's own document.
  readonly overrideDiscovery: (script: DiscoveryScript | null) => void;
  // Back to a fresh server: no scripts, no override, nothing received.
  // Issued codes are kept; they are single-use anyway.
  readonly reset: () => void;
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
  let discoveryScript: DiscoveryScript | null = null;
  let discoveryCount = 0;
  let issuer = '';

  // Serialised before the head is written, so a body that cannot be
  // serialised fails before anything was sent.
  const json = (response: ServerResponse, status: number, body: unknown) => {
    const text = JSON.stringify(body) ?? '';
    response.writeHead(status, { 'content-type': 'application/json' });
    response.end(text);
  };

  const stall = (response: ServerResponse, hang: 'body' | true) => {
    if (hang === 'body') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.write('{"partial":');
    }
  };

  const token = async (request: IncomingMessage, response: ServerResponse) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(chunk as Buffer);
    const form = Object.fromEntries(
      new URLSearchParams(Buffer.concat(chunks).toString('utf8')),
    );
    received.push(form);
    if (script !== null) {
      if (script.location !== undefined) {
        response.writeHead(script.status, { location: script.location });
        response.end();
        return;
      }
      if (script.hang !== undefined) return stall(response, script.hang);
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
      discoveryCount += 1;
      const override = discoveryScript;
      if (override?.hang !== undefined) return stall(response, override.hang);
      if (override?.raw !== undefined) {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(override.raw);
        return;
      }
      if (override?.status !== undefined) {
        response.writeHead(override.status);
        response.end();
        return;
      }
      return json(
        response,
        200,
        override?.document ?? {
          authorization_endpoint: `${issuer}/oauth2/auth`,
          code_challenge_methods_supported: ['S256'],
          issuer,
          jwks_uri: keys.keys.url,
          token_endpoint: `${issuer}/oauth2/token`,
        },
      );
    }
    if (request.method === 'POST' && path === '/oauth2/token') {
      // A failure here is the test server's own bug: said out loud, not
      // folded into a 500 the flow would read as the issuer's.
      token(request, response).catch((error: unknown) => {
        console.error(
          'test authorization server: token endpoint failed',
          error,
        );
        if (response.headersSent) response.destroy();
        else json(response, 500, {});
      });
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
    discoveryRequests: () => discoveryCount,
    issuer,
    jwksUri: keys.keys.url,
    overrideDiscovery: (next) => {
      discoveryScript = next;
    },
    reset: () => {
      script = null;
      discoveryScript = null;
      discoveryCount = 0;
      received.length = 0;
    },
    scriptTokenEndpoint: (next) => {
      script = next;
    },
    sign: (payload) => keys.sign(payload),
    tokenRequests: () => [...received],
  };
}
