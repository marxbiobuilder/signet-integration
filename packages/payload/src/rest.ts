import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import {
  createTokenVerifier,
  hasAllScopes,
  trustedUrl,
  type VerifiedIdentity,
} from '@xignet/core';
import { validateScopes } from '@xignet/core/oauth';
import type {
  Access,
  Config,
  Payload,
  PayloadRequest,
  TypedUser,
} from 'payload';
import type { XignetPayloadOptions } from './types.js';

export interface RestEntityPolicy {
  readonly read?: readonly string[];
  readonly create?: readonly string[];
  readonly update?: readonly string[];
}
export interface RestOptions {
  readonly enabled: boolean;
  /** Separate audience from MCP, e.g. https://cms.example.com/api. */
  readonly resource: string;
  readonly admissionScopes: readonly string[];
  readonly collections: Readonly<Record<string, RestEntityPolicy>>;
  readonly globals?: Readonly<Record<string, Omit<RestEntityPolicy, 'create'>>>;
  /** Exact custom paths relative to the API root; no wildcard or inherited permission. */
  readonly endpoints?: readonly {
    readonly path: string;
    readonly method: 'GET' | 'POST';
    readonly scopes: readonly string[];
  }[];
  /** Locally approved machine identities. No human user or admin role is assigned. */
  readonly services?: readonly {
    readonly subject: string;
    readonly clientId: string;
  }[];
}
type Principal = { identity: VerifiedIdentity; service: boolean };
const principals = new WeakMap<object, Principal>();
const key = '__xignetRest';
function principal(req: { user?: TypedUser | null }): Principal | undefined {
  const marker = (req.user as unknown as Record<string, unknown> | null)?.[key];
  return marker && typeof marker === 'object'
    ? principals.get(marker)
    : undefined;
}
/** Only true for an authenticated service principal created by this adapter. */
export function isXignetService(req: { user?: TypedUser | null }): boolean {
  return principal(req)?.service === true;
}
class Refused extends Error {
  constructor(
    readonly status: number,
    readonly category:
      'invalid_token' | 'permission_denied' | 'jwks_unavailable' = status ===
    401
      ? 'invalid_token'
      : 'permission_denied',
  ) {
    super('Xignet REST access refused');
  }
}
const bearer = (headers: Headers) =>
  /^Bearer(?:\s|$)/i.test(headers.get('authorization') ?? '');

export function createRest<TUser extends TypedUser>(
  options: XignetPayloadOptions<TUser>,
) {
  const authenticated = new AsyncLocalStorage<{
    authorization: string;
    user: TypedUser;
  }>();
  // Snapshot authorization policy; caller mutation must not expand active grants.
  const rest: RestOptions | undefined =
    options.rest && JSON.parse(JSON.stringify(options.rest));
  const scopes = (value: readonly string[]) => {
    validateScopes(value);
    if (!value.length) throw new Error('REST policy requires explicit scopes');
  };
  if (rest) {
    scopes(rest.admissionScopes);
    for (const policy of [
      ...Object.values(rest.collections),
      ...Object.values(rest.globals ?? {}),
    ])
      for (const value of Object.values(policy)) scopes(value);
    for (const endpoint of rest.endpoints ?? []) {
      if (
        !/^\/[a-zA-Z0-9/_-]+$/.test(endpoint.path) ||
        !['GET', 'POST'].includes(endpoint.method)
      )
        throw new Error(
          'REST custom endpoint requires an exact path and method',
        );
      scopes(endpoint.scopes);
    }
    for (const service of rest.services ?? [])
      if (
        !service.subject.startsWith('service:') ||
        service.subject !== service.clientId
      )
        throw new Error(
          'Xignet service subject must equal its service client ID',
        );
    const resource = trustedUrl(rest.resource, options.allowInsecureLoopback);
    if (
      resource.origin !== new URL(options.resource).origin ||
      rest.resource === options.resource
    )
      throw new Error('REST requires a separate audience on the CMS origin');
  }
  const verifier =
    rest && createTokenVerifier({ ...options, audience: rest.resource });
  function route(request: Request): readonly string[] | undefined {
    if (!rest) return;
    const path = new URL(request.url).pathname;
    const root = new URL(rest.resource).pathname;
    if (!path.startsWith(`${root}/`) || /%|\\|\/\//.test(path)) return;
    const relative = path.slice(root.length);
    const endpoint = rest.endpoints?.find(
      (e) => e.path === relative && e.method === request.method,
    );
    if (endpoint) return endpoint.scopes;
    const parts = relative.slice(1).split('/');
    if (parts[0] === 'globals' && parts.length === 2) {
      const policy = rest.globals?.[parts[1]];
      return request.method === 'GET'
        ? policy?.read
        : request.method === 'POST'
          ? policy?.update
          : undefined;
    }
    const policy = rest.collections[parts[0]];
    if (!policy || (parts.length !== 1 && parts.length !== 2)) return;
    // Only native document IDs. Excludes auth, versions, access and custom routes.
    if (
      parts.length === 2 &&
      !/^(?:[0-9]+|[a-fA-F0-9]{24}|[a-fA-F0-9-]{36})$/.test(parts[1])
    )
      return;
    if (request.method === 'GET') return policy.read;
    if (parts.length === 1 && request.method === 'POST') return policy.create;
    if (parts.length === 2 && request.method === 'PATCH') return policy.update;
  }
  async function authenticate(headers: Headers, payload: Payload) {
    if (!rest?.enabled || !verifier) throw new Refused(401);
    const token = headers
      .get('authorization')
      ?.match(/^Bearer ([^\s,]+)$/i)?.[1];
    if (!token) throw new Refused(401);
    const verified = await verifier.verifyAccessToken(token);
    if (!verified.ok)
      throw new Refused(
        verified.kind === 'verification_unavailable' ? 503 : 401,
        verified.kind === 'verification_unavailable'
          ? 'jwks_unavailable'
          : 'invalid_token',
      );
    const identity = verified.identity;
    if (!hasAllScopes(identity, rest.admissionScopes)) throw new Refused(403);
    const service = identity.subject.startsWith('service:');
    let user: TypedUser;
    if (service) {
      if (
        !rest.services?.some(
          (s) =>
            s.subject === identity.subject && s.clientId === identity.clientId,
        )
      )
        throw new Refused(403);
      user = {
        id: identity.subject,
        collection: 'xignet-services',
      } as TypedUser;
    } else {
      const resolved = await options.resolveUser({
        identity,
        channel: 'rest',
        payload,
      });
      if (
        resolved.status !== 'allowed' ||
        resolved.user.collection !== options.userCollection
      )
        throw new Refused(403);
      user = resolved.user;
    }
    const marker = Object.freeze({});
    principals.set(marker, { identity, service });
    return { ...user, _strategy: 'xignet-rest', [key]: marker } as TypedUser;
  }
  const guard =
    (existing: Access | undefined, required?: readonly string[]): Access =>
    async (args) => {
      const p = principal(args.req);
      if (p && (!required || !hasAllScopes(p.identity, required))) return false;
      // Keep all application access filters, including explicit local service policy.
      return existing ? existing(args) : Boolean(args.req.user);
    };
  return {
    async handle(
      request: Request,
      payload: Payload,
      next: () => Promise<Response>,
    ): Promise<Response> {
      // MCP owns its own Bearer validation and audience.
      if (
        !bearer(request.headers) ||
        new URL(request.url).pathname === new URL(options.resource).pathname
      )
        return next();
      const requestId = randomUUID();
      let user: TypedUser;
      try {
        user = await authenticate(request.headers, payload);
        const required = route(request);
        if (!required || !hasAllScopes(principal({ user })!.identity, required))
          throw new Refused(403);
      } catch (error) {
        const status = error instanceof Refused ? error.status : 503;
        const category =
          error instanceof Refused
            ? error.category
            : 'authentication_internal_error';
        const entry = {
          event: 'xignet_rest_denied',
          requestId,
          status,
          category,
        };
        if (status === 503) payload.logger.error(entry);
        else payload.logger.info(entry);
        return Response.json(
          {
            error:
              status === 503
                ? 'authentication_unavailable'
                : status === 401
                  ? 'invalid_token'
                  : 'insufficient_permission',
          },
          {
            status,
            headers: {
              'cache-control': 'no-store',
              'x-request-id': requestId,
              ...(status === 401
                ? { 'www-authenticate': 'Bearer error="invalid_token"' }
                : {}),
            },
          },
        );
      }
      const response = await authenticated.run(
        { authorization: request.headers.get('authorization')!, user },
        next,
      );
      payload.logger.info({
        event: 'xignet_rest_request',
        requestId,
        method: request.method,
        subject: principal({ user })!.identity.subject,
        clientId: principal({ user })!.identity.clientId,
        status: response.status,
      });
      return response;
    },
    enhance(config: Config): Config {
      if (!rest?.enabled) return config;
      if (new URL(rest.resource).pathname !== (config.routes?.api ?? '/api'))
        throw new Error('REST resource must equal the Payload API root');
      for (const slug of Object.keys(rest.collections)) {
        const collection = config.collections?.find((c) => c.slug === slug);
        if (!collection || collection.auth)
          throw new Error(
            `REST requires a non-auth content collection: ${slug}`,
          );
      }
      for (const slug of Object.keys(rest.globals ?? {}))
        if (!config.globals?.some((g) => g.slug === slug))
          throw new Error(`Unknown REST global: ${slug}`);
      return {
        ...config,
        collections: config.collections?.map((c) => ({
          ...c,
          ...(c.slug === options.userCollection
            ? {
                auth: {
                  ...(typeof c.auth === 'object' ? c.auth : {}),
                  strategies: [
                    {
                      name: 'xignet-rest',
                      authenticate: async ({
                        headers,
                        payload,
                        req,
                        isGraphQL,
                      }) => {
                        if (
                          !bearer(headers) ||
                          isGraphQL ||
                          (req &&
                            req.pathname === new URL(options.resource).pathname)
                        )
                          return { user: null };
                        const current = authenticated.getStore();
                        if (
                          current &&
                          current.authorization === headers.get('authorization')
                        )
                          return { user: current.user };
                        try {
                          return { user: await authenticate(headers, payload) };
                        } catch {
                          return { user: null };
                        } // HTTP failures are handled before Payload dispatch by handle().
                      },
                    },
                    ...(typeof c.auth === 'object'
                      ? (c.auth.strategies ?? [])
                      : []),
                  ],
                },
              }
            : {}),
          access: {
            ...c.access,
            read: guard(c.access?.read, rest.collections[c.slug]?.read),
            create: guard(c.access?.create, rest.collections[c.slug]?.create),
            update: guard(c.access?.update, rest.collections[c.slug]?.update),
            delete: guard(c.access?.delete),
            readVersions: guard(c.access?.readVersions),
          },
        })),
        globals: config.globals?.map((g) => ({
          ...g,
          access: {
            ...g.access,
            read: guard(g.access?.read, rest.globals?.[g.slug]?.read),
            update: guard(g.access?.update, rest.globals?.[g.slug]?.update),
            readVersions: guard(g.access?.readVersions),
          },
        })),
      };
    },
  };
}
