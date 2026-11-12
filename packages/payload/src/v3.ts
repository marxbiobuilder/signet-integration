import {
  createTokenVerifier,
  hasAllScopes,
  trustedUrl,
  type VerifiedIdentity,
} from '@xignet/core';
import {
  createBearerChallenge,
  createProtectedResourceMetadata,
  validateScopes,
} from '@xignet/core/oauth';
import {
  mcpPlugin,
  type MCPAccessSettings,
  type MCPPluginConfig,
} from '@payloadcms/plugin-mcp';
import {
  APIError,
  type Access,
  type Config,
  type PayloadRequest,
  type TypedUser,
} from 'payload';

import type {
  EntityPolicy,
  MCPOperation,
  XignetPayloadIntegration,
  XignetPayloadOptions,
} from './types.js';

export type * from './types.js';

class ResourceError extends Error {
  constructor(
    readonly status: 401 | 403 | 503,
    readonly requiredScopes: readonly string[] = [],
    readonly invalidToken = false,
  ) {
    super('Xignet resource request refused');
  }
}

type Principal = {
  readonly identity: VerifiedIdentity;
  readonly user: TypedUser;
};
const operations: readonly MCPOperation[] = ['find', 'create', 'update'];
const camelCase = (slug: string) =>
  slug
    .replace(/[-_\s]+(.)?/g, (_, c: string | undefined) =>
      c ? c.toUpperCase() : '',
    )
    .replace(/^(.)/, (c) => c.toLowerCase());

function snapshot(
  input: Readonly<Record<string, EntityPolicy>> = {},
): Readonly<Record<string, EntityPolicy>> {
  const result: Record<string, EntityPolicy> = Object.create(null);
  for (const [slug, policy] of Object.entries(input)) {
    const saved: EntityPolicy = Object.freeze({
      ...Object.fromEntries(
        operations
          .filter((op) => policy[op] !== undefined)
          .map((op) => {
            const scopes = [...policy[op]!.scopes];
            validateScopes(scopes);
            if (!scopes.length)
              throw new Error('MCP operations require explicit scopes');
            return [op, Object.freeze({ scopes: Object.freeze(scopes) })];
          }),
      ),
      mutationPolicy: policy.mutationPolicy,
    });
    if ((saved.create || saved.update) && !saved.mutationPolicy)
      throw new Error(`MCP writes require mutationPolicy: ${slug}`);
    result[slug] = saved;
  }
  return Object.freeze(result);
}

/** Compose official v3 MCP transport with request-scoped Xignet authorization. */
export function createXignetPayload<TUser extends TypedUser>(
  input: XignetPayloadOptions<TUser>,
): XignetPayloadIntegration {
  const options = Object.freeze({
    ...input,
    admissionScopes: Object.freeze([...input.admissionScopes]),
  });
  const enabled = input.mcp.enabled;
  const collections = snapshot(input.mcp.collections);
  const globals = snapshot(input.mcp.globals);
  const entries = [...Object.entries(collections), ...Object.entries(globals)];
  const names = new Set<string>();
  for (const [slug] of entries) {
    const key = camelCase(slug);
    if (
      names.has(key) ||
      [
        'user',
        'auth',
        'config',
        'collections',
        'globals',
        'jobs',
        'custom',
        '__proto__',
        'constructor',
        'prototype',
        'payloadMcpApiKeys',
      ].includes(key)
    )
      throw new Error(`Ambiguous/reserved MCP resource name: ${slug}`);
    names.add(key);
  }
  if (!options.admissionScopes.length)
    throw new Error('MCP requires admissionScopes');
  validateScopes(options.admissionScopes);
  const verifier = createTokenVerifier({
    ...options,
    audience: options.resource,
  });
  const resource = trustedUrl(options.resource, options.allowInsecureLoopback);
  const metadata = createProtectedResourceMetadata({
    resource: options.resource,
    issuer: options.issuer,
    scopesSupported: [
      ...options.admissionScopes,
      ...(input.mcp.scopesSupported ?? []),
      ...entries.flatMap(([, p]) =>
        operations.flatMap((op) => p[op]?.scopes ?? []),
      ),
    ],
    allowInsecureLoopback: options.allowInsecureLoopback,
  });
  // Context is copied by Payload's Local API. Its marker object retains its
  // identity through the shallow copy; JSON from clients cannot forge it.
  const principals = new WeakMap<object, Principal>();
  const contextKey = '__xignetPayloadPrincipal';
  const principal = (req: PayloadRequest): Principal | undefined => {
    const marker: unknown = req.context?.[contextKey];
    if (!marker || typeof marker !== 'object') return undefined;
    const known = principals.get(marker);
    if (
      known &&
      known.user.id === req.user?.id &&
      known.user.collection === req.user?.collection
    )
      return known;
    return undefined;
  };

  const guardAccess =
    (
      existing: Access | undefined,
      policy: EntityPolicy | undefined,
      operation: MCPOperation,
    ): Access =>
    async (args) => {
      if (args.req.payloadAPI === 'MCP') {
        const p = principal(args.req);
        if (
          !p ||
          !policy?.[operation] ||
          !hasAllScopes(p.identity, [
            ...options.admissionScopes,
            ...policy[operation]!.scopes,
          ])
        )
          return false;
      }
      // Payload's default is an authenticated user when no collection access
      // function is configured. Preserve that default for all channels.
      return existing ? existing(args) : Boolean(args.req.user);
    };

  const guardMutation =
    (policy: EntityPolicy) =>
    async (args: {
      req: PayloadRequest;
      data: Record<string, unknown>;
      originalDoc?: Record<string, unknown>;
      operation?: 'create' | 'update';
    }) => {
      if (args.req.payloadAPI !== 'MCP') return args.data;
      const p = principal(args.req);
      const operation = args.operation ?? 'update';
      const op = policy[operation];
      if (
        !p ||
        !op ||
        !policy.mutationPolicy ||
        !hasAllScopes(p.identity, op.scopes)
      )
        throw new APIError('MCP mutation refused', 403);
      const required = await policy.mutationPolicy({
        ...args,
        operation,
        identity: p.identity,
      });
      if (required === false) throw new APIError('MCP mutation refused', 403);
      validateScopes(required);
      if (!hasAllScopes(p.identity, [...options.admissionScopes, ...required]))
        throw new APIError('MCP scope insufficient', 403);
      return args.data;
    };

  const settings = (p: Principal): MCPAccessSettings => {
    const result: MCPAccessSettings = { user: p.user };
    for (const [slug, policy] of entries) {
      result[camelCase(slug)] = Object.fromEntries([
        ...operations.map((op) => [
          op,
          Boolean(policy[op] && hasAllScopes(p.identity, policy[op]!.scopes)),
        ]),
        ['delete', false],
      ]);
    }
    return result;
  };

  const authenticate = async (req: PayloadRequest): Promise<Principal> => {
    // A previous native cookie/API-key identity cannot substitute for Bearer.
    req.user = null;
    const authorization = req.headers.get('authorization');
    const match = authorization?.match(/^Bearer ([^\s,]+)$/i);
    if (!match)
      throw new ResourceError(
        401,
        options.admissionScopes,
        Boolean(authorization),
      );
    const verified = await verifier.verifyAccessToken(match[1]);
    if (!verified.ok)
      throw new ResourceError(
        verified.kind === 'verification_unavailable' ? 503 : 401,
        options.admissionScopes,
        true,
      );
    if (!hasAllScopes(verified.identity, options.admissionScopes))
      throw new ResourceError(403, options.admissionScopes);
    const resolved = await options.resolveUser({
      identity: verified.identity,
      channel: 'mcp',
      payload: req.payload,
    });
    if (resolved.status !== 'allowed') throw new ResourceError(403);
    if (
      !resolved.user ||
      resolved.user.collection !== options.userCollection ||
      !['number', 'string'].includes(typeof resolved.user.id)
    )
      throw new Error(
        'Xignet resolver returned an invalid user collection or ID',
      );
    req.user = resolved.user;
    const marker = Object.freeze({});
    const p = Object.freeze({
      identity: verified.identity,
      user: resolved.user,
    });
    principals.set(marker, p);
    req.context = { ...req.context, [contextKey]: marker };
    return p;
  };

  return {
    metadata: () =>
      enabled
        ? Response.json(metadata, { headers: { 'cache-control': 'no-store' } })
        : new Response(null, { status: 404 }),
    plugin: () => async (config: Config) => {
      const apiPath = `${config.routes?.api ?? '/api'}/mcp`;
      if (resource.pathname !== apiPath)
        throw new Error(`MCP resource path must equal ${apiPath}`);
      if (
        config.serverURL &&
        new URL(config.serverURL).origin !== resource.origin
      )
        throw new Error('MCP resource origin must match serverURL');
      if (
        !(config.collections ?? []).some(
          (c) => c.slug === options.userCollection && c.auth,
        )
      )
        throw new Error('Xignet requires an auth-enabled userCollection');
      for (const slug of Object.keys(collections))
        if (!(config.collections ?? []).some((c) => c.slug === slug))
          throw new Error(`Unknown MCP collection: ${slug}`);
      for (const slug of Object.keys(globals))
        if (!(config.globals ?? []).some((g) => g.slug === slug))
          throw new Error(`Unknown MCP global: ${slug}`);
      const mcpOptions: MCPPluginConfig = {
        disabled: !enabled,
        userCollection: options.userCollection,
        collections: Object.fromEntries(
          Object.entries(collections).map(([slug, p]) => [
            slug,
            {
              enabled: {
                find: Boolean(p.find),
                create: Boolean(p.create),
                update: Boolean(p.update),
                delete: false,
              },
            },
          ]),
        ),
        globals: Object.fromEntries(
          Object.entries(globals).map(([slug, p]) => [
            slug,
            { enabled: { find: Boolean(p.find), update: Boolean(p.update) } },
          ]),
        ),
        overrideAuth: async (req) => {
          const p = principal(req);
          if (!p) throw new APIError('MCP authentication required', 401);
          return settings(p);
        },
        overrideApiKeyCollection: (c) => ({
          ...c,
          admin: { ...c.admin, hidden: true },
          access: {
            read: () => false,
            create: () => false,
            update: () => false,
            delete: () => false,
          },
        }),
      };
      const original = (config.endpoints ?? []).filter(
        (e) => e.path === '/mcp',
      );
      if (original.length)
        throw new Error(
          'Install Xignet MCP once; another /mcp endpoint already exists',
        );
      const result = await mcpPlugin(mcpOptions)(config);
      if (!enabled) return result;
      result.collections = result.collections?.map((c) => {
        const p = collections[c.slug];
        return {
          ...c,
          access: {
            ...c.access,
            read: guardAccess(c.access?.read, p, 'find'),
            create: guardAccess(c.access?.create, p, 'create'),
            update: guardAccess(c.access?.update, p, 'update'),
            delete: async (args) =>
              args.req.payloadAPI === 'MCP'
                ? false
                : c.access?.delete
                  ? c.access.delete(args)
                  : Boolean(args.req.user),
            readVersions: guardAccess(c.access?.readVersions, p, 'find'),
          },
          hooks: {
            ...c.hooks,
            beforeChange: [
              ...(p?.mutationPolicy ? [guardMutation(p)] : []),
              ...(c.hooks?.beforeChange ?? []),
            ],
          },
        };
      });
      result.globals = result.globals?.map((g) => {
        const p = globals[g.slug];
        return {
          ...g,
          access: {
            ...g.access,
            read: guardAccess(g.access?.read, p, 'find'),
            update: guardAccess(g.access?.update, p, 'update'),
            readVersions: guardAccess(g.access?.readVersions, p, 'find'),
          },
          hooks: {
            ...g.hooks,
            beforeChange: [
              ...(p?.mutationPolicy ? [guardMutation(p)] : []),
              ...(g.hooks?.beforeChange ?? []),
            ],
          },
        };
      });
      result.endpoints = result.endpoints?.map((endpoint) =>
        endpoint.path !== '/mcp'
          ? endpoint
          : {
              ...endpoint,
              handler: async (req) => {
                try {
                  req.payloadAPI = 'MCP';
                  await authenticate(req);
                  return await endpoint.handler(req);
                } catch (error) {
                  if (!(error instanceof ResourceError)) throw error;
                  const headers = new Headers({ 'cache-control': 'no-store' });
                  if (
                    error.status !== 503 &&
                    (error.status === 401 || error.requiredScopes.length)
                  )
                    headers.set(
                      'WWW-Authenticate',
                      createBearerChallenge({
                        resource: options.resource,
                        requiredScopes: error.requiredScopes,
                        error:
                          error.status === 403
                            ? 'insufficient_scope'
                            : error.invalidToken
                              ? 'invalid_token'
                              : undefined,
                      }),
                    );
                  return Response.json(
                    {
                      error:
                        error.status === 503
                          ? 'verification_unavailable'
                          : error.status === 401
                            ? 'unauthorized'
                            : 'forbidden',
                    },
                    { status: error.status, headers },
                  );
                }
              },
            },
      );
      return result;
    },
  };
}
