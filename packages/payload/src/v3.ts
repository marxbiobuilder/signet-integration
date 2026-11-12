import { randomUUID } from 'node:crypto';

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

import { createNativeSessions, SESSION_COLLECTION } from './native-session.js';
import { createLogin } from './login.js';
import { inspectRpc, observeRpc, rpcMethod } from './rpc-audit.js';

export type * from './types.js';

class ResourceError extends Error {
  constructor(
    readonly status: 401 | 403 | 503,
    readonly requiredScopes: readonly string[] = [],
    readonly invalidToken = false,
    readonly detail?: string,
  ) {
    super('Xignet resource request refused');
    this.name = 'XignetResourceError';
  }
}

type Principal = {
  readonly requestId: string;
  readonly identity: VerifiedIdentity;
  readonly user: TypedUser;
  readonly rpc: {
    outcome?: 'success' | 'failed' | 'denied' | 'partial_failure';
  };
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
    login: input.login
      ? Object.freeze({
          ...input.login,
          scopes: Object.freeze([...input.login.scopes]),
          session: Object.freeze({ ...input.login.session }),
        })
      : undefined,
    admissionScopes: Object.freeze([...input.admissionScopes]),
  });
  const enabled = input.mcp.enabled;
  const writesEnabled = input.mcp.writesEnabled !== false;
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

  const audit = (
    req: PayloadRequest,
    operation: string,
    target: string,
    outcome: string,
  ) => {
    const p = principal(req);
    if (req.payloadAPI !== 'MCP' || !p) return;
    req.payload.logger.info({
      event: 'xignet_mcp_operation',
      requestId: p.requestId,
      issuer: p.identity.issuer,
      subject: p.identity.subject,
      clientId: p.identity.clientId,
      userId: p.user.id,
      operation,
      target,
      outcome,
    });
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
          (operation !== 'find' && !writesEnabled) ||
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
      const allowed = existing ? await existing(args) : Boolean(args.req.user);
      if (args.req.payloadAPI === 'MCP' && allowed === false) {
        const p = principal(args.req);
        if (p) p.rpc.outcome = 'denied';
      }
      return allowed;
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
        !writesEnabled ||
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
      if (required === false) {
        p.rpc.outcome = 'denied';
        audit(args.req, operation, 'mutation', 'denied_by_policy');
        throw new APIError('MCP mutation refused', 403);
      }
      validateScopes(required);
      if (
        !hasAllScopes(p.identity, [...options.admissionScopes, ...required])
      ) {
        p.rpc.outcome = 'denied';
        audit(args.req, operation, 'mutation', 'insufficient_scope');
        throw new APIError('MCP scope insufficient', 403);
      }
      return args.data;
    };

  const settings = (p: Principal): MCPAccessSettings => {
    const result: MCPAccessSettings = { user: p.user };
    for (const [slug, policy] of entries) {
      result[camelCase(slug)] = Object.fromEntries([
        ...operations.map((op) => [
          op,
          Boolean(
            (op === 'find' || writesEnabled) &&
            policy[op] &&
            hasAllScopes(p.identity, policy[op]!.scopes),
          ),
        ]),
        ['delete', false],
      ]);
    }
    return result;
  };

  const authenticate = async (
    req: PayloadRequest,
    requestId: string,
  ): Promise<Principal> => {
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
        verified.reason,
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
    req.user = { ...resolved.user, _strategy: 'xignet-mcp' };
    const marker = Object.freeze({});
    const p = Object.freeze({
      requestId,
      identity: verified.identity,
      user: req.user,
      rpc: {},
    });
    principals.set(marker, p);
    req.context = { ...req.context, [contextKey]: marker };
    return p;
  };

  const sessions = createNativeSessions(options);
  const login = createLogin(options, sessions);
  const tools = new Map<
    string,
    {
      readonly target: string;
      readonly scopes: readonly string[];
      readonly operation: MCPOperation;
    }
  >();
  for (const [kind, policies] of [
    ['collection', collections],
    ['global', globals],
  ] as const)
    for (const [slug, policy] of Object.entries(policies))
      for (const op of operations)
        if (policy[op]) {
          const name = `${op}${slug.charAt(0).toUpperCase()}${camelCase(slug).slice(1)}`;
          tools.set(name, {
            target: `${kind}:${slug}`,
            scopes: policy[op]!.scopes,
            operation: op,
          });
        }
  const toolResponse = (
    response: { content: Array<{ text: string; type: string }> },
    doc: Record<string, unknown>,
    req: PayloadRequest,
    collection = true,
  ) => {
    const p = principal(req);
    if (p) {
      // Only collection bulk result envelopes carry operation errors.
      // Single documents always have an ID; globals cannot be bulk updated.
      const bulk = collection && !('id' in doc) && Array.isArray(doc.docs);
      const hasErrors =
        bulk && Array.isArray(doc.errors) && doc.errors.length > 0;
      const hasSuccesses = Array.isArray(doc.docs) && doc.docs.length > 0;
      if (hasErrors && hasSuccesses) p.rpc.outcome = 'partial_failure';
      else if (p.rpc.outcome !== 'denied')
        p.rpc.outcome =
          hasErrors || !Object.keys(doc).length ? 'failed' : 'success';
    }
    return response;
  };
  return {
    ...login,
    loginEnabled: options.login?.enabled === true,
    revokeUserSessions: sessions.revokeUserSessions,
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
      if ((config.collections ?? []).some((c) => c.slug === SESSION_COLLECTION))
        throw new Error('Reserved Xignet session collection already exists');
      config.collections = [
        ...(config.collections ?? []).map((c) =>
          c.slug === options.userCollection ? sessions.enhanceUser(c) : c,
        ),
        sessions.collection,
      ];
      const mcpOptions: MCPPluginConfig = {
        disabled: !enabled,
        userCollection: options.userCollection,
        collections: Object.fromEntries(
          Object.entries(collections).map(([slug, p]) => [
            slug,
            {
              overrideResponse: toolResponse,
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
            {
              enabled: { find: Boolean(p.find), update: Boolean(p.update) },
              overrideResponse: (response, doc, req) =>
                toolResponse(response, doc, req, false),
            },
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
              ...(c.hooks?.beforeChange ?? []),
              ...(p?.mutationPolicy ? [guardMutation(p)] : []),
            ],
            afterOperation: [
              ...(c.hooks?.afterOperation ?? []),
              (args) => {
                audit(
                  args.req,
                  args.operation,
                  `collection:${c.slug}`,
                  args.result &&
                    typeof args.result === 'object' &&
                    !('id' in args.result) &&
                    'docs' in args.result &&
                    Array.isArray(args.result.docs) &&
                    'errors' in args.result &&
                    Array.isArray(args.result.errors) &&
                    args.result.errors.length
                    ? 'partial_failure'
                    : 'success',
                );
                return args.result;
              },
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
              ...(g.hooks?.beforeChange ?? []),
              ...(p?.mutationPolicy ? [guardMutation(p)] : []),
            ],
            afterRead: [
              ...(g.hooks?.afterRead ?? []),
              (args) => {
                audit(args.req, 'find', `global:${g.slug}`, 'success');
                return args.doc;
              },
            ],
            afterChange: [
              ...(g.hooks?.afterChange ?? []),
              (args) => {
                audit(args.req, 'update', `global:${g.slug}`, 'success');
                return args.doc;
              },
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
                const requestId = randomUUID();
                try {
                  req.payloadAPI = 'MCP';
                  const p = await authenticate(req, requestId);
                  const rpc = req.clone
                    ? await inspectRpc(req.clone())
                    : undefined;
                  const method = rpcMethod(rpc?.method);
                  const name =
                    rpc?.params &&
                    typeof rpc.params === 'object' &&
                    'name' in rpc.params
                      ? rpc.params.name
                      : undefined;
                  const tool =
                    typeof name === 'string' ? tools.get(name) : undefined;
                  const target = tool?.target;
                  if (
                    tool &&
                    (!hasAllScopes(p.identity, tool.scopes) ||
                      (tool.operation !== 'find' && !writesEnabled))
                  )
                    p.rpc.outcome = 'denied';
                  const response = await endpoint.handler(req);
                  const body = observeRpc(response, (reply, completed) => {
                    const isError =
                      reply?.error ||
                      (reply?.result &&
                        typeof reply.result === 'object' &&
                        'isError' in reply.result &&
                        reply.result.isError === true);
                    let outcome = 'unobserved';
                    if (rpc && completed) {
                      if (p.rpc.outcome === 'denied') outcome = 'denied';
                      else if (isError || response.status >= 400)
                        outcome = 'failed';
                      else if (p.rpc.outcome) outcome = p.rpc.outcome;
                      else if (reply?.result && method !== 'tools/call')
                        outcome = 'success';
                    }
                    audit(
                      req,
                      method,
                      target ??
                        (method === 'tools/call' ? 'unknown_tool' : 'protocol'),
                      outcome,
                    );
                  });
                  audit(
                    req,
                    'request',
                    options.resource,
                    `http_${response.status}`,
                  );
                  const headers = new Headers(response.headers);
                  headers.set('cache-control', 'no-store');
                  headers.set('x-request-id', requestId);
                  return new Response(body, {
                    status: response.status,
                    statusText: response.statusText,
                    headers,
                  });
                } catch (error) {
                  req.payload.logger.warn({
                    event: 'xignet_mcp_request_failed',
                    requestId,
                    resource: options.resource,
                    status: error instanceof ResourceError ? error.status : 500,
                    category: error instanceof Error ? error.name : 'unknown',
                    ...(error instanceof ResourceError
                      ? { detail: error.detail }
                      : {}),
                  });
                  if (!(error instanceof ResourceError)) throw error;
                  const headers = new Headers({
                    'cache-control': 'no-store',
                    'x-request-id': requestId,
                  });
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
