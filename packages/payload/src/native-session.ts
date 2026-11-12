import { type VerifiedIdentity } from '@xignet/core';
import { errors, jwtVerify, type JWTPayload } from 'jose';
import {
  APIError,
  JWT_AUTH_VERSION,
  createLocalReq,
  getFieldsToSign,
  jwtSign,
  type CollectionAfterReadHook,
  type CollectionConfig,
  type CollectionRefreshHook,
  type Payload,
  type PayloadRequest,
  type TypedUser,
} from 'payload';
import { parseCookies } from 'payload/shared';

import type { XignetPayloadOptions } from './types.js';

export const SESSION_COLLECTION = 'xignet-sessions';
export const SESSION_CLAIM = '__xignet_sso';
export type UserID = string | number;
type NativeSessionUser = TypedUser & {
  sessions?: Array<{
    id: string;
    createdAt?: string | Date;
    expiresAt: string | Date;
  }>;
};
export type SessionRecord = {
  id: UserID;
  sid: string;
  resource: string;
  user: UserID;
  absoluteExpiresAt: string;
  identity: VerifiedIdentity;
};

// Match Payload 3.93's credential precedence and CSRF rules. extractJWT is
// not a public export, so the pinned adapter tests native browser auth.
function selectedToken(req: PayloadRequest): string | undefined {
  for (const method of req.payload.config.auth.jwtOrder) {
    if (method === 'Bearer' || method === 'JWT') {
      const header = req.headers.get('authorization');
      if (header?.startsWith(`${method} `))
        return header.slice(method.length + 1);
    } else {
      const token = parseCookies(req.headers).get(
        `${req.payload.config.cookiePrefix}-token`,
      );
      if (!token) continue;
      const origin = req.headers.get('origin');
      const csrf = req.payload.config.csrf;
      if (
        origin
          ? csrf.length === 0 || csrf.includes(origin)
          : csrf.length === 0 ||
            ['same-origin', 'same-site', 'none'].includes(
              req.headers.get('sec-fetch-site') ?? '',
            )
      )
        return token;
    }
  }
  return undefined;
}

async function reference(req: PayloadRequest): Promise<JWTPayload | undefined> {
  const token = selectedToken(req);
  if (!token) return undefined;
  try {
    const result = await jwtVerify(
      token,
      new TextEncoder().encode(req.payload.secret),
      { algorithms: ['HS256'], requiredClaims: ['exp'] },
    );
    return result.protectedHeader.authVersion === JWT_AUTH_VERSION &&
      result.payload[SESSION_CLAIM] === true
      ? result.payload
      : undefined;
  } catch (error) {
    if (error instanceof errors.JOSEError) return undefined;
    throw error;
  }
}

export function createNativeSessions<TUser extends TypedUser>(
  options: XignetPayloadOptions<TUser>,
) {
  const maxAge = options.login?.session.maxAgeSeconds ?? 7200;
  const absoluteMaxAge = options.login?.session.absoluteMaxAgeSeconds ?? 7200;
  if (
    ![maxAge, absoluteMaxAge].every(
      (n) => Number.isInteger(n) && n > 0 && n <= 604800,
    ) ||
    maxAge > absoluteMaxAge
  )
    throw new Error('Invalid SSO session lifetimes');

  const record = async (
    req: PayloadRequest,
    sid: unknown,
  ): Promise<SessionRecord | null> =>
    typeof sid === 'string'
      ? (req.payload.db.findOne({
          collection: SESSION_COLLECTION,
          req,
          where: { sid: { equals: sid } },
        }) as Promise<SessionRecord | null>)
      : null;
  const allowed = async (
    req: PayloadRequest,
    entry: SessionRecord,
    userId: UserID,
  ) => {
    if (
      entry.user !== userId ||
      entry.resource !== options.resource ||
      entry.identity?.issuer !== options.issuer ||
      !Number.isFinite(Date.parse(entry.absoluteExpiresAt)) ||
      Date.parse(entry.absoluteExpiresAt) <= Date.now()
    )
      return false;
    const resolved = await options.resolveUser({
      identity: entry.identity,
      channel: 'session',
      payload: req.payload,
    });
    return (
      resolved.status === 'allowed' &&
      resolved.user.id === userId &&
      resolved.user.collection === options.userCollection
    );
  };

  const collection: CollectionConfig = {
    slug: SESSION_COLLECTION,
    admin: { hidden: true },
    access: {
      create: () => false,
      read: () => false,
      update: () => false,
      delete: () => false,
    },
    fields: [
      { name: 'sid', type: 'text', required: true, unique: true },
      { name: 'resource', type: 'text', required: true },
      {
        name: 'user',
        type: 'relationship',
        relationTo: options.userCollection,
        required: true,
        index: true,
      },
      { name: 'absoluteExpiresAt', type: 'date', required: true, index: true },
      { name: 'identity', type: 'json', required: true },
    ],
  };

  const revokeUserSessions = async ({
    payload,
    userId,
    req: existingReq,
  }: {
    payload: Payload;
    userId: UserID;
    req?: PayloadRequest;
  }) => {
    const req = existingReq ?? (await createLocalReq({}, payload));
    const entries = await payload.find({
      collection: SESSION_COLLECTION,
      req,
      overrideAccess: true,
      pagination: false,
      depth: 0,
      where: { user: { equals: userId } },
    });
    const ids = new Set(entries.docs.map((doc) => doc.sid));
    const user = (await payload.db.findOne({
      collection: options.userCollection,
      req,
      where: { id: { equals: userId } },
    })) as NativeSessionUser | null;
    if (user)
      await payload.db.updateOne({
        collection: options.userCollection,
        id: userId,
        req,
        returning: false,
        data: {
          sessions: (user.sessions ?? []).filter(
            (s: { id: string }) => !ids.has(s.id),
          ),
        },
      });
    await payload.delete({
      collection: SESSION_COLLECTION,
      req,
      overrideAccess: true,
      where: { user: { equals: userId } },
    });
  };

  const revokeSession = async (
    req: PayloadRequest,
    userId: UserID,
    sid: string,
  ) => {
    const current = (await req.payload.db.findOne({
      collection: options.userCollection,
      req,
      where: { id: { equals: userId } },
    })) as NativeSessionUser | null;
    if (current)
      await req.payload.db.updateOne({
        collection: options.userCollection,
        id: userId,
        req,
        returning: false,
        data: {
          sessions: (current.sessions ?? []).filter((s) => s.id !== sid),
        },
      });
    await req.payload.delete({
      collection: SESSION_COLLECTION,
      req,
      overrideAccess: true,
      where: { sid: { equals: sid } },
    });
  };

  const protectSession: CollectionAfterReadHook = async ({ doc, req }) => {
    const ref = await reference(req);
    if (!ref || ref.collection !== options.userCollection || ref.id !== doc.id)
      return doc;
    if (!(doc.sessions ?? []).some((s: { id: string }) => s.id === ref.sid))
      return doc;
    try {
      const entry = await record(req, ref.sid);
      if (entry && (await allowed(req, entry, doc.id))) return doc;
    } catch (error) {
      // Payload's native JWT strategy catches auth failures. Log the service
      // failure here so an outage cannot silently look like an expired login.
      req.payload.logger.error({
        event: 'xignet_session_verification_failed',
        category: error instanceof Error ? error.name : 'unknown',
      });
      throw error;
    }
    // Revocation must survive re-enabling/rebinding the account. Merely
    // filtering this one auth response would let an old cookie revive later.
    await revokeSession(req, doc.id, ref.sid as string);
    req.payload.logger.info({
      event: 'xignet_session_revoked',
      userId: doc.id,
      reason: 'expired_disabled_or_unbound',
    });
    return {
      ...doc,
      sessions: (doc.sessions ?? []).filter(
        (s: { id: string }) => s.id !== ref.sid,
      ),
    };
  };

  const enhanceUser = (config: CollectionConfig): CollectionConfig => {
    const auth = typeof config.auth === 'object' ? config.auth : {};
    if (
      !config.auth ||
      auth.disableLocalStrategy ||
      auth.useSessions === false
    ) {
      if (options.login?.enabled)
        throw new Error('SSO requires native Payload auth with sessions');
      return config;
    }
    const previousRefresh = config.hooks?.refresh ?? [];
    const refresh: CollectionRefreshHook = async (args) => {
      const ref = await reference(args.args.req);
      if (!ref) {
        for (const hook of previousRefresh) {
          const result = await hook(args);
          if (result) return result;
        }
        return;
      }
      const req = args.args.req;
      const entry = await record(req, ref.sid);
      if (!entry || !(await allowed(req, entry, args.user.id)))
        throw new APIError('SSO session expired or revoked', 403);
      let prior;
      for (const hook of previousRefresh) {
        prior = await hook(args);
        if (prior) break;
      }
      const user = prior?.user ?? args.user;
      if (user.id !== entry.user) throw new APIError('SSO user mismatch', 403);
      const ttl = Math.min(
        maxAge,
        Math.floor(Date.parse(entry.absoluteExpiresAt) / 1000) -
          Math.floor(Date.now() / 1000),
      );
      if (ttl < 1) throw new APIError('SSO session expired', 403);
      const signed = await jwtSign({
        fieldsToSign: {
          ...getFieldsToSign({
            collectionConfig: args.args.collection.config,
            user,
            email: user.email,
            sid: entry.sid,
          }),
          [SESSION_CLAIM]: true,
        },
        secret: req.payload.secret,
        tokenExpiration: ttl,
      });
      const current = (await req.payload.db.findOne({
        collection: options.userCollection,
        req,
        where: { id: { equals: user.id } },
      })) as NativeSessionUser | null;
      if (!current?.sessions?.some((s: { id: string }) => s.id === entry.sid))
        throw new APIError('SSO session revoked', 403);
      await req.payload.db.updateOne({
        collection: options.userCollection,
        id: user.id,
        req,
        returning: false,
        data: {
          sessions: current.sessions.map((s: { id: string }) =>
            s.id === entry.sid
              ? { ...s, expiresAt: new Date(signed.exp * 1000) }
              : s,
          ),
        },
      });
      // A refresh hook runs before Payload applies user read/field access.
      return {
        ...prior,
        exp: signed.exp,
        refreshedToken: signed.token,
        user,
        setCookie: true,
      };
    };
    return {
      ...config,
      auth: {
        ...auth,
        useSessions: true,
        cookies: {
          ...auth.cookies,
          ...(options.login?.enabled &&
          new URL(options.resource).protocol === 'https:'
            ? { secure: true }
            : {}),
        },
      },
      hooks: {
        ...config.hooks,
        afterRead: [...(config.hooks?.afterRead ?? []), protectSession],
        refresh: [refresh],
        afterLogout: [
          ...(config.hooks?.afterLogout ?? []),
          async ({ req }) => {
            if (req.user?._sid)
              await req.payload.delete({
                collection: SESSION_COLLECTION,
                req,
                overrideAccess: true,
                where: { sid: { equals: req.user._sid } },
              });
          },
        ],
      },
    };
  };
  return {
    collection,
    revokeSession,
    enhanceUser,
    revokeUserSessions,
    maxAge,
    absoluteMaxAge,
  };
}
