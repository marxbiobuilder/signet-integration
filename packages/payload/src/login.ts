import { hkdfSync } from 'node:crypto';

import {
  createOidcClient,
  LoginDiscoveryError,
  LoginTransportError,
  OidcError,
  type LoginTransaction,
} from '@xignet/core/oidc';
import { trustedUrl } from '@xignet/core';
import { EncryptJWT, errors, jwtDecrypt } from 'jose';
import {
  APIError,
  commitTransaction,
  createLocalReq,
  getFieldsToSign,
  initTransaction,
  jwtSign,
  type Payload,
  type TypedUser,
} from 'payload';
import { addSessionToUser, generatePayloadCookie } from 'payload/shared';

import {
  SESSION_CLAIM,
  SESSION_COLLECTION,
  type createNativeSessions,
} from './native-session.js';
import type { XignetPayloadOptions } from './types.js';

class LoginTransactionInterrupted extends Error {
  constructor() {
    super('Owned login transaction was interrupted by a nested operation');
    this.name = 'LoginTransactionInterrupted';
  }
}

export function createLogin<TUser extends TypedUser>(
  options: XignetPayloadOptions<TUser>,
  sessions: ReturnType<typeof createNativeSessions<TUser>>,
) {
  const login = options.login;
  const resource = trustedUrl(options.resource, options.allowInsecureLoopback);
  const redirect = login
    ? trustedUrl(login.redirectUri, options.allowInsecureLoopback)
    : undefined;
  if (redirect && redirect.origin !== resource.origin)
    throw new Error('SSO callback must share the CMS resource origin');
  const success = new URL(login?.successRedirect ?? '/admin', resource.origin);
  if (
    success.origin !== resource.origin ||
    (login?.enabled && !login.successRedirect.startsWith('/'))
  )
    throw new Error('SSO successRedirect must be a local absolute path');
  let key: Uint8Array | undefined;
  if (login?.enabled) {
    if (Buffer.byteLength(login.transactionSecret, 'utf8') < 32)
      throw new Error('SSO transactionSecret must be at least 32 random bytes');
    key = new Uint8Array(
      hkdfSync(
        'sha256',
        login.transactionSecret,
        new Uint8Array(),
        '@xignet/payload/v3 transaction',
        32,
      ),
    );
  }
  const oidc = login?.enabled
    ? createOidcClient({
        ...options,
        audience: options.resource,
        clientId: login.clientId,
        redirectUri: login.redirectUri,
        scopes: login.scopes,
        admissionScopes: options.admissionScopes,
      })
    : undefined;
  const cookieName = `xignet_login.${options.userCollection}`;
  const transactionCookie = (value: string, seconds: number) =>
    `${cookieName}=${value}; Path=${redirect!.pathname}; Max-Age=${seconds}; HttpOnly; SameSite=Lax${redirect!.protocol === 'https:' ? '; Secure' : ''}`;

  return {
    async login(request: Request): Promise<Response> {
      if (!oidc || !key) return new Response(null, { status: 404 });
      if (request.method !== 'GET')
        return new Response(null, { status: 405, headers: { allow: 'GET' } });
      const begin = await oidc.begin();
      const sealed = await new EncryptJWT({ transaction: begin.transaction })
        .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
        .setIssuer(resource.origin)
        .setAudience(login!.redirectUri)
        .setIssuedAt()
        .setExpirationTime('600s')
        .encrypt(key);
      return new Response(null, {
        status: 303,
        headers: {
          location: begin.authorizationUrl,
          'set-cookie': transactionCookie(sealed, 600),
          'cache-control': 'no-store',
          'referrer-policy': 'no-referrer',
        },
      });
    },
    async callback(request: Request, payload: Payload): Promise<Response> {
      if (!oidc || !key) return new Response(null, { status: 404 });
      if (request.method !== 'GET')
        return new Response(null, { status: 405, headers: { allow: 'GET' } });
      if (
        !payload.config.serverURL ||
        new URL(payload.config.serverURL).origin !== resource.origin
      )
        throw new Error('SSO Payload provider has the wrong serverURL');
      const headers = new Headers({
        'set-cookie': transactionCookie('', 0),
        'cache-control': 'no-store',
        'referrer-policy': 'no-referrer',
      });
      const req = await createLocalReq({ req: request.clone() }, payload);
      req.payloadAPI = 'REST';
      let ownTransaction = false;
      let ownedTransactionID: string | number | undefined;
      let transactionCompleted = false;
      let createdSession: { sid: string; userId: string | number } | undefined;
      try {
        const values = (request.headers.get('cookie') ?? '')
          .split(';')
          .map((pair) => pair.trim())
          .filter((pair) => pair.startsWith(`${cookieName}=`));
        if (values.length !== 1) throw new OidcError('state_invalid');
        const decrypted = await jwtDecrypt(
          values[0].slice(cookieName.length + 1),
          key,
          {
            keyManagementAlgorithms: ['dir'],
            contentEncryptionAlgorithms: ['A256GCM'],
            issuer: resource.origin,
            audience: login!.redirectUri,
            requiredClaims: ['exp'],
          },
        );
        const result = await oidc.complete({
          callbackUrl: request.url,
          transaction: decrypted.payload
            .transaction as unknown as LoginTransaction,
        });
        const resolved = await options.resolveUser({
          identity: result.identity,
          channel: 'login',
          payload,
          login: { idTokenClaims: result.idTokenClaims },
        });
        if (
          resolved.status !== 'allowed' ||
          resolved.user.collection !== options.userCollection
        )
          throw new APIError('SSO access denied', 403);
        ownTransaction = await initTransaction(req);
        if (ownTransaction) ownedTransactionID = await req.transactionID;
        const collectionConfig =
          payload.collections[options.userCollection].config;
        let user = (await payload.db.findOne({
          collection: options.userCollection,
          req,
          where: { id: { equals: resolved.user.id } },
        })) as TypedUser;
        if (
          !user ||
          (collectionConfig.auth.verify && user._verified !== true) ||
          (user.lockUntil && Date.parse(user.lockUntil) > Date.now())
        )
          throw new APIError('SSO access denied', 403);
        user.collection = options.userCollection;
        for (const hook of collectionConfig.hooks.beforeLogin)
          user =
            (await hook({
              collection: collectionConfig,
              context: req.context,
              req,
              user,
            })) || user;
        if (user.id !== resolved.user.id)
          throw new APIError('SSO user mismatch', 403);
        const ttl = Math.min(sessions.maxAge, sessions.absoluteMaxAge);
        const { sid } = await addSessionToUser({
          collectionConfig: {
            ...collectionConfig,
            auth: { ...collectionConfig.auth, tokenExpiration: ttl },
          },
          payload,
          req,
          user,
        });
        if (!sid) throw new Error('Native Payload SID was not created');
        createdSession = { sid, userId: user.id };
        const signed = await jwtSign({
          fieldsToSign: {
            ...getFieldsToSign({
              collectionConfig,
              user,
              email: user.email ?? '',
              sid,
            }),
            [SESSION_CLAIM]: true,
          },
          secret: payload.secret,
          tokenExpiration: ttl,
        });
        await payload.create({
          collection: SESSION_COLLECTION,
          req,
          overrideAccess: true,
          data: {
            sid,
            resource: options.resource,
            user: user.id,
            absoluteExpiresAt: new Date(
              Date.now() + sessions.absoluteMaxAge * 1000,
            ).toISOString(),
            identity: result.identity,
          },
        });
        user._sid = sid;
        user._strategy = 'local-jwt';
        req.user = user;
        for (const hook of collectionConfig.hooks.afterLogin) {
          user =
            (await hook({
              collection: collectionConfig,
              context: req.context,
              req,
              user,
              token: signed.token,
            })) || user;
          if (user.id !== resolved.user.id)
            throw new APIError('SSO user mismatch', 403);
        }
        // Error responses may only clear the transaction cookie, including
        // when committing the database transaction fails after signing.
        const successHeaders = new Headers(headers);
        successHeaders.append(
          'set-cookie',
          generatePayloadCookie({
            collectionAuthConfig: {
              ...collectionConfig.auth,
              tokenExpiration: ttl,
            },
            cookiePrefix: payload.config.cookiePrefix,
            token: signed.token,
          }),
        );
        successHeaders.set('location', success.toString());
        const response = new Response(null, {
          status: 303,
          headers: successHeaders,
        });
        if (ownTransaction) {
          if (req.transactionID !== ownedTransactionID)
            throw new LoginTransactionInterrupted();
          await commitTransaction(req);
          transactionCompleted = true;
        }
        // Some adapters fulfill commit even if the underlying transaction
        // rolled back. Fresh reads outside req's transaction must confirm
        // both records before the browser receives its authentication cookie.
        const [persistedMetadata, persistedUser] = await Promise.all([
          payload.db.findOne({
            collection: SESSION_COLLECTION,
            where: {
              and: [
                { sid: { equals: sid } },
                { resource: { equals: options.resource } },
                { user: { equals: user.id } },
              ],
            },
          }),
          payload.db.findOne({
            collection: options.userCollection,
            where: { id: { equals: user.id } },
          }),
        ]);
        if (
          !persistedMetadata ||
          !(persistedUser as TypedUser | null)?.sessions?.some(
            (session: { id: string }) => session.id === sid,
          )
        )
          throw new APIError('SSO session persistence failed', 503);
        return response;
      } catch (error) {
        try {
          if (ownTransaction && !transactionCompleted) {
            // Payload's killTransaction swallows adapter rollback errors.
            // This callback owns the transaction and must observe failures.
            try {
              const interrupted = req.transactionID !== ownedTransactionID;
              await payload.db.rollbackTransaction(ownedTransactionID!);
              // Nested Local API operations may call killTransaction first,
              // suppress rollback errors and remove req.transactionID. The
              // adapter cannot establish cleanup success in that case.
              if (interrupted) throw new LoginTransactionInterrupted();
            } finally {
              delete req.transactionID;
            }
          } else if (createdSession)
            await sessions.revokeSession(
              req,
              createdSession.userId,
              createdSession.sid,
            );
        } catch (cleanupError) {
          payload.logger.error({
            event: 'xignet_login_cleanup_failed',
            category:
              cleanupError instanceof Error ? cleanupError.name : 'unknown',
          });
          return Response.json(
            { error: 'login_failed' },
            { status: 503, headers },
          );
        }
        if (
          error instanceof LoginDiscoveryError ||
          error instanceof LoginTransportError
        ) {
          payload.logger.warn({
            event: 'xignet_login_unavailable',
            category: error.name,
            detail: error.detail,
          });
          return Response.json(
            { error: 'verification_unavailable' },
            { status: 503, headers },
          );
        }
        if (
          error instanceof OidcError ||
          error instanceof errors.JOSEError ||
          error instanceof APIError
        ) {
          const status =
            error instanceof OidcError &&
            error.reason === 'verification_unavailable'
              ? 503
              : error instanceof APIError
                ? error.status
                : 401;
          payload.logger.warn({
            event: 'xignet_login_refused',
            category: error.name,
            ...(error instanceof OidcError
              ? { reason: error.reason, detail: error.detail }
              : {}),
          });
          return Response.json(
            {
              error:
                status === 503 ? 'verification_unavailable' : 'login_failed',
            },
            { status, headers },
          );
        }
        // HTTP is the outer boundary: preserve the 500, clear browser state,
        // and log stack locations without an arbitrary exception message.
        const header =
          error instanceof Error
            ? `${error.name}: ${error.message}`
            : undefined;
        const frames =
          error instanceof Error && header && error.stack?.startsWith(header)
            ? error.stack.slice(header.length)
            : undefined;
        payload.logger.error({
          event: 'xignet_login_failed',
          category: error instanceof Error ? error.name : 'unknown',
          stack: frames,
        });
        return Response.json(
          { error: 'login_failed' },
          { status: 500, headers },
        );
      }
    },
  };
}
