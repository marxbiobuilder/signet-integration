import { createHash, randomUUID } from 'node:crypto';
import { jwtVerify, SignJWT } from 'jose';
import { APIError, type Endpoint, type PayloadRequest } from 'payload';
import {
  canonicalEmail,
  DirectoryError,
  type DirectoryClient,
  type DirectoryIdentity,
} from '@xignet/client/directory';

import { directoryMessages as messages } from './directory-messages.js';

export function directoryBindings({
  directory,
  issuer,
  collection,
  origin,
  canManage,
}: {
  directory?: DirectoryClient;
  issuer: string;
  collection: string;
  origin: string;
  canManage(req: PayloadRequest): boolean | Promise<boolean>;
}) {
  const key = (req: PayloadRequest) =>
    createHash('sha256')
      .update(`xignet-directory-confirmation:${req.payload.secret}`)
      .digest();
  async function resolve(
    req: PayloadRequest,
    email: string,
    operation: 'preview' | 'save',
  ): Promise<DirectoryIdentity> {
    const requestId = randomUUID();
    req.context.xignetDirectoryRequestId = requestId;
    const audit = {
      event: 'xignet_directory_lookup',
      requestId,
      operation,
      actorId: req.user?.id ?? 'trusted-local',
    };
    try {
      if (!directory) throw new DirectoryError('unavailable');
      const identity = await directory.resolve(canonicalEmail(email), {
        requestId,
      });
      if (
        identity.issuer !== issuer ||
        identity.email !== canonicalEmail(email) ||
        !identity.sub ||
        identity.sub.startsWith('service:')
      )
        throw new DirectoryError('invalid_response');
      req.payload.logger.info({ ...audit, outcome: 'success' });
      return identity;
    } catch (error) {
      const code =
        error instanceof DirectoryError && Object.hasOwn(messages, error.code)
          ? error.code
          : 'unavailable';
      req.payload.logger.warn({ ...audit, outcome: 'denied', reason: code });
      throw new APIError(
        messages[code],
        code === 'invalid_email'
          ? 400
          : code === 'not_found'
            ? 404
            : code === 'rate_limited'
              ? 429
              : 503,
        { code },
        true,
      );
    }
  }
  const endpoint: Endpoint = {
    path: '/xignet/resolve',
    method: 'post',
    handler: async (req) => {
      if (!req.user || !(await canManage(req)))
        throw new APIError('Forbidden', 403);
      if (req.headers.get('origin') !== origin)
        throw new APIError('Forbidden origin', 403);
      const text = await req.text?.();
      if (!text || text.length > 1024)
        throw new APIError('Invalid lookup request', 400);
      let email: unknown;
      try {
        email = (JSON.parse(text) as { email?: unknown }).email;
      } catch {
        throw new APIError('Invalid lookup request', 400);
      }
      if (typeof email !== 'string') throw new APIError('Invalid email', 400);
      let identity: DirectoryIdentity;
      try {
        identity = await resolve(req, email, 'preview');
      } catch (error) {
        if (!(error instanceof APIError)) throw error;
        return Response.json(
          { error: error.data?.code ?? 'unavailable' },
          {
            status: error.status,
            headers: {
              'cache-control': 'no-store',
              'x-request-id': String(req.context.xignetDirectoryRequestId),
            },
          },
        );
      }
      const confirmation = await new SignJWT({
        identity,
        actor: String(req.user.id),
      })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuer('xignet-directory-confirmation')
        .setAudience(`${origin}/${collection}`)
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(key(req));
      return Response.json(
        { identity, confirmation },
        {
          headers: {
            'cache-control': 'no-store',
            'x-request-id': String(req.context.xignetDirectoryRequestId),
          },
        },
      );
    },
  };
  async function verify(
    req: PayloadRequest,
    email: string,
    confirmation: unknown,
  ) {
    const identity = await resolve(req, email, 'save');
    // Only trusted server-side Local API calls can skip the interactive preview.
    if (req.payloadAPI === 'local' && !req.user) return identity;
    if (!req.user || !(await canManage(req)))
      throw new APIError('Forbidden', 403);
    try {
      if (typeof confirmation !== 'string') throw new Error();
      const { payload } = await jwtVerify(confirmation, key(req), {
        algorithms: ['HS256'],
        issuer: 'xignet-directory-confirmation',
        audience: `${origin}/${collection}`,
        requiredClaims: ['exp', 'iat'],
      });
      const prior = payload.identity as DirectoryIdentity | undefined;
      if (
        payload.actor !== String(req.user.id) ||
        prior?.issuer !== identity.issuer ||
        prior.sub !== identity.sub ||
        prior.email !== identity.email
      )
        throw new Error();
    } catch {
      req.payload.logger.warn({
        event: 'xignet_directory_confirmation_rejected',
        requestId: req.context.xignetDirectoryRequestId,
        actorId: req.user.id,
        reason: 'confirmation_invalid',
      });
      throw new APIError('請重新查詢並確認 Xignet 身分後儲存。', 409);
    }
    return identity;
  }
  return { endpoint, verify };
}
