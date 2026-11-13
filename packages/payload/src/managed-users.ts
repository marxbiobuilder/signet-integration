import { randomUUID } from 'node:crypto';
import { canonicalEmail, type DirectoryClient } from '@xignet/client/directory';
import { directoryBindings } from './directory-binding.js';
import {
  APIError,
  type CollectionConfig,
  type PayloadRequest,
  type TypedUser,
} from 'payload';

import type { ResolveUser, XignetPayloadIntegration } from './types.js';

export interface ManagedUsersOptions<TUser extends TypedUser = TypedUser> {
  /** Project policy for the administrators allowed to edit identity bindings. */
  readonly canManageBindings: (
    req: PayloadRequest,
  ) => boolean | Promise<boolean>;
  /** Local account eligibility; the plugin does not assign business roles. */
  readonly allowUser: (user: TUser) => boolean | Promise<boolean>;
  /** Local fields whose changes must revoke SSO sessions, for example role. */
  readonly revokeOnFields?: readonly string[];
}

export function createManagedUsers<TUser extends TypedUser>({
  issuer,
  resource,
  directory,
  userCollection,
  policy,
  revoke,
}: {
  issuer: string;
  resource: string;
  directory?: DirectoryClient;
  userCollection: string;
  policy: ManagedUsersOptions<TUser>;
  revoke: XignetPayloadIntegration['revokeUserSessions'];
}) {
  const bindings = directoryBindings({
    directory,
    issuer,
    collection: userCollection,
    origin: new URL(resource).origin,
    canManage: policy.canManageBindings,
  });
  const changedFields = [
    ...new Set([
      'email',
      'xignetIssuer',
      'xignetSubject',
      ...(policy.revokeOnFields ?? []),
    ]),
  ];
  const resolveUser: ResolveUser<TUser> = async ({
    identity,
    payload,
    channel,
    login,
  }) => {
    if (identity.issuer !== issuer)
      return { status: 'denied', reason: 'not_allowed' };
    const found = await payload.find({
      collection: userCollection,
      overrideAccess: true,
      limit: 2,
      depth: 0,
      where: {
        and: [
          { xignetIssuer: { equals: identity.issuer } },
          { xignetSubject: { equals: identity.subject } },
        ],
      },
    });
    if (!found.docs.length) return { status: 'denied', reason: 'unbound' };
    if (found.docs.length !== 1)
      return { status: 'denied', reason: 'not_allowed' };
    const user = found.docs[0] as unknown as TUser & {
      email?: string;
    };
    if (
      channel === 'login' &&
      (login?.idTokenClaims.email_verified !== true ||
        typeof login.idTokenClaims.email !== 'string' ||
        canonicalEmail(login.idTokenClaims.email) !== user.email)
    )
      return { status: 'denied', reason: 'not_allowed' };
    if (!(await policy.allowUser(user)))
      return { status: 'denied', reason: 'not_allowed' };
    return { status: 'allowed', user: { ...user, collection: userCollection } };
  };

  const enhanceUser = (config: CollectionConfig): CollectionConfig => {
    const reserved = [
      'xignetIssuer',
      'xignetSubject',
      'xignetDirectoryConfirmation',
    ];
    if (
      config.fields.some(
        (field) => 'name' in field && reserved.includes(field.name),
      )
    )
      throw new Error(
        'Managed Xignet identity fields are installed by the plugin',
      );
    const access = ({ req }: { req: PayloadRequest }) =>
      policy.canManageBindings(req);
    return {
      ...config,
      endpoints: [...(config.endpoints || []), bindings.endpoint],
      indexes: [
        ...(config.indexes ?? []),
        {
          fields: ['xignetIssuer', 'xignetSubject'],
          unique: true,
        },
      ],
      fields: [
        ...config.fields,
        {
          name: 'xignetDirectoryConfirmation',
          type: 'text',
          virtual: true,
          access: { read: access, create: access, update: access },
          admin: {
            components: {
              Field: {
                path: '@xignet/payload/client#XignetDirectoryField',
                clientProps: { collection: userCollection },
              },
            },
          },
        },
        {
          name: 'xignetIssuer',
          type: 'text',
          label: 'Xignet issuer',
          admin: {
            readOnly: true,
            description: 'Managed by the Xignet provider configuration.',
          },
          access: { read: access, create: access, update: access },
        },
        {
          name: 'xignetSubject',
          type: 'text',
          label: 'Xignet sub',
          admin: {
            readOnly: true,
            description: '由公司 email 查詢取得的 Xignet 身分。',
          },
          access: { read: access, create: access, update: access },
        },
      ],
      hooks: {
        ...config.hooks,
        beforeValidate: [
          ...(config.hooks?.beforeValidate ?? []),
          async ({ data, originalDoc, operation, req }) => {
            if (!data) return data;
            const trusted = req.payloadAPI === 'local' && !req.user;
            const protectedFields = ['email', ...reserved];
            const changes = protectedFields.some(
              (field) =>
                data[field] !== undefined &&
                data[field] !== originalDoc?.[field],
            );
            if (
              (operation === 'create' || changes) &&
              !trusted &&
              !(await policy.canManageBindings(req))
            )
              throw new APIError('Xignet binding management is forbidden', 403);
            let email: string;
            try {
              email =
                data.email === undefined
                  ? originalDoc?.email
                  : canonicalEmail(data.email);
            } catch {
              throw new APIError('請輸入完整公司 email。', 400, null, true);
            }
            const needsLookup =
              operation === 'create' ||
              email !== originalDoc?.email ||
              !originalDoc?.xignetIssuer ||
              !originalDoc?.xignetSubject ||
              Boolean(data.xignetDirectoryConfirmation);
            if (needsLookup) {
              const identity = await bindings.verify(
                req,
                email,
                data.xignetDirectoryConfirmation,
              );
              if (
                operation !== 'create' &&
                originalDoc?.xignetSubject &&
                (originalDoc.xignetSubject !== identity.sub ||
                  originalDoc.xignetIssuer !== identity.issuer)
              )
                throw new APIError('現有帳號不能改綁另一個 Xignet 身分。', 409);
              for (const [field, value] of Object.entries({
                xignetIssuer: identity.issuer,
                xignetSubject: identity.sub,
              })) {
                if (
                  data[field] != null &&
                  data[field] !== '' &&
                  data[field] !== value
                )
                  throw new APIError(
                    'Xignet identity is managed by Directory',
                    400,
                  );
                data[field] = value;
              }
              data.email = identity.email;
            } else {
              for (const field of ['xignetIssuer', 'xignetSubject'])
                if (
                  data[field] !== undefined &&
                  data[field] !== originalDoc?.[field]
                )
                  throw new APIError(
                    'Xignet identity is managed by Directory',
                    400,
                  );
            }
            delete data.xignetDirectoryConfirmation;
            return data;
          },
        ],
        afterChange: [
          ...(config.hooks?.afterChange ?? []),
          async ({ doc, previousDoc, req, operation }) => {
            if (
              operation === 'update' &&
              previousDoc &&
              changedFields.some((field) => doc[field] !== previousDoc[field])
            )
              await revoke({ payload: req.payload, userId: doc.id, req });
            if (
              operation === 'create' ||
              !previousDoc ||
              changedFields.some((field) => doc[field] !== previousDoc[field])
            )
              req.payload.logger.info({
                event: 'xignet_user_changed',
                outcome: 'applied',
                requestId: req.context.xignetDirectoryRequestId ?? randomUUID(),
                actorId: req.user?.id ?? 'trusted-local',
                userId: doc.id,
                operation,
              });
            return doc;
          },
        ],
        beforeDelete: [
          ...(config.hooks?.beforeDelete ?? []),
          async ({ id, req }) => {
            await revoke({ payload: req.payload, userId: id, req });
          },
        ],
      },
    };
  };
  return { resolveUser, enhanceUser };
}
