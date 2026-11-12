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
  userCollection,
  policy,
  revoke,
}: {
  issuer: string;
  userCollection: string;
  policy: ManagedUsersOptions<TUser>;
  revoke: XignetPayloadIntegration['revokeUserSessions'];
}) {
  const changedFields = [
    ...new Set([
      'xignetIssuer',
      'xignetSubject',
      'xignetEnabled',
      ...(policy.revokeOnFields ?? []),
    ]),
  ];
  const resolveUser: ResolveUser<TUser> = async ({ identity, payload }) => {
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
      xignetEnabled?: boolean;
    };
    if (!user.xignetEnabled) return { status: 'denied', reason: 'disabled' };
    if (!(await policy.allowUser(user)))
      return { status: 'denied', reason: 'not_allowed' };
    return { status: 'allowed', user: { ...user, collection: userCollection } };
  };

  const enhanceUser = (config: CollectionConfig): CollectionConfig => {
    const reserved = ['xignetIssuer', 'xignetSubject', 'xignetEnabled'];
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
            description:
              'The approved Xignet subject. Required when creating a user.',
          },
          access: { read: access, create: access, update: access },
        },
        {
          name: 'xignetEnabled',
          type: 'checkbox',
          defaultValue: true,
          label: 'Enable Xignet access',
          access: { read: access, create: access, update: access },
        },
      ],
      hooks: {
        ...config.hooks,
        beforeValidate: [
          ...(config.hooks?.beforeValidate ?? []),
          async ({ data, originalDoc, operation, req }) => {
            if (!data) return data;
            for (const field of reserved)
              if (data[field] === undefined) delete data[field];
            for (const field of ['xignetIssuer', 'xignetSubject'])
              if (
                data[field] !== undefined &&
                data[field] !== null &&
                typeof data[field] !== 'string'
              )
                throw new APIError(`${field} must be a string or null`, 400);
            const modifiesBinding = reserved.some(
              (field) =>
                Object.hasOwn(data, field) &&
                data[field] !== originalDoc?.[field],
            );
            if (
              modifiesBinding &&
              req.payloadAPI !== 'local' &&
              !(await policy.canManageBindings(req))
            )
              throw new APIError('Xignet binding management is forbidden', 403);
            const subject = Object.hasOwn(data, 'xignetSubject')
              ? data.xignetSubject
              : originalDoc?.xignetSubject;
            const hasSubject =
              typeof subject === 'string' && subject.trim().length > 0;
            const enabled =
              data.xignetEnabled ?? originalDoc?.xignetEnabled ?? true;
            if (!hasSubject && (operation === 'create' || enabled))
              throw new APIError('An approved Xignet sub is required', 400);
            // Existing namespaces stay stable during unrelated account edits.
            const rebinding =
              hasSubject && subject !== originalDoc?.xignetSubject;
            const expected = hasSubject
              ? rebinding
                ? issuer
                : originalDoc?.xignetIssuer
              : null;
            const supplied = data.xignetIssuer;
            if (
              typeof supplied === 'string' &&
              supplied.trim() &&
              supplied !== expected &&
              supplied !== originalDoc?.xignetIssuer
            )
              throw new APIError('Xignet issuer is managed by the server', 400);
            if (
              hasSubject &&
              (typeof expected !== 'string' || !expected.trim())
            )
              throw new APIError(
                'The existing Xignet binding is incomplete',
                400,
              );
            data.xignetIssuer = expected;
            if (!hasSubject && Object.hasOwn(data, 'xignetSubject'))
              data.xignetSubject = null;
            return data;
          },
        ],
        afterChange: [
          ...(config.hooks?.afterChange ?? []),
          async ({ doc, previousDoc, req }) => {
            if (
              previousDoc &&
              changedFields.some((field) => doc[field] !== previousDoc[field])
            )
              await revoke({ payload: req.payload, userId: doc.id, req });
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
