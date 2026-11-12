import type { Config, Plugin, TypedUser } from 'payload';

import {
  createManagedUsers,
  type ManagedUsersOptions,
} from './managed-users.js';
import { createXignetPayload } from './v3.js';
import type {
  XignetPayloadIntegration,
  XignetPayloadOptions,
} from './types.js';

/** The production AS currently advertises this issuer in discovery and tokens. */
export const XIGNET_PROVIDER = Object.freeze({
  issuer: 'https://signet.marxbio.tech',
  jwksUri: 'https://signet.marxbio.tech/.well-known/jwks.json',
});

export type XignetPluginOptions<TUser extends TypedUser = TypedUser> = Omit<
  XignetPayloadOptions<TUser>,
  'issuer' | 'jwksUri' | 'resolveUser' | 'sessionAuthentication'
> & {
  /** Explicit override for tests or a self-hosted Xignet AS. */
  readonly provider?: { readonly issuer: string; readonly jwksUri: string };
  readonly users: ManagedUsersOptions<TUser>;
  readonly admin?: { readonly loginPath?: string; readonly label?: string };
};
export type XignetPlugin = Plugin & XignetPayloadIntegration;

/** A standard Payload plugin with managed bindings and Xignet-only sessions. */
export function xignetPlugin<TUser extends TypedUser>(
  input: XignetPluginOptions<TUser>,
): XignetPlugin {
  const userCollection = input.userCollection;
  const loginLabel = input.admin?.label ?? 'Sign in with Xignet';
  const provider = Object.freeze({ ...(input.provider ?? XIGNET_PROVIDER) });
  const managed = createManagedUsers({
    ...provider,
    userCollection,
    policy: Object.freeze({
      ...input.users,
      revokeOnFields: Object.freeze([...(input.users.revokeOnFields ?? [])]),
    }),
    revoke: (args): Promise<void> => integration.revokeUserSessions(args),
  });
  const integration: XignetPayloadIntegration = createXignetPayload({
    ...input,
    ...provider,
    sessionAuthentication: 'xignet-only',
    resolveUser: managed.resolveUser,
  });
  const apply = integration.plugin();
  const loginPath = input.admin?.loginPath ?? '/auth/xignet/login';
  if (
    !loginPath.startsWith('/') ||
    loginPath.startsWith('//') ||
    new URL(loginPath, 'https://cms.invalid').origin !== 'https://cms.invalid'
  )
    throw new Error('Xignet loginPath must be a local absolute path');
  const plugin: Plugin = async (config: Config) => {
    const enhanced = await apply({
      ...config,
      collections: (config.collections ?? []).map((collection) =>
        collection.slug === userCollection
          ? managed.enhanceUser(collection)
          : collection,
      ),
    });
    enhanced.admin = {
      ...enhanced.admin,
      components: {
        ...enhanced.admin?.components,
        beforeLogin: [
          ...(enhanced.admin?.components?.beforeLogin ?? []),
          {
            path: '@xignet/payload/components#XignetLogin',
            serverProps: {
              enabled: integration.loginEnabled,
              loginPath,
              label: loginLabel,
            },
          },
        ],
      },
    };
    return enhanced;
  };
  return Object.assign(plugin, integration, { plugin: () => plugin });
}

export type { ManagedUsersOptions } from './managed-users.js';
