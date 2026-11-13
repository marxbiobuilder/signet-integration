import type { DirectoryClient } from '@xignet/client/directory';
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

/** Default issuer advertised by the production Xignet AS. */
export const XIGNET_PROVIDER = Object.freeze({
  issuer: 'https://xignet.marxbio.tech',
  jwksUri: 'https://xignet.marxbio.tech/.well-known/jwks.json',
});

export type XignetPluginOptions<TUser extends TypedUser = TypedUser> = Omit<
  XignetPayloadOptions<TUser>,
  'issuer' | 'jwksUri' | 'resolveUser' | 'sessionAuthentication'
> & {
  /** Explicit override for tests or a self-hosted Xignet AS. */
  readonly provider?: { readonly issuer: string; readonly jwksUri: string };
  readonly users: ManagedUsersOptions<TUser>;
  /** Server-only directory client. Omit to disable account provisioning. */
  readonly directory?: DirectoryClient;
  readonly admin?: {
    readonly loginPath?: string;
    readonly label?: string | Readonly<Record<string, string>>;
  };
};
export type XignetPlugin = Plugin & XignetPayloadIntegration;

/** A standard Payload plugin with managed bindings and Xignet-only sessions. */
export function xignetPlugin<TUser extends TypedUser>(
  input: XignetPluginOptions<TUser>,
): XignetPlugin {
  const userCollection = input.userCollection;
  const loginLabel = input.admin?.label ?? {
    en: 'Sign in with Xignet',
    zh: '使用火星護照登入',
  };
  const provider = Object.freeze({ ...(input.provider ?? XIGNET_PROVIDER) });
  const managed = createManagedUsers({
    ...provider,
    resource: input.resource,
    directory: input.directory,
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

export { isXignetService } from './rest.js';
export type { RestOptions, RestEntityPolicy } from './rest.js';
