import {
  type DynamicModule,
  type ExistingProvider,
  type FactoryProvider,
  Module,
  type Provider,
  type Type,
  type ValueProvider,
} from '@nestjs/common';

import { SignetDeploymentProfileService } from './deployment-profile';
import { SignetBearerGuard } from './guard';
import {
  SIGNET_INTEGRATION_OPTIONS,
  type SignetIntegrationOptions,
} from './options';
import {
  SIGNET_PRINCIPAL_RESOLVER,
  type SignetPrincipalResolver,
} from './principal-resolver';
import { SignetJwtStrategy } from './strategy';
import { validateSignetIntegrationOptions } from './validate-options';

export type ResolverProvider =
  | Omit<ExistingProvider<SignetPrincipalResolver>, 'provide'>
  | Omit<FactoryProvider<SignetPrincipalResolver>, 'provide'>
  | Omit<ValueProvider<SignetPrincipalResolver>, 'provide'>
  | Type<SignetPrincipalResolver>;

export interface SignetIntegrationModuleOptions {
  // Modules whose exports the resolver depends on. The resolver is
  // instantiated inside this module's scope, so a class resolver that injects
  // a consumer's own provider (a grant loader, a user repository) needs the
  // module that exports it listed here.
  readonly imports?: DynamicModule['imports'];
  readonly options: SignetIntegrationOptions;
  // The consumer's SignetPrincipalResolver: a class, or a provider definition
  // WITHOUT `provide` -- this module binds it to SIGNET_PRINCIPAL_RESOLVER.
  readonly resolver: ResolverProvider;
}

// Wires the Bearer channel: options behind their token, the consumer's
// resolver behind its token, the deployment profile, the Passport strategy
// (which registers itself by name in its constructor, so it must be a
// provider) and the guard. Exports everything a consumer's own auth module
// re-exports or a dispatcher injects.
//
// NOT here: the metadata controller (createProtectedResourceController --
// the consumer declares it in the module of the process that serves the
// resource), the exception filter (BearerChallengeFilter as APP_FILTER, or
// the consumer's own filter calling challengeFor), and the guard's mounting
// (APP_GUARD, or inside a consumer's credential dispatcher).
@Module({})
export class SignetIntegrationModule {
  static forRoot(input: SignetIntegrationModuleOptions): DynamicModule {
    const resolver: Provider =
      typeof input.resolver === 'function'
        ? { provide: SIGNET_PRINCIPAL_RESOLVER, useClass: input.resolver }
        : { ...input.resolver, provide: SIGNET_PRINCIPAL_RESOLVER };
    return {
      exports: [
        SIGNET_INTEGRATION_OPTIONS,
        SIGNET_PRINCIPAL_RESOLVER,
        SignetBearerGuard,
        SignetDeploymentProfileService,
        SignetJwtStrategy,
      ],
      imports: input.imports ?? [],
      module: SignetIntegrationModule,
      providers: [
        {
          provide: SIGNET_INTEGRATION_OPTIONS,
          useValue: validateSignetIntegrationOptions(input.options),
        },
        resolver,
        SignetBearerGuard,
        SignetDeploymentProfileService,
        SignetJwtStrategy,
      ],
    };
  }
}
