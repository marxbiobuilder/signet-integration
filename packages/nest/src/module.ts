import {
  type DynamicModule,
  type ExistingProvider,
  type FactoryProvider,
  Module,
  type Provider,
  type Type,
  type ValueProvider,
} from '@nestjs/common';

import { SignetDecision } from './decision';
import { SignetDeploymentProfileService } from './deployment-profile';
import { SignetBearerGuard } from './guard';
import {
  SIGNET_INTEGRATION_OPTIONS,
  type SignetIntegrationOptions,
} from './options';
import { SignetPassportGuard } from './passport-guard';
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

export interface SignetPassportModuleOptions {
  // Modules whose exports the package's providers depend on (none today; kept
  // for symmetry with forRoot, whose resolver is instantiated in this scope).
  readonly imports?: DynamicModule['imports'];
  readonly options: SignetIntegrationOptions;
}

export interface SignetIntegrationModuleOptions extends SignetPassportModuleOptions {
  // The consumer's SignetPrincipalResolver: a class, or a provider definition
  // WITHOUT `provide` -- this module binds it to SIGNET_PRINCIPAL_RESOLVER.
  // A class resolver that injects a consumer's own provider (a grant loader,
  // a user repository) needs the module that exports it in `imports`.
  readonly resolver: ResolverProvider;
}

// Two ways in, one set of providers underneath.
//
// forPassport: the consumer brings its own strategy (a SignetPrincipalStrategy
// subclass, registered as a provider in the consumer's module) and guards
// with SignetPassportGuard or any AuthGuard(SIGNET_JWT_STRATEGY). This
// module then provides what that strategy injects: the options behind their
// token, the deployment profile, and SignetDecision.
//
// forRoot: the module-wired shape. Adds the consumer's resolver behind its
// token, SignetJwtStrategy (which registers itself by name in its
// constructor, so it must be a provider) and SignetBearerGuard.
//
// NOT here either way: the metadata controller (createProtectedResourceController --
// the consumer declares it in the module of the process that serves the
// resource), the exception filter (BearerChallengeFilter as APP_FILTER, or
// the consumer's own filter calling challengeFor), and the guard's mounting
// (APP_GUARD, or inside a consumer's credential dispatcher).
@Module({})
export class SignetIntegrationModule {
  static forPassport(input: SignetPassportModuleOptions): DynamicModule {
    return {
      exports: [
        SIGNET_INTEGRATION_OPTIONS,
        SignetDecision,
        SignetDeploymentProfileService,
        SignetPassportGuard,
      ],
      imports: input.imports ?? [],
      module: SignetIntegrationModule,
      providers: [
        {
          provide: SIGNET_INTEGRATION_OPTIONS,
          useValue: validateSignetIntegrationOptions(input.options),
        },
        SignetDecision,
        SignetDeploymentProfileService,
        SignetPassportGuard,
      ],
    };
  }

  static forRoot(input: SignetIntegrationModuleOptions): DynamicModule {
    const resolver: Provider =
      typeof input.resolver === 'function'
        ? { provide: SIGNET_PRINCIPAL_RESOLVER, useClass: input.resolver }
        : { ...input.resolver, provide: SIGNET_PRINCIPAL_RESOLVER };
    const base = SignetIntegrationModule.forPassport(input);
    return {
      ...base,
      exports: [
        ...(base.exports ?? []),
        SIGNET_PRINCIPAL_RESOLVER,
        SignetBearerGuard,
        SignetJwtStrategy,
      ],
      providers: [
        ...(base.providers ?? []),
        resolver,
        SignetBearerGuard,
        SignetJwtStrategy,
      ],
    };
  }
}
