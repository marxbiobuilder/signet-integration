import { type DynamicModule, Global, Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

// Spec-only helpers (excluded from the build and from coverage): the one
// fake ConfigService the specs share. `get` answers the env or the caller's
// fallback; `getOrThrow` throws `<KEY> missing` for an absent key, as the
// package's own error messages expect.
export function configOf(
  env: Record<string, string | undefined>,
): ConfigService {
  return {
    get: (key: string, fallback?: unknown) => env[key] ?? fallback,
    getOrThrow: (key: string) => {
      const value = env[key];
      if (value === undefined) throw new Error(`${key} missing`);
      return value;
    },
  } as unknown as ConfigService;
}

// A consumer's ConfigModule is global; the package's providers inject
// ConfigService from inside SignetIntegrationModule's own scope, which a
// plain provider on the test root would not reach.
@Global()
@Module({})
export class FakeConfigModule {
  static forEnv(env: Record<string, string | undefined>): DynamicModule {
    return {
      exports: [ConfigService],
      module: FakeConfigModule,
      providers: [{ provide: ConfigService, useValue: configOf(env) }],
    };
  }
}
