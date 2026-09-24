import {
  Controller,
  type DynamicModule,
  Get,
  Global,
  type INestApplication,
  Inject,
  Injectable,
  Logger,
  Module,
  Req,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { PassportModule } from '@nestjs/passport';
import { Test } from '@nestjs/testing';
import { type Request } from 'express';

import { BearerChallengeFilter } from './bearer-challenge.filter';
import { SignetBearerGuard } from './guard';
import { type VerifiedSignetIdentity } from './jwt-verifier';
import { SignetIntegrationModule } from './module';
import { createSignetPrincipalDecorator } from './principal.decorator';
import {
  type PrincipalResolution,
  SIGNET_PRINCIPAL_RESOLVER,
  type SignetPrincipalResolver,
} from './principal-resolver';
import { createProtectedResourceController } from './protected-resource.controller';
import { Public } from './public.decorator';
import { FIXTURE_OPTIONS } from './testing/fixture';
import { startTestIssuer, type TestIssuer } from './testing/signet-token';

// The DI-facing API, compiled and driven over real HTTP: forRoot with a class
// resolver that injects a dependency from the consumer's own module, the
// guard as APP_GUARD, the filter as APP_FILTER, the metadata controller from
// the factory, and the principal decorator -- against a token minted by the
// package's own test issuer. What the metadata-only spec in a consumer cannot
// show is exactly this: that the graph resolves and the pieces meet.

const ISSUER = 'https://iss.module-spec.invalid';
const DEP = Symbol('DEP');
interface Principal {
  readonly name: string;
}
const isPrincipal = (value: unknown): value is Principal =>
  typeof value === 'object' && value !== null && 'name' in value;

@Module({ exports: [DEP], providers: [{ provide: DEP, useValue: 'users' }] })
class DepModule {}

@Injectable()
class FixtureResolver implements SignetPrincipalResolver<Principal> {
  constructor(@Inject(DEP) private readonly source: string) {}
  resolve(
    identity: VerifiedSignetIdentity,
  ): Promise<PrincipalResolution<Principal>> {
    if (identity.subject !== 'user-1') {
      return Promise.resolve({ ok: false, reason: 'unknown_subject' });
    }
    return Promise.resolve({
      logFields: { source: this.source },
      ok: true,
      principal: { name: `${this.source}:${identity.subject}` },
    });
  }
}

const Principal = createSignetPrincipalDecorator<Principal>(
  FIXTURE_OPTIONS,
  isPrincipal,
);

// Class-level @Public(): the guard must consult the class as well as the
// handler.
@Controller('open')
@Public()
class OpenController {
  @Get()
  ok(): { open: true } {
    return { open: true };
  }
}

@Controller()
class ProbeController {
  @Get('mcp')
  mcp(@Principal() principal: Principal): { principal: Principal } {
    return { principal };
  }

  @Get('health')
  @Public()
  health(): { ok: true } {
    return { ok: true };
  }

  // Public AND asking for a principal: the decorator's runtime check is the
  // only thing between this handler and an undefined principal.
  @Get('unguarded')
  @Public()
  unguarded(@Principal() principal: Principal): { principal: Principal } {
    return { principal };
  }

  @Get('raw')
  raw(@Req() request: Request & { principal?: unknown }): {
    user: unknown;
    principal: unknown;
  } {
    return { principal: request.principal, user: request.user };
  }
}

// A consumer's ConfigModule is global; the package's providers inject
// ConfigService from inside SignetIntegrationModule's own scope, which a
// plain provider on the test root would not reach.
@Global()
@Module({})
class FakeConfigModule {
  static forEnv(env: Record<string, string>): DynamicModule {
    return {
      exports: [ConfigService],
      module: FakeConfigModule,
      providers: [
        {
          provide: ConfigService,
          useValue: {
            get: (key: string, fallback?: unknown) => env[key] ?? fallback,
            getOrThrow: (key: string) => {
              if (env[key] === undefined) throw new Error(`${key} missing`);
              return env[key];
            },
          },
        },
      ],
    };
  }
}

describe('SignetIntegrationModule.forRoot, end to end', () => {
  let issuer: TestIssuer;
  let app: INestApplication;
  let baseUrl: string;

  beforeAll(async () => {
    jest.spyOn(Logger.prototype, 'log').mockImplementation();
    jest.spyOn(Logger.prototype, 'warn').mockImplementation();
    issuer = await startTestIssuer();
    const moduleRef = await Test.createTestingModule({
      controllers: [
        OpenController,
        ProbeController,
        createProtectedResourceController(FIXTURE_OPTIONS),
      ],
      imports: [
        // Registers AuthModuleOptions. AuthGuard property-injects that object
        // onto `options`; the admitted-token case below stays green only when
        // the guard keeps its integration options on another field.
        PassportModule.register({}),
        FakeConfigModule.forEnv({
          ACME_JWT_ISSUER: ISSUER,
          ACME_JWT_JWKS_URI: issuer.keys.url,
          ACME_SIGNET_ENABLED: 'true',
          NODE_ENV: 'test',
        }),
        SignetIntegrationModule.forRoot({
          imports: [DepModule],
          options: FIXTURE_OPTIONS,
          resolver: FixtureResolver,
        }),
      ],
      providers: [
        { provide: APP_GUARD, useClass: SignetBearerGuard },
        { provide: APP_FILTER, useClass: BearerChallengeFilter },
      ],
    }).compile();
    app = moduleRef.createNestApplication({ logger: false });
    await app.listen(0, '127.0.0.1');
    baseUrl = await app.getUrl();
  });

  afterAll(async () => {
    await app?.close();
    await issuer.close();
  });

  const token = (
    subject: string,
    scopes: readonly string[] = ['acme:access'],
  ) =>
    issuer.signSignetToken({
      audience: 'http://localhost/mcp',
      clientId: 'acme-cli',
      issuer: ISSUER,
      scopes,
      subject,
    });

  it('lets a @Public() route through the APP_GUARD, marked on the handler or on the class', async () => {
    const response = await fetch(`${baseUrl}/health`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
    const open = await fetch(`${baseUrl}/open`);
    expect(open.status).toBe(200);
    expect(await open.json()).toEqual({ open: true });
  });

  it('answers a credential-less resource request 401 with the metadata challenge', async () => {
    const response = await fetch(`${baseUrl}/mcp`);
    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toBe(
      'Bearer realm="acme", resource_metadata="http://localhost/.well-known/oauth-protected-resource/mcp", scope="acme:access"',
    );
  });

  it('answers a credential-less non-resource request 401 with the plain challenge', async () => {
    const response = await fetch(`${baseUrl}/raw`);
    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toBe(
      'Bearer realm="acme", scope="acme:access"',
    );
  });

  it('serves the RFC 9728 document from the same settings the verifier uses', async () => {
    const response = await fetch(
      `${baseUrl}/.well-known/oauth-protected-resource/mcp`,
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      authorization_servers: [ISSUER],
      bearer_methods_supported: ['header'],
      resource: 'http://localhost/mcp',
      scopes_supported: ['acme:access', 'widgets:read', 'widgets:write'],
    });
  });

  it('verifies a token against the issuer’s JWKS, resolves it through the consumer’s resolver and its dependency, and hands the principal to the handler', async () => {
    const response = await fetch(`${baseUrl}/mcp`, {
      headers: { authorization: `Bearer ${await token('user-1')}` },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      principal: { name: 'users:user-1' },
    });
  });

  it('keeps Passport’s identity on request.user and the principal under requestPrincipalKey', async () => {
    const response = await fetch(`${baseUrl}/raw`, {
      headers: { authorization: `Bearer ${await token('user-1')}` },
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      principal: unknown;
      user: { subject?: string; claims?: unknown };
    };
    expect(body.principal).toEqual({ name: 'users:user-1' });
    expect(body.user.subject).toBe('user-1');
    expect(body.user.claims).toBeDefined();
  });

  it('403s a resolver refusal bare, with the generic message', async () => {
    const response = await fetch(`${baseUrl}/mcp`, {
      headers: { authorization: `Bearer ${await token('stranger')}` },
    });
    expect(response.status).toBe(403);
    expect(response.headers.get('www-authenticate')).toBeNull();
    expect(await response.json()).toMatchObject({
      message: 'this identity holds no authorization in this service',
    });
  });

  it('403s a token without the admission scope with an insufficient_scope challenge', async () => {
    const response = await fetch(`${baseUrl}/mcp`, {
      headers: { authorization: `Bearer ${await token('user-1', ['openid'])}` },
    });
    expect(response.status).toBe(403);
    expect(response.headers.get('www-authenticate')).toBe(
      'Bearer realm="acme", error="insufficient_scope", scope="acme:access"',
    );
  });

  it('401s a token for another audience with the same challenge as no token', async () => {
    const foreign = await issuer.signSignetToken({
      audience: 'https://elsewhere.example',
      clientId: 'acme-cli',
      issuer: ISSUER,
      scopes: ['acme:access'],
      subject: 'user-1',
    });
    const response = await fetch(`${baseUrl}/mcp`, {
      headers: { authorization: `Bearer ${foreign}` },
    });
    expect(response.status).toBe(401);
    expect(response.headers.get('www-authenticate')).toBe(
      'Bearer realm="acme", resource_metadata="http://localhost/.well-known/oauth-protected-resource/mcp", scope="acme:access"',
    );
  });

  it('500s a handler that asks for a principal on a route the guard did not run on', async () => {
    jest.spyOn(Logger.prototype, 'error').mockImplementation();
    const response = await fetch(`${baseUrl}/unguarded`);
    expect(response.status).toBe(500);
    expect(await response.json()).toMatchObject({
      message: expect.stringContaining('request.principal') as unknown,
    });
  });
});

describe('SignetIntegrationModule.forRoot, resolver provider shapes', () => {
  it('binds a provider object (useFactory) under the resolver token, with its own inject', async () => {
    const resolver: SignetPrincipalResolver = {
      resolve: () => Promise.resolve({ ok: false, reason: 'never' }),
    };
    const moduleRef = await Test.createTestingModule({
      imports: [
        FakeConfigModule.forEnv({ NODE_ENV: 'test' }),
        SignetIntegrationModule.forRoot({
          imports: [DepModule],
          options: FIXTURE_OPTIONS,
          resolver: {
            inject: [DEP],
            useFactory: (source: string) => {
              if (source !== 'users') throw new Error('inject did not run');
              return resolver;
            },
          },
        }),
      ],
    }).compile();
    expect(moduleRef.get(SIGNET_PRINCIPAL_RESOLVER)).toBe(resolver);
    expect(moduleRef.get(SignetBearerGuard)).toBeInstanceOf(SignetBearerGuard);
    await moduleRef.close();
  });

  it('refuses options that break an invariant, at construction', () => {
    expect(() =>
      SignetIntegrationModule.forRoot({
        options: { ...FIXTURE_OPTIONS, scopesSupported: [] },
        resolver: FixtureResolver,
      }),
    ).toThrow(/scopesSupported must include the admission scope/);
  });
});
