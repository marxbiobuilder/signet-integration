import {
  BadRequestException,
  Controller,
  type DynamicModule,
  type ExecutionContext,
  Get,
  Global,
  type INestApplication,
  Injectable,
  Logger,
  Module,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { APP_FILTER } from '@nestjs/core';
import { AuthGuard, PassportModule } from '@nestjs/passport';
import { Test } from '@nestjs/testing';
import { type Request, type Response } from 'express';

import { BearerChallengeFilter } from './bearer-challenge.filter';
import { type VerifiedSignetIdentity } from './jwt-verifier';
import { type SignetLoginEntry } from './login-entry';
import { SignetLoginError } from './login-error';
import { SignetLoginStrategy } from './login-strategy';
import { SignetIntegrationModule } from './module';
import { type SignetIntegrationOptions } from './options';
import { type PrincipalResolution } from './principal-resolver';
import {
  startTestAuthorizationServer,
  type TestAuthorizationServer,
} from './testing/authorization-server';
import { FIXTURE_OPTIONS } from './testing/fixture';

// The consumer's wiring, compiled and driven over real HTTP: a subclass of
// the mixin registered beside forPassport, begin() from a handler, and the
// callback behind AuthGuard(entry.name) with handleRequest overridden --
// against the package's own test authorization server. What the flow's spec
// cannot show is this: that Passport finds the strategy by the entry's name,
// that property injection reaches it, and that the reason survives to
// handleRequest.

const CLIENT_ID = 'acme-web';
const CALLBACK_PATH = '/auth/signet/callback';

const ENTRY = {
  name: 'acme-login',
  redirectUris: {
    development: `http://localhost:3000${CALLBACK_PATH}`,
    production: `https://acme.example${CALLBACK_PATH}`,
    staging: `https://acme.staging.example${CALLBACK_PATH}`,
  },
} as const satisfies SignetLoginEntry<'production' | 'staging'>;

const OPTIONS: SignetIntegrationOptions = {
  ...FIXTURE_OPTIONS,
  env: {
    ...FIXTURE_OPTIONS.env,
    loginClientId: 'ACME_LOGIN_CLIENT_ID',
    loginStateSecret: 'ACME_LOGIN_STATE_SECRET',
  },
};

interface Principal {
  readonly name: string;
}

@Injectable()
class AcmeLogin extends SignetLoginStrategy<Principal>(ENTRY) {
  resolve(
    identity: VerifiedSignetIdentity,
  ): Promise<PrincipalResolution<Principal>> {
    if (identity.subject !== 'person-1') {
      return Promise.resolve({ ok: false, reason: 'unknown_subject' });
    }
    return Promise.resolve({
      ok: true,
      principal: { name: `acme:${identity.subject}` },
    });
  }
}

// The consumer's callback guard: a login failure becomes its own UI answer
// (here a 400 naming the reason); anything else -- SignetDecision's 403 --
// passes through.
@Injectable()
class AcmeCallbackGuard extends AuthGuard(ENTRY.name) {
  override handleRequest<U>(
    error: Error | null,
    user: U,
    _info: unknown,
    _context: ExecutionContext,
  ): U {
    if (error instanceof SignetLoginError) {
      throw new BadRequestException(error.reason);
    }
    if (error) throw error;
    return user;
  }
}

@Controller('auth')
class AuthController {
  constructor(private readonly login: AcmeLogin) {}

  @Get('signet')
  async start(@Res() response: Response): Promise<void> {
    response.redirect(await this.login.begin(response));
  }

  @Get('signet/callback')
  @UseGuards(AcmeCallbackGuard)
  callback(@Req() request: Request): { user: unknown } {
    return { user: request.user };
  }

  // Passport's default handleRequest: the SignetLoginError escapes as is.
  @Get('signet/unhandled')
  @UseGuards(AuthGuard(ENTRY.name))
  unhandled(@Req() request: Request): { user: unknown } {
    return { user: request.user };
  }
}

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

describe('SignetLoginStrategy', () => {
  it('refuses an entry name that is not a cookie-safe token, at class creation', () => {
    expect(() => SignetLoginStrategy({ ...ENTRY, name: 'Acme Login' })).toThrow(
      'must be lowercase letters, digits and hyphens',
    );
    expect(() => SignetLoginStrategy({ ...ENTRY, name: 'signet-jwt' })).toThrow(
      "is the Bearer strategy's",
    );
  });

  it('leaves resolve abstract', () => {
    // @ts-expect-error -- a subclass without resolve does not compile
    class Incomplete extends SignetLoginStrategy<Principal>({
      ...ENTRY,
      name: 'incomplete-login',
    }) {}
    expect(Incomplete).toBeDefined();
  });

  describe('wired into a Nest application', () => {
    let server: TestAuthorizationServer;
    let app: INestApplication;
    let baseUrl: string;

    beforeAll(async () => {
      jest.spyOn(Logger.prototype, 'log').mockImplementation();
      jest.spyOn(Logger.prototype, 'warn').mockImplementation();
      server = await startTestAuthorizationServer({ clientId: CLIENT_ID });
      const moduleRef = await Test.createTestingModule({
        controllers: [AuthController],
        imports: [
          PassportModule.register({}),
          FakeConfigModule.forEnv({
            ACME_JWT_ISSUER: server.issuer,
            ACME_JWT_JWKS_URI: server.jwksUri,
            ACME_LOGIN_CLIENT_ID: CLIENT_ID,
            ACME_LOGIN_STATE_SECRET: 'a-login-state-secret-of-32-bytes!',
            ACME_SIGNET_ENABLED: 'true',
            NODE_ENV: 'test',
          }),
          SignetIntegrationModule.forPassport({ options: OPTIONS }),
        ],
        providers: [
          AcmeLogin,
          { provide: APP_FILTER, useClass: BearerChallengeFilter },
        ],
      }).compile();
      app = moduleRef.createNestApplication({ logger: false });
      await app.listen(0, '127.0.0.1');
      baseUrl = await app.getUrl();
    });

    afterAll(async () => {
      await app?.close();
      await server?.close();
    });

    // The browser: GET /auth/signet, keep the cookie, let the IdP answer,
    // then follow its redirect to this app (the registered URI names
    // localhost:3000; the test app listens elsewhere).
    const login = async (idp: (authorizationUrl: string) => string) => {
      const started = await fetch(`${baseUrl}/auth/signet`, {
        redirect: 'manual',
      });
      expect(started.status).toBe(302);
      const cookie = started.headers.getSetCookie()[0].split(';')[0];
      const back = new URL(idp(started.headers.get('location')!));
      return fetch(`${baseUrl}${CALLBACK_PATH}${back.search}`, {
        headers: { cookie },
        redirect: 'manual',
      });
    };

    it('logs a user in: begin redirects to the IdP, the callback hands the resolved principal to the handler', async () => {
      const response = await login((url) =>
        server.authorize(url, { subject: 'person-1' }),
      );
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({
        user: { name: 'acme:person-1' },
      });
      expect(response.headers.getSetCookie()).toEqual([
        `signet_login.acme-login=; Path=${CALLBACK_PATH}; Max-Age=0; HttpOnly; SameSite=Lax`,
      ]);
    });

    it('hands the reason of a login failure to handleRequest', async () => {
      const response = await login((url) => server.deny(url));
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ message: 'cancelled' });
    });

    it('passes SignetDecision’s refusal through as a 403', async () => {
      const response = await login((url) =>
        server.authorize(url, { subject: 'stranger' }),
      );
      expect(response.status).toBe(403);
    });

    it('answers an unhandled login failure 401 WITHOUT a Bearer challenge', async () => {
      // No state cookie: STATE_INVALID, escaping Passport's default
      // handleRequest to the filter.
      const response = await fetch(
        `${baseUrl}/auth/signet/unhandled?code=c&state=s`,
        { redirect: 'manual' },
      );
      expect(response.status).toBe(401);
      expect(response.headers.get('www-authenticate')).toBeNull();
    });
  });
});
