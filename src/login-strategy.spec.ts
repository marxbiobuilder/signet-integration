import {
  BadRequestException,
  Controller,
  type ExecutionContext,
  Get,
  type INestApplication,
  Injectable,
  Logger,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { AuthGuard, PassportModule } from '@nestjs/passport';
import { Test } from '@nestjs/testing';
import { type Request, type Response } from 'express';

import { FakeConfigModule } from './__spec__/fake-config';
import {
  LOGIN_CALLBACK_PATH,
  LOGIN_CLIENT_ID,
  LOGIN_ENTRY,
  LOGIN_OPTIONS,
  loginEnv,
} from './__spec__/login-fixture';
import { BearerChallengeFilter } from './bearer-challenge.filter';
import { type VerifiedSignetIdentity } from './jwt-verifier';
import { SignetLoginError } from './login-error';
import { type SignetLoginContext } from './login-flow';
import { SignetLoginStrategy } from './login-strategy';
import { SignetIntegrationModule } from './module';
import { type PrincipalResolution } from './principal-resolver';
import {
  startTestAuthorizationServer,
  type TestAuthorizationServer,
} from './testing/authorization-server';

// The consumer's wiring, compiled and driven over real HTTP: a subclass of
// the mixin registered beside forPassport, begin() from a handler, and the
// callback behind AuthGuard(entry.name) with handleRequest overridden --
// against the package's own test authorization server. What the flow's spec
// cannot show is this: that Passport finds the strategy by the entry's name,
// that property injection reaches it, and that the reason survives to
// handleRequest.

const ENTRY = LOGIN_ENTRY;
const CALLBACK_PATH = LOGIN_CALLBACK_PATH;

interface Principal {
  readonly email: unknown;
  readonly name: string;
}

@Injectable()
class AcmeLogin extends SignetLoginStrategy<Principal>(ENTRY) {
  resolve(
    identity: VerifiedSignetIdentity,
    { idTokenClaims }: SignetLoginContext,
  ): Promise<PrincipalResolution<Principal>> {
    if (identity.subject !== 'person-1') {
      return Promise.resolve({ ok: false, reason: 'unknown_subject' });
    }
    return Promise.resolve({
      ok: true,
      principal: {
        email: idTokenClaims.email,
        name: `acme:${identity.subject}`,
      },
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

describe('SignetLoginStrategy', () => {
  it('refuses an entry name that is not a cookie-safe token, at class creation', () => {
    expect(() => SignetLoginStrategy({ ...ENTRY, name: 'Acme Login' })).toThrow(
      'must be lowercase letters, digits and hyphens',
    );
    expect(() => SignetLoginStrategy({ ...ENTRY, name: 'signet-jwt' })).toThrow(
      "is the Bearer strategy's",
    );
  });

  it('checks every environment’s redirect URI at class creation, not only the running one’s', () => {
    expect(() =>
      SignetLoginStrategy({
        ...ENTRY,
        name: 'typo-login',
        redirectUris: {
          ...ENTRY.redirectUris,
          production: 'http://acme.example/auth/signet/callback',
        },
      }),
    ).toThrow(
      'invalid SignetLoginEntry typo-login: redirect URI for production must be https',
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

  it('says what is wrong when Nest never injected it', () => {
    class HandMade extends SignetLoginStrategy<Principal>({
      ...ENTRY,
      name: 'hand-made-login',
    }) {
      resolve(): Promise<PrincipalResolution<Principal>> {
        return Promise.resolve({ ok: false, reason: 'unused' });
      }
    }
    expect(() => new HandMade().begin({} as Response)).toThrow(
      'HandMade: its dependencies were not injected; register it as a provider in a module that imports SignetIntegrationModule.forPassport',
    );
  });

  describe('wired into a Nest application', () => {
    let server: TestAuthorizationServer;
    let app: INestApplication;
    let baseUrl: string;

    beforeAll(async () => {
      jest.spyOn(Logger.prototype, 'log').mockImplementation();
      jest.spyOn(Logger.prototype, 'warn').mockImplementation();
      server = await startTestAuthorizationServer({
        clientId: LOGIN_CLIENT_ID,
      });
      const moduleRef = await Test.createTestingModule({
        controllers: [AuthController],
        imports: [
          PassportModule.register({}),
          FakeConfigModule.forEnv(loginEnv(server)),
          SignetIntegrationModule.forPassport({ options: LOGIN_OPTIONS }),
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

    it('builds the flow even when a subclass overrides onModuleInit without calling super', async () => {
      @Injectable()
      class ForgetfulLogin extends SignetLoginStrategy<Principal>({
        ...ENTRY,
        name: 'forgetful-login',
      }) {
        // A consumer's own init, without super.onModuleInit().
        override onModuleInit(): void {}
        resolve(): Promise<PrincipalResolution<Principal>> {
          return Promise.resolve({ ok: false, reason: 'unused' });
        }
      }
      const moduleRef = await Test.createTestingModule({
        imports: [
          PassportModule.register({}),
          FakeConfigModule.forEnv(loginEnv(server)),
          SignetIntegrationModule.forPassport({ options: LOGIN_OPTIONS }),
        ],
        providers: [ForgetfulLogin],
      }).compile();
      await moduleRef.init();
      const url = await moduleRef.get(ForgetfulLogin).begin({
        append: () => undefined,
        req: { ip: '127.0.0.1', path: '/auth/signet' },
      } as unknown as Response);
      expect(url.startsWith(`${server.issuer}/oauth2/auth?`)).toBe(true);
      await moduleRef.close();
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
        server.authorize(url, {
          idTokenClaims: { email: 'person-1@example.com' },
          subject: 'person-1',
        }),
      );
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({
        user: { email: 'person-1@example.com', name: 'acme:person-1' },
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
