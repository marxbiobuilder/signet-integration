import { Logger } from '@nestjs/common';
import { type ConfigService } from '@nestjs/config';
import { type Request } from 'express';

import { SignetBearerVerification } from './strategy';
import {
  FIXTURE_DEVELOPMENT_PROFILE,
  FIXTURE_OPTIONS,
} from './testing/fixture';
import { startTestIssuer, type TestIssuer } from './testing/signet-token';

const ISSUER = 'https://iss.strategy-spec.invalid';

function configOf(env: Record<string, string>): ConfigService {
  return {
    get: (key: string, fallback?: unknown) => env[key] ?? fallback,
    getOrThrow: (key: string) => {
      if (env[key] === undefined) throw new Error(`${key} missing`);
      return env[key];
    },
  } as unknown as ConfigService;
}

function requestOf(authorization?: string): Request {
  return {
    headers: authorization === undefined ? {} : { authorization },
    ip: '127.0.0.1',
    method: 'GET',
    originalUrl: '/probe',
  } as unknown as Request;
}

describe('SignetBearerVerification', () => {
  let issuer: TestIssuer;
  let logger: Logger;
  let warn: jest.SpyInstance;

  beforeAll(async () => {
    issuer = await startTestIssuer();
  });

  afterAll(async () => {
    await issuer.close();
  });

  beforeEach(() => {
    logger = new Logger('spec');
    jest.spyOn(logger, 'log').mockImplementation();
    warn = jest.spyOn(logger, 'warn').mockImplementation();
  });

  const build = (signetEnabled: string) =>
    new SignetBearerVerification(
      configOf({
        ACME_JWT_ISSUER: ISSUER,
        ACME_JWT_JWKS_URI: issuer.keys.url,
        ACME_SIGNET_ENABLED: signetEnabled,
      }),
      { profile: FIXTURE_DEVELOPMENT_PROFILE },
      FIXTURE_OPTIONS,
      logger,
    );

  const token = () =>
    issuer.signSignetToken({
      audience: FIXTURE_DEVELOPMENT_PROFILE.canonicalResource,
      clientId: 'acme-web',
      issuer: ISSUER,
      scopes: ['acme:access'],
      subject: 'example-user-123',
    });

  describe('verifyToken', () => {
    it('verifies a token handed to it directly, through the same verifier', async () => {
      const verification = build('true');
      expect(verification.enabled).toBe(true);
      const result = await verification.verifyToken(await token());
      expect(result).toMatchObject({
        identity: { clientId: 'acme-web', subject: 'example-user-123' },
        ok: true,
      });
    });

    it('returns the rejection reason and writes no line: the caller logs it', async () => {
      const result = await build('true').verifyToken('not-a-jwt');
      expect(result).toEqual({ ok: false, reason: 'ERR_JWS_INVALID' });
      expect(warn).not.toHaveBeenCalled();
    });

    it('answers signet_disabled without touching the token when the flag is off', async () => {
      const verification = build('false');
      expect(verification.enabled).toBe(false);
      const fetchesBefore = issuer.keys.calls();
      const result = await verification.verifyToken(await token());
      expect(result).toEqual({ ok: false, reason: 'signet_disabled' });
      expect(issuer.keys.calls()).toBe(fetchesBefore);
      expect(warn).not.toHaveBeenCalled();
    });
  });

  describe('verify', () => {
    it('still logs every rejection, signet_disabled included', async () => {
      expect(await build('false').verify(requestOf())).toBe(false);
      expect(warn).toHaveBeenCalledWith(
        expect.stringContaining('reason=signet_disabled'),
      );
    });

    it('logs a token the verifier refused under signet_auth_rejected', async () => {
      expect(await build('true').verify(requestOf('Bearer not-a-jwt'))).toBe(
        false,
      );
      expect(warn).toHaveBeenCalledWith(
        expect.stringContaining(
          'metric=signet_auth_rejected reason=ERR_JWS_INVALID',
        ),
      );
    });

    it('returns the identity for a valid header', async () => {
      const identity = await build('true').verify(
        requestOf(`Bearer ${await token()}`),
      );
      expect(identity).toMatchObject({ subject: 'example-user-123' });
    });
  });
});
