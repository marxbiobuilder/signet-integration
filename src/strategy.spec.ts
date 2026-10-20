import { Logger, type LogLevel } from '@nestjs/common';
import { type Request } from 'express';

import { configOf } from './__spec__/fake-config';
import {
  SignetBearerRejectionEnum,
  SignetBearerVerification,
} from './strategy';
import {
  FIXTURE_DEVELOPMENT_PROFILE,
  FIXTURE_OPTIONS,
} from './testing/fixture';
import { startTestIssuer, type TestIssuer } from './testing/signet-token';

const ISSUER = 'https://iss.strategy-spec.invalid';

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
  // Every Logger method, so "writes no line" means no line at any level.
  let lines: Record<LogLevel, jest.SpyInstance>;

  beforeAll(async () => {
    issuer = await startTestIssuer();
  });

  afterAll(async () => {
    await issuer.close();
  });

  beforeEach(() => {
    logger = new Logger('spec');
    lines = {
      debug: jest.spyOn(logger, 'debug').mockImplementation(),
      error: jest.spyOn(logger, 'error').mockImplementation(),
      fatal: jest.spyOn(logger, 'fatal').mockImplementation(),
      log: jest.spyOn(logger, 'log').mockImplementation(),
      verbose: jest.spyOn(logger, 'verbose').mockImplementation(),
      warn: jest.spyOn(logger, 'warn').mockImplementation(),
    };
  });

  // The constructor's own startup line is not what these cases are about:
  // cleared, so every assertion counts lines from the call under test.
  const build = (signetEnabled: string) => {
    const verification = new SignetBearerVerification(
      configOf({
        ACME_JWT_ISSUER: ISSUER,
        ACME_JWT_JWKS_URI: issuer.keys.url,
        ACME_SIGNET_ENABLED: signetEnabled,
      }),
      { profile: FIXTURE_DEVELOPMENT_PROFILE },
      FIXTURE_OPTIONS,
      logger,
    );
    for (const spy of Object.values(lines)) spy.mockClear();
    return verification;
  };

  const expectNoLines = () => {
    for (const spy of Object.values(lines)) expect(spy).not.toHaveBeenCalled();
  };

  const token = () =>
    issuer.signSignetToken({
      audience: FIXTURE_DEVELOPMENT_PROFILE.canonicalResource,
      clientId: 'acme-web',
      issuer: ISSUER,
      scopes: ['acme:access'],
      subject: 'example-user-123',
    });

  describe('enabled', () => {
    it('is true with the Signet flag on', () => {
      expect(build('true').enabled).toBe(true);
    });

    it('is false with the Signet flag off', () => {
      expect(build('false').enabled).toBe(false);
    });
  });

  describe('verifyToken', () => {
    it('verifies a token handed to it directly, through the same verifier', async () => {
      const result = await build('true').verifyToken(await token());
      expect(result).toMatchObject({
        identity: { clientId: 'acme-web', subject: 'example-user-123' },
        ok: true,
      });
    });

    it('returns the verifier’s rejection reason', async () => {
      const result = await build('true').verifyToken('not-a-jwt');
      expect(result).toEqual({ ok: false, reason: 'ERR_JWS_INVALID' });
    });

    it('answers signet_disabled without fetching the JWKS when the flag is off', async () => {
      const verification = build('false');
      const fetchesBefore = issuer.keys.calls();
      const result = await verification.verifyToken(await token());
      expect(result).toEqual({
        ok: false,
        reason: SignetBearerRejectionEnum.DISABLED,
      });
      expect(issuer.keys.calls()).toBe(fetchesBefore);
    });

    it.each([
      ['a valid token', 'true', true],
      ['a refused token', 'true', false],
      ['the flag off', 'false', true],
    ])(
      'writes no line at any level for %s: the caller logs it',
      async (_, flag, valid) => {
        const verification = build(flag);
        await verification.verifyToken(valid ? await token() : 'not-a-jwt');
        expectNoLines();
      },
    );
  });

  describe('verify', () => {
    const rejectedWith = (reason: string) => {
      expect(lines.warn).toHaveBeenCalledTimes(1);
      expect(lines.warn).toHaveBeenCalledWith(
        expect.stringContaining(
          `metric=signet_auth_rejected reason=${reason} `,
        ),
      );
    };

    it('logs signet_disabled, ahead of the header check, when the flag is off', async () => {
      expect(await build('false').verify(requestOf())).toBe(false);
      rejectedWith(SignetBearerRejectionEnum.DISABLED);
    });

    it('logs header_missing for a request without an Authorization header, without touching the verifier', async () => {
      const verification = build('true');
      const fetchesBefore = issuer.keys.calls();
      expect(await verification.verify(requestOf())).toBe(false);
      rejectedWith(SignetBearerRejectionEnum.HEADER_MISSING);
      expect(issuer.keys.calls()).toBe(fetchesBefore);
    });

    it.each(['Basic abc', 'Bearer'])(
      'logs header_malformed for %j, without touching the verifier',
      async (authorization) => {
        const verification = build('true');
        const fetchesBefore = issuer.keys.calls();
        expect(await verification.verify(requestOf(authorization))).toBe(false);
        rejectedWith(SignetBearerRejectionEnum.HEADER_MALFORMED);
        expect(issuer.keys.calls()).toBe(fetchesBefore);
      },
    );

    it('logs a token the verifier refused, once, under signet_auth_rejected', async () => {
      expect(await build('true').verify(requestOf('Bearer not-a-jwt'))).toBe(
        false,
      );
      rejectedWith('ERR_JWS_INVALID');
    });

    it('returns the identity for a valid header and logs no rejection', async () => {
      const identity = await build('true').verify(
        requestOf(`Bearer ${await token()}`),
      );
      expect(identity).toMatchObject({ subject: 'example-user-123' });
      expect(lines.warn).not.toHaveBeenCalled();
    });
  });
});
