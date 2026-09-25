import { Logger } from '@nestjs/common';

import { SignetDecision } from './decision';
import { type VerifiedSignetIdentity } from './jwt-verifier';
import { type SignetPrincipalResolver } from './principal-resolver';
import {
  FIXTURE_DEVELOPMENT_PROFILE,
  FIXTURE_OPTIONS,
} from './testing/fixture';

// The classification itself is pinned through SignetBearerGuard (guard.spec);
// what this file pins is the helper's own contract: what it returns, when the
// attachment runs relative to the log line, and whose logger it writes to.

const IDENTITY: VerifiedSignetIdentity = {
  claims: { sub: 'user-1' },
  clientId: 'acme-cli',
  issuer: 'https://iss.decision-spec.invalid',
  scopes: ['acme:access'],
  subject: 'user-1',
};

const PRINCIPAL = { id: 'p-1' };
const resolver: SignetPrincipalResolver<typeof PRINCIPAL> = {
  resolve: () => Promise.resolve({ ok: true, principal: PRINCIPAL }),
};

const decision = () =>
  new SignetDecision(FIXTURE_OPTIONS, { profile: FIXTURE_DEVELOPMENT_PROFILE });

describe('SignetDecision', () => {
  it('returns the principal the resolver produced', async () => {
    jest.spyOn(Logger.prototype, 'log').mockImplementation();
    await expect(decision().decide(IDENTITY, resolver)).resolves.toBe(
      PRINCIPAL,
    );
  });

  it('runs attach with the principal BEFORE the authorized line, and writes no line when attach throws', async () => {
    const log = jest.spyOn(Logger.prototype, 'log').mockImplementation();
    const order: string[] = [];
    log.mockImplementation(() => {
      order.push('log');
    });
    await decision().decide(IDENTITY, resolver, {
      attach: (principal) => {
        expect(principal).toBe(PRINCIPAL);
        order.push('attach');
      },
    });
    expect(order).toEqual(['attach', 'log']);

    log.mockClear();
    await expect(
      decision().decide(IDENTITY, resolver, {
        attach: () => {
          throw new TypeError('read-only property');
        },
      }),
    ).rejects.toThrow('read-only property');
    expect(log).not.toHaveBeenCalled();
  });

  it('writes through the caller’s logger when given one, else its own', async () => {
    const contexts: unknown[] = [];
    jest.spyOn(Logger.prototype, 'log').mockImplementation(function (
      this: Logger,
    ) {
      contexts.push((this as unknown as { context?: string }).context);
    });
    await decision().decide(IDENTITY, resolver);
    await decision().decide(IDENTITY, resolver, {
      logger: new Logger('ConsumerStrategy'),
    });
    expect(contexts).toEqual(['SignetDecision', 'ConsumerStrategy']);
  });

  it('names the caller’s address on the scope-missing line, and none when absent', async () => {
    const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation();
    const noScope = { ...IDENTITY, scopes: ['openid'] };
    await expect(
      decision().decide(noScope, resolver, { source: '10.0.0.7' }),
    ).rejects.toMatchObject({ status: 403 });
    await expect(decision().decide(noScope, resolver)).rejects.toMatchObject({
      status: 403,
    });
    expect(warn.mock.calls.map((call) => String(call[0]))).toEqual([
      expect.stringContaining('metric=signet_scope_missing source=10.0.0.7'),
      expect.stringContaining('metric=signet_scope_missing source=none'),
    ]);
  });
});
