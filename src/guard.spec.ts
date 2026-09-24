import {
  type ExecutionContext,
  ForbiddenException,
  InternalServerErrorException,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { type Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';

import {
  carriesScopeChallenge,
  InsufficientScopeException,
} from './bearer-challenge';
import { SignetBearerGuard } from './guard';
import { type VerifiedSignetIdentity } from './jwt-verifier';
import { type SignetIntegrationOptions } from './options';
import {
  type PrincipalResolution,
  PrincipalStoreUnavailableError,
  SIGNET_PRINCIPAL_RESOLVER,
} from './principal-resolver';
import { IS_PUBLIC_ROUTE } from './public.decorator';
import {
  FIXTURE_DEVELOPMENT_PROFILE,
  FIXTURE_OPTIONS,
} from './testing/fixture';

// Passport's part is stubbed at the base class: what these cases pin is the
// layer the guard adds after the strategy returned an identity. The strategy
// and verifier have their own specs.
const IDENTITY: VerifiedSignetIdentity = {
  claims: { sub: 'example-user-123' },
  clientId: 'acme-agent-spec',
  issuer: 'https://iss.guard-spec.invalid',
  scopes: ['openid', 'acme:access'],
  subject: 'example-user-123',
};

const PRINCIPAL = { id: 'p-1' };

function makeContext(user: VerifiedSignetIdentity | undefined) {
  const request: Record<string, unknown> = { ip: '127.0.0.1', user };
  return {
    context: {
      getClass: () => undefined,
      getHandler: () => undefined,
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({ setHeader: jest.fn() }),
      }),
    } as unknown as ExecutionContext,
    request,
  };
}

// Answers per key, and ignores the [handler, class] array: a fake that
// ignored the key would report every route as public.
function reflectorOf(publicRoute: boolean): Reflector {
  return {
    getAllAndOverride: (key: string) =>
      key === IS_PUBLIC_ROUTE ? publicRoute : undefined,
  } as unknown as Reflector;
}

function makeGuard(
  resolve: jest.Mock,
  passport: () => Promise<boolean> = () => Promise.resolve(true),
  options: SignetIntegrationOptions = FIXTURE_OPTIONS,
  publicRoute = false,
): SignetBearerGuard {
  // AuthGuard(...) returns a fresh mixin class; its prototype is where Nest's
  // canActivate lives, so the stub goes on the mixin's prototype.
  const guard = new SignetBearerGuard(
    { resolve },
    { profile: FIXTURE_DEVELOPMENT_PROFILE },
    options,
    reflectorOf(publicRoute),
  );
  const base = Object.getPrototypeOf(
    Object.getPrototypeOf(guard),
  ) as InstanceType<ReturnType<typeof AuthGuard>>;
  jest.spyOn(base, 'canActivate').mockImplementation(passport);
  return guard;
}

const authorized = (logFields?: Record<string, string>): jest.Mock =>
  jest.fn().mockResolvedValue({
    logFields,
    ok: true,
    principal: PRINCIPAL,
  } satisfies PrincipalResolution<unknown>);

describe('SignetBearerGuard', () => {
  afterEach(() => jest.restoreAllMocks());

  // The guard can be an APP_GUARD on its own: a route marked @Public() is
  // let through before Passport runs, so a credential-free route (the
  // metadata document, a health probe) does not 401.
  it('lets a @Public() route through without running the strategy or the resolver', async () => {
    const resolve = authorized();
    const passport = jest.fn().mockResolvedValue(true);
    await expect(
      makeGuard(resolve, passport, FIXTURE_OPTIONS, true).canActivate(
        makeContext(undefined).context,
      ),
    ).resolves.toBe(true);
    expect(passport).not.toHaveBeenCalled();
    expect(resolve).not.toHaveBeenCalled();
  });

  it('hands the verified identity to the resolver and attaches its principal under requestPrincipalKey', async () => {
    jest.spyOn(Logger.prototype, 'log').mockImplementation();
    const resolve = authorized();
    const { context, request } = makeContext(IDENTITY);
    await expect(makeGuard(resolve).canActivate(context)).resolves.toBe(true);
    expect(resolve).toHaveBeenCalledWith(IDENTITY);
    expect(request.principal).toBe(PRINCIPAL);
    // Passport's identity stays where Passport put it.
    expect(request.user).toBe(IDENTITY);
  });

  it('attaches under whatever key the options name, including Passport’s own', async () => {
    jest.spyOn(Logger.prototype, 'log').mockImplementation();
    const { context, request } = makeContext(IDENTITY);
    await expect(
      makeGuard(authorized(), undefined, {
        ...FIXTURE_OPTIONS,
        requestPrincipalKey: 'user',
      }).canActivate(context),
    ).resolves.toBe(true);
    expect(request.user).toBe(PRINCIPAL);
  });

  // Every field of a decision line, in order: the fixed ones, the resolver's
  // logFields between reason and clientId, in the order given. Pinned as a
  // whole so a field being ADDED -- the caller's `sub`, the issuer, anything
  // derived from the token -- fails here instead of reaching an operator's
  // log.
  function decisionFields(line: unknown): Record<string, string> {
    const fields: Record<string, string> = {};
    for (const [, key, value] of String(line).matchAll(/(\w+)=(\S*)/g)) {
      fields[key] = value;
    }
    return fields;
  }

  it('logs an authorization at info with the resolver’s fields in order, naming the client', async () => {
    const log = jest.spyOn(Logger.prototype, 'log').mockImplementation();
    const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation();
    const { context } = makeContext(IDENTITY);
    await expect(
      makeGuard(
        authorized({ principalId: 'p-1', bindingId: 'b-1' }),
      ).canActivate(context),
    ).resolves.toBe(true);
    expect(warn).not.toHaveBeenCalled();
    expect(log).toHaveBeenCalledTimes(1);
    const fields = decisionFields(log.mock.calls[0][0]);
    expect(Object.keys(fields)).toEqual([
      'metric',
      'reason',
      'principalId',
      'bindingId',
      'clientId',
      'environment',
    ]);
    expect(fields).toEqual({
      bindingId: 'b-1',
      clientId: 'acme-agent-spec',
      environment: 'development',
      metric: 'signet_principal_authorized',
      principalId: 'p-1',
      reason: 'none',
    });
    expect(String(log.mock.calls[0][0])).not.toContain(IDENTITY.subject);
    expect(String(log.mock.calls[0][0])).not.toContain(IDENTITY.issuer);
  });

  it('logs a refusal at warn with the same field set and order, and answers a bare 403 with the options’ message', async () => {
    const warn = jest.spyOn(Logger.prototype, 'warn').mockImplementation();
    const guard = makeGuard(
      jest.fn().mockResolvedValue({
        logFields: { principalId: 'none', bindingId: 'none' },
        ok: false,
        reason: 'binding_disabled',
      }),
      undefined,
      { ...FIXTURE_OPTIONS, principalRefusalMessage: 'nothing for you here' },
    );
    const caught = await guard
      .canActivate(makeContext(IDENTITY).context)
      .catch((error: unknown) => error);
    expect(caught).toBeInstanceOf(ForbiddenException);
    expect((caught as ForbiddenException).message).toBe('nothing for you here');
    expect(carriesScopeChallenge(caught as ForbiddenException)).toBe(false);
    expect(warn).toHaveBeenCalledTimes(1);
    const fields = decisionFields(warn.mock.calls[0][0]);
    expect(Object.keys(fields)).toEqual([
      'metric',
      'reason',
      'principalId',
      'bindingId',
      'clientId',
      'environment',
    ]);
    expect(fields).toEqual({
      bindingId: 'none',
      clientId: 'acme-agent-spec',
      environment: 'development',
      metric: 'signet_principal_refused',
      principalId: 'none',
      reason: 'binding_disabled',
    });
    expect(String(warn.mock.calls[0][0])).not.toContain(IDENTITY.subject);
    expect(String(warn.mock.calls[0][0])).not.toContain(IDENTITY.issuer);
    // The reason is for the operator, not the caller.
    expect((caught as ForbiddenException).message).not.toContain(
      'binding_disabled',
    );
  });

  it('answers a refusal with a generic message when the options name none', async () => {
    jest.spyOn(Logger.prototype, 'warn').mockImplementation();
    const caught = await makeGuard(
      jest.fn().mockResolvedValue({ ok: false, reason: 'unknown' }),
    )
      .canActivate(makeContext(IDENTITY).context)
      .catch((error: unknown) => error);
    expect((caught as ForbiddenException).message).toBe(
      'this identity holds no authorization in this service',
    );
  });

  it('folds a client id or a resolver field that would forge a field of its own', async () => {
    const log = jest.spyOn(Logger.prototype, 'log').mockImplementation();
    const { context } = makeContext({
      ...IDENTITY,
      clientId: 'evil clientId=trusted-agent',
    });
    await expect(
      makeGuard(authorized({ principalId: 'p 1=x' })).canActivate(context),
    ).resolves.toBe(true);
    expect(decisionFields(log.mock.calls[0][0])).toMatchObject({
      clientId: 'evil_clientId_trusted-agent',
      principalId: 'p_1_x',
    });
  });

  // The decision line's own keys are not the resolver's to reuse: a second
  // `clientId=` is whichever copy the log parser keeps.
  it.each(['metric', 'reason', 'clientId', 'environment'])(
    'refuses a resolver logFields key that shadows the fixed field %s',
    async (key) => {
      const error = jest.spyOn(Logger.prototype, 'error').mockImplementation();
      const guard = makeGuard(authorized({ [key]: 'spoof' }));
      await expect(
        guard.canActivate(makeContext(IDENTITY).context),
      ).rejects.toThrow(/reserved key/);
      expect(error).not.toHaveBeenCalled();
    },
  );

  it('turns the strategy’s refusal into ONE indistinguishable 401', async () => {
    const resolve = authorized();
    const guard = makeGuard(resolve, () =>
      Promise.reject(new UnauthorizedException('Unauthorized: token expired')),
    );
    await expect(
      guard.canActivate(makeContext(undefined).context),
    ).rejects.toMatchObject({ message: 'Unauthorized' });
    expect(resolve).not.toHaveBeenCalled();
  });

  it('lets a programming error from Passport through rather than dressing it as a 401', async () => {
    await expect(
      makeGuard(authorized(), () =>
        Promise.reject(new TypeError('boom')),
      ).canActivate(makeContext(undefined).context),
    ).rejects.toBeInstanceOf(TypeError);
  });

  it.each([
    ['passes but attaches no identity', () => Promise.resolve(true), undefined],
    ['resolves false without throwing', () => Promise.resolve(false), IDENTITY],
  ])('500s and logs when Passport %s', async (_label, passport, user) => {
    const error = jest.spyOn(Logger.prototype, 'error').mockImplementation();
    const resolve = authorized();
    await expect(
      makeGuard(resolve, passport).canActivate(makeContext(user).context),
    ).rejects.toBeInstanceOf(InternalServerErrorException);
    expect(String(error.mock.calls[0][0])).toContain(
      'metric=signet_identity_missing',
    );
    expect(resolve).not.toHaveBeenCalled();
  });

  it('403s a valid token that lacks the admission scope, with a challenge-carrying exception, before calling the resolver', async () => {
    jest.spyOn(Logger.prototype, 'warn').mockImplementation();
    const resolve = authorized();
    const caught = await makeGuard(resolve)
      .canActivate(makeContext({ ...IDENTITY, scopes: ['openid'] }).context)
      .catch((error: unknown) => error);
    expect(caught).toBeInstanceOf(InsufficientScopeException);
    expect((caught as InsufficientScopeException).requiredScopes).toEqual([
      'acme:access',
    ]);
    expect((caught as InsufficientScopeException).message).toContain(
      'acme:access',
    );
    expect(resolve).not.toHaveBeenCalled();
  });

  it('reads the admission scope from the options, not a constant', async () => {
    jest.spyOn(Logger.prototype, 'warn').mockImplementation();
    jest.spyOn(Logger.prototype, 'log').mockImplementation();
    const other = { ...FIXTURE_OPTIONS, admissionScope: 'other:access' };
    const refused = await makeGuard(authorized(), undefined, other)
      .canActivate(makeContext(IDENTITY).context)
      .catch((error: unknown) => error);
    expect((refused as InsufficientScopeException).requiredScopes).toEqual([
      'other:access',
    ]);
    await expect(
      makeGuard(authorized(), undefined, other).canActivate(
        makeContext({ ...IDENTITY, scopes: ['other:access'] }).context,
      ),
    ).resolves.toBe(true);
  });

  // The driver's message is the thing that must NOT reach the key=value
  // line; it is also the thing the operator needs, so it travels in the
  // stack, the second argument. The resolver decides what is "unavailable"
  // and wraps it; the guard answers the wrapper with a 503 and logs the
  // CAUSE's class and stack, not the wrapper's.
  const DRIVER_MESSAGE =
    'connect ECONNREFUSED postgres://acme:hunter2@db.invalid:5432/acme';

  it.each([
    [
      'a named driver error',
      () =>
        Object.assign(new Error(DRIVER_MESSAGE), { name: 'DriverException' }),
      'DriverException',
    ],
    [
      'a bare socket error',
      () => Object.assign(new Error(DRIVER_MESSAGE), { code: 'ECONNREFUSED' }),
      'Error',
    ],
  ])(
    '503s when the resolver reports %s as unavailable, keeping the driver message off the line',
    async (_label, makeError, errorName) => {
      const error = jest.spyOn(Logger.prototype, 'error').mockImplementation();
      const guard = makeGuard(
        jest
          .fn()
          .mockRejectedValue(new PrincipalStoreUnavailableError(makeError())),
      );
      await expect(
        guard.canActivate(makeContext(IDENTITY).context),
      ).rejects.toBeInstanceOf(ServiceUnavailableException);
      const [line, stack] = error.mock.calls[0] as [string, string];
      expect(line).toContain('metric=auth_store_unavailable');
      expect(line).toContain(`errorName=${errorName}`);
      expect(line).not.toContain('hunter2');
      expect(stack).toContain(DRIVER_MESSAGE);
    },
  );

  it('rethrows a programming error from the resolver unchanged (500), not a 503', async () => {
    const error = jest.spyOn(Logger.prototype, 'error').mockImplementation();
    const boom = new TypeError('boom');
    await expect(
      makeGuard(jest.fn().mockRejectedValue(boom)).canActivate(
        makeContext(IDENTITY).context,
      ),
    ).rejects.toBe(boom);
    const [line, stack] = error.mock.calls[0] as [string, string];
    expect(line).toContain('metric=auth_store_error');
    expect(line).toContain('errorName=TypeError');
    expect(line).not.toContain('boom');
    expect(stack).toContain('boom');
  });

  it('does not classify anything itself: an UNWRAPPED socket error is a 500', async () => {
    const error = jest.spyOn(Logger.prototype, 'error').mockImplementation();
    const raw = Object.assign(new Error(DRIVER_MESSAGE), {
      code: 'ECONNREFUSED',
    });
    await expect(
      makeGuard(jest.fn().mockRejectedValue(raw)).canActivate(
        makeContext(IDENTITY).context,
      ),
    ).rejects.toBe(raw);
    expect(String(error.mock.calls[0][0])).toContain('metric=auth_store_error');
  });

  it.each([
    ['null', null, 'object'],
    ['a string', 'boom', 'string'],
  ])(
    'survives the resolver throwing %s: one auth_store_error line, the value rethrown as-is',
    async (_label, thrown, expectedName) => {
      const error = jest.spyOn(Logger.prototype, 'error').mockImplementation();
      await expect(
        makeGuard(jest.fn().mockRejectedValue(thrown)).canActivate(
          makeContext(IDENTITY).context,
        ),
      ).rejects.toBe(thrown);
      expect(error).toHaveBeenCalledTimes(1);
      const [line] = error.mock.calls[0] as [string];
      expect(line).toContain('metric=auth_store_error');
      expect(line).toContain(`errorName=${expectedName}`);
    },
  );

  it('requires the principal resolver instead of inheriting AuthGuard’s optional first parameter', () => {
    expect(
      Reflect.getMetadata('optional:paramtypes', SignetBearerGuard) as unknown,
    ).not.toContain(0);
    // A consumer subclass with no constructor of its own (OrderSync's
    // SignetJwtAuthGuard) reads this class's metadata through the chain.
    class ConsumerGuard extends SignetBearerGuard {}
    expect(
      Reflect.getMetadata('optional:paramtypes', ConsumerGuard) as unknown,
    ).not.toContain(0);
    const declared = Reflect.getMetadata(
      'self:paramtypes',
      SignetBearerGuard,
    ) as { index: number; param: unknown }[];
    expect(declared).toContainEqual({
      index: 0,
      param: SIGNET_PRINCIPAL_RESOLVER,
    });
    expect(
      Reflect.getMetadata('self:paramtypes', ConsumerGuard) as unknown,
    ).toContainEqual({
      index: 0,
      param: SIGNET_PRINCIPAL_RESOLVER,
    });
  });

  it('passes an HttpException thrown by the resolver through as-is, unlogged', async () => {
    const error = jest.spyOn(Logger.prototype, 'error').mockImplementation();
    const refusal = new ForbiddenException('resolver said no');
    await expect(
      makeGuard(jest.fn().mockRejectedValue(refusal)).canActivate(
        makeContext(IDENTITY).context,
      ),
    ).rejects.toBe(refusal);
    expect(error).not.toHaveBeenCalled();
  });
});
