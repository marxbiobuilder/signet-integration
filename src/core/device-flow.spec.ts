import {
  DeviceAuthorization,
  DeviceFlowError,
  type DeviceOptions,
  type DeviceRuntime,
  discoverDeviceEndpoints,
} from './device-flow';
import { type JsonResponse, LoginTransportError } from './login-http';

const options: DeviceOptions = {
  clientId: 'device-client',
  issuer: 'https://issuer.example',
  resource: 'https://resource.example/api/mcp',
  scope: 'openid service:access',
};
const endpoints = {
  device: `${options.issuer}/device-authorize`,
  jwks: `${options.issuer}/jwks`,
  token: `${options.issuer}/token`,
};
const issued = {
  device_code: 'secret-device-code',
  expires_in: 600,
  user_code: 'ABCD-EFGH',
  verification_uri: `${options.issuer}/verify`,
};
const token = {
  access_token: 'secret-access-token',
  expires_in: 300,
  token_type: 'Bearer',
};

function harness(responses: (JsonResponse | Error)[]) {
  let now = 0;
  const waits: number[] = [];
  const requests: URLSearchParams[] = [];
  const rt: DeviceRuntime = {
    http: async (_url, init) => {
      await Promise.resolve();
      if (init.body) requests.push(init.body);
      const response = responses.shift();
      if (!response) throw new Error('unexpected_request');
      if (response instanceof Error) throw response;
      return response;
    },
    now: () => now,
    wait: async (ms, signal) => {
      await Promise.resolve();
      signal.throwIfAborted();
      waits.push(ms);
      now += ms;
    },
  };
  return { requests, rt, waits };
}
const ok = (body: unknown): JsonResponse => ({
  body,
  json: true,
  ok: true,
  status: 200,
});
const error = (code: string): JsonResponse => ({
  body: { error: code },
  json: true,
  ok: false,
  status: 400,
});

describe('device authorization', () => {
  it('honours the RFC default interval, slow_down and timeout backoff without leaking device_code', async () => {
    const h = harness([
      ok(issued),
      error('authorization_pending'),
      error('slow_down'),
      new LoginTransportError('TimeoutError'),
      ok(token),
    ]);
    const signal = new AbortController().signal;
    const flow = await DeviceAuthorization.start(
      options,
      endpoints,
      signal,
      h.rt,
    );
    expect(JSON.stringify(flow)).not.toContain(issued.device_code);
    expect(flow.approval).toEqual({
      expiresIn: 600,
      userCode: issued.user_code,
      verificationUri: issued.verification_uri,
    });
    expect(await flow.poll(signal)).toEqual({
      accessToken: token.access_token,
      expiresIn: 300,
    });
    expect(h.waits).toEqual([5000, 5000, 10000, 20000]);
    expect(h.requests[1].get('device_code')).toBe(issued.device_code);
    expect(h.requests[1].get('resource')).toBe(options.resource);
    expect(h.requests[1].get('grant_type')).toBe(
      'urn:ietf:params:oauth:grant-type:device_code',
    );
    await expect(flow.poll(signal)).rejects.toThrow('request_failed');
  });

  it.each(['access_denied', 'expired_token'])(
    'stops polling on %s',
    async (code) => {
      const h = harness([ok(issued), error(code), ok(token)]);
      const signal = new AbortController().signal;
      const flow = await DeviceAuthorization.start(
        options,
        endpoints,
        signal,
        h.rt,
      );
      await expect(flow.poll(signal)).rejects.toThrow(code);
      expect(h.requests).toHaveLength(2);
    },
  );

  it('cancellation stops the transaction without another token request', async () => {
    const h = harness([ok(issued), ok(token)]);
    const controller = new AbortController();
    const flow = await DeviceAuthorization.start(
      options,
      endpoints,
      controller.signal,
      h.rt,
    );
    controller.abort();
    await expect(flow.poll(controller.signal)).rejects.toThrow('cancelled');
    expect(h.requests).toHaveLength(1);
  });

  it('never polls once the next interval would exceed expiry', async () => {
    const h = harness([ok({ ...issued, expires_in: 5 }), ok(token)]);
    const signal = new AbortController().signal;
    const flow = await DeviceAuthorization.start(
      options,
      endpoints,
      signal,
      h.rt,
    );
    await expect(flow.poll(signal)).rejects.toThrow('expired_token');
    expect(h.requests).toHaveLength(1);
  });

  it.each([
    { interval: 0 },
    { interval: -1 },
    { interval: 0.1 },
    { expires_in: 0 },
    { device_code: '' },
    { user_code: 'code\nforged' },
    { verification_uri: 'http://issuer.example/verify' },
    { verification_uri: 'https://attacker.example/verify' },
    {
      verification_uri_complete: 'https://user:password@issuer.example/verify',
    },
  ])('rejects malformed or unsafe approval metadata: %j', async (override) => {
    const h = harness([ok({ ...issued, ...override })]);
    await expect(
      DeviceAuthorization.start(
        options,
        endpoints,
        new AbortController().signal,
        h.rt,
      ),
    ).rejects.toBeInstanceOf(DeviceFlowError);
  });

  it('does not expose upstream response bodies or error descriptions', async () => {
    const h = harness([
      ok(issued),
      {
        body: {
          error: 'invalid_client',
          error_description: 'secret-device-code secret-access-token',
        },
        json: true,
        ok: false,
        status: 400,
      },
    ]);
    const signal = new AbortController().signal;
    const flow = await DeviceAuthorization.start(
      options,
      endpoints,
      signal,
      h.rt,
    );
    await expect(flow.poll(signal)).rejects.toThrow(/^request_failed$/);
  });
});

describe('device discovery', () => {
  const metadata = {
    device_authorization_endpoint: endpoints.device,
    issuer: options.issuer,
    jwks_uri: endpoints.jwks,
    token_endpoint: endpoints.token,
  };
  it('reads endpoints from the trusted issuer', async () => {
    const h = harness([ok(metadata)]);
    await expect(
      discoverDeviceEndpoints(options, new AbortController().signal, h.rt),
    ).resolves.toEqual(endpoints);
  });
  it.each([
    { issuer: 'https://attacker.example' },
    { token_endpoint: 'https://attacker.example/token' },
    { jwks_uri: 'http://issuer.example/jwks' },
    { device_authorization_endpoint: undefined },
    { token_endpoint: 'https://issuer.example/token#fragment' },
  ])(
    'rejects mismatched metadata before sending codes: %j',
    async (override) => {
      const h = harness([ok({ ...metadata, ...override })]);
      await expect(
        discoverDeviceEndpoints(options, new AbortController().signal, h.rt),
      ).rejects.toThrow('discovery_failed');
      expect(h.requests).toHaveLength(0);
    },
  );
});
