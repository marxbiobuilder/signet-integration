import { setTimeout as delay } from 'node:timers/promises';

import { discoveryUrl } from './login-discovery';
import { fetchJson, LoginTransportError } from './login-http';

export type DeviceFailure =
  | 'access_denied'
  | 'cancelled'
  | 'discovery_failed'
  | 'expired_token'
  | 'invalid_response'
  | 'request_failed';

export class DeviceFlowError extends Error {
  constructor(readonly code: DeviceFailure) {
    super(code);
    this.name = 'DeviceFlowError';
  }
}

export interface DeviceEndpoints {
  readonly device: string;
  readonly jwks: string;
  readonly token: string;
}

export interface DeviceApproval {
  readonly verificationUri: string;
  readonly verificationUriComplete?: string;
  readonly userCode: string;
  readonly expiresIn: number;
}

export interface DeviceOptions {
  readonly issuer: string;
  readonly clientId: string;
  readonly resource: string;
  readonly scope: string;
  readonly timeoutMs?: number;
  // Only for local test issuers; the shipped CLI exposes no insecure flag.
  readonly allowLoopbackHttp?: boolean;
}

export interface DeviceRuntime {
  readonly http: typeof fetchJson;
  readonly now: () => number;
  readonly wait: (ms: number, signal: AbortSignal) => Promise<void>;
}

const runtime: DeviceRuntime = {
  http: fetchJson,
  now: Date.now,
  wait: async (ms, signal) => {
    await delay(ms, undefined, { signal });
  },
};

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new DeviceFlowError('invalid_response');
  }
  return value as Record<string, unknown>;
}

function positive(value: unknown, maximum: number): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value <= 0 ||
    value > maximum
  ) {
    throw new DeviceFlowError('invalid_response');
  }
  return value;
}

function string(value: unknown, maximum: number): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maximum ||
    /[\p{Cc}\u2028\u2029]/u.test(value)
  ) {
    throw new DeviceFlowError('invalid_response');
  }
  return value;
}

export function trustedEndpoint(
  value: unknown,
  options: DeviceOptions,
): string {
  try {
    const issuer = new URL(options.issuer);
    const endpoint = new URL(string(value, 4096));
    const local =
      options.allowLoopbackHttp === true &&
      issuer.protocol === 'http:' &&
      ['127.0.0.1', '[::1]'].includes(issuer.hostname);
    if (
      (!local && issuer.protocol !== 'https:') ||
      issuer.username ||
      issuer.password ||
      issuer.search ||
      issuer.hash ||
      endpoint.origin !== issuer.origin ||
      endpoint.username ||
      endpoint.password ||
      endpoint.hash
    ) {
      throw new DeviceFlowError('invalid_response');
    }
    return endpoint.href;
  } catch {
    throw new DeviceFlowError('invalid_response');
  }
}

export async function discoverDeviceEndpoints(
  options: DeviceOptions,
  signal: AbortSignal,
  rt: DeviceRuntime = runtime,
): Promise<DeviceEndpoints> {
  try {
    const url = trustedEndpoint(discoveryUrl(options.issuer), options);
    const response = await rt.http(url, { signal }, options.timeoutMs ?? 5000);
    if (!response.ok || !response.json) throw new Error();
    const body = record(response.body);
    if (body.issuer !== options.issuer) throw new Error();
    return {
      device: trustedEndpoint(body.device_authorization_endpoint, options),
      jwks: trustedEndpoint(body.jwks_uri, options),
      token: trustedEndpoint(body.token_endpoint, options),
    };
  } catch {
    throw new DeviceFlowError(
      signal.aborted ? 'cancelled' : 'discovery_failed',
    );
  }
}

export class DeviceAuthorization {
  private polled = false;
  readonly #code: string;

  private constructor(
    readonly approval: DeviceApproval,
    code: string,
    private intervalMs: number,
    private readonly deadline: number,
    private readonly options: DeviceOptions,
    private readonly endpoints: DeviceEndpoints,
    private readonly rt: DeviceRuntime,
  ) {
    this.#code = code;
  }

  static async start(
    options: DeviceOptions,
    endpoints: DeviceEndpoints,
    signal: AbortSignal,
    rt: DeviceRuntime = runtime,
  ): Promise<DeviceAuthorization> {
    try {
      // Signet selects the audience using a single-resource client. This
      // extension parameter is carried, but is not evidence of selection.
      const response = await rt.http(
        trustedEndpoint(endpoints.device, options),
        {
          body: new URLSearchParams({
            client_id: options.clientId,
            resource: options.resource,
            scope: options.scope,
          }),
          method: 'POST',
          signal,
        },
        options.timeoutMs ?? 5000,
      );
      if (!response.ok || !response.json)
        throw new DeviceFlowError('request_failed');
      const body = record(response.body);
      const expiresIn = positive(body.expires_in, 3600);
      const interval = positive(body.interval ?? 5, 3600);
      const approval: DeviceApproval = {
        expiresIn,
        userCode: string(body.user_code, 64),
        verificationUri: trustedEndpoint(body.verification_uri, options),
        ...(body.verification_uri_complete === undefined
          ? {}
          : {
              verificationUriComplete: trustedEndpoint(
                body.verification_uri_complete,
                options,
              ),
            }),
      };
      return new DeviceAuthorization(
        Object.freeze(approval),
        string(body.device_code, 4096),
        interval * 1000,
        rt.now() + expiresIn * 1000,
        options,
        endpoints,
        rt,
      );
    } catch (error) {
      if (signal.aborted) throw new DeviceFlowError('cancelled');
      if (error instanceof DeviceFlowError) throw error;
      throw new DeviceFlowError('request_failed');
    }
  }

  redact(text: string): string {
    return text.replaceAll(this.#code, '[REDACTED]');
  }

  async poll(
    signal: AbortSignal,
  ): Promise<{ accessToken: string; expiresIn: number }> {
    if (this.polled) throw new DeviceFlowError('request_failed');
    this.polled = true;
    while (!signal.aborted) {
      const remaining = this.deadline - this.rt.now();
      if (remaining <= this.intervalMs)
        throw new DeviceFlowError('expired_token');
      try {
        await this.rt.wait(this.intervalMs, signal);
        if (signal.aborted) break;
        if (this.rt.now() >= this.deadline)
          throw new DeviceFlowError('expired_token');
        const response = await this.rt.http(
          trustedEndpoint(this.endpoints.token, this.options),
          {
            body: new URLSearchParams({
              client_id: this.options.clientId,
              device_code: this.#code,
              grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
              resource: this.options.resource,
            }),
            method: 'POST',
            signal,
          },
          Math.min(
            this.options.timeoutMs ?? 5000,
            this.deadline - this.rt.now(),
          ),
        );
        if (!response.json) throw new DeviceFlowError('invalid_response');
        const body = record(response.body);
        if (response.ok) {
          if (
            typeof body.token_type !== 'string' ||
            body.token_type.toLowerCase() !== 'bearer'
          )
            throw new DeviceFlowError('invalid_response');
          return {
            accessToken: string(body.access_token, 65536),
            expiresIn: positive(body.expires_in, 86400),
          };
        }
        if (body.error === 'authorization_pending') continue;
        if (body.error === 'slow_down') {
          this.intervalMs += 5000;
          continue;
        }
        if (body.error === 'access_denied' || body.error === 'expired_token') {
          throw new DeviceFlowError(body.error);
        }
        throw new DeviceFlowError('request_failed');
      } catch (error) {
        if (signal.aborted) break;
        if (
          error instanceof LoginTransportError &&
          error.detail.startsWith('TimeoutError')
        ) {
          this.intervalMs = Math.min(this.intervalMs * 2, 3600000);
          continue;
        }
        if (error instanceof DeviceFlowError) throw error;
        throw new DeviceFlowError('request_failed');
      }
    }
    throw new DeviceFlowError('cancelled');
  }
}
