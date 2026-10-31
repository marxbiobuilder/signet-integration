import {
  type CallToolResult,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';

import {
  DeviceAuthorization,
  DeviceFlowError,
  type DeviceRuntime,
  discoverDeviceEndpoints,
} from '../../../src/core/device-flow';
import { JwtVerifier } from '../../../src/core/jwt-verifier';
import { fetchJson } from '../../../src/core/login-http';
import { type AdapterProfile } from './config';
import { connectUpstream, type Upstream } from './upstream';

type State =
  | 'idle'
  | 'starting'
  | 'pending'
  | 'connecting'
  | 'ready'
  | 'expired'
  | 'denied'
  | 'error'
  | 'reauth_required';

export class AuthSession {
  private state: State = 'idle';
  private generation = 0;
  private controller = new AbortController();
  private flow?: DeviceAuthorization;
  private token?: string;
  private upstream?: Upstream;
  private expiry?: number;
  private subject?: string;
  private failure?: string;
  private expiryTimer?: NodeJS.Timeout;

  constructor(
    readonly profile: AdapterProfile,
    private readonly changed: () => void,
    private readonly dependencies: {
      runtime?: DeviceRuntime;
      connect?: typeof connectUpstream;
      checkResource?: (signal: AbortSignal) => Promise<void>;
    } = {},
  ) {}

  private now(): number {
    return this.dependencies.runtime?.now() ?? Date.now();
  }

  private reset(state: State): void {
    this.generation++;
    this.controller.abort();
    this.controller = new AbortController();
    clearTimeout(this.expiryTimer);
    const upstream = this.upstream;
    this.upstream = undefined;
    this.token = undefined;
    this.flow = undefined;
    this.expiry = undefined;
    this.subject = undefined;
    this.failure = undefined;
    this.state = state;
    if (upstream) void upstream.close().catch(() => undefined);
    this.changed();
  }

  disconnect(): void {
    this.reset('idle');
  }

  status(): Record<string, unknown> {
    if (
      this.state === 'ready' &&
      this.expiry !== undefined &&
      this.now() >= this.expiry
    )
      this.reset('reauth_required');
    return {
      environment: this.profile.environment,
      resource: this.profile.resource,
      service: this.profile.service,
      state: this.state,
      ...(this.failure ? { reason: this.failure } : {}),
      ...(this.expiry === undefined
        ? {}
        : { expiresAt: new Date(this.expiry).toISOString() }),
      ...(this.subject ? { subject: this.subject } : {}),
    };
  }

  protect<T>(value: T): T {
    return JSON.parse(
      JSON.stringify(value, (_key, item: unknown) => {
        if (typeof item !== 'string') return item;
        const redacted = this.flow?.redact(item) ?? item;
        return this.token
          ? redacted.replaceAll(this.token, '[REDACTED]')
          : redacted;
      }),
    ) as T;
  }

  async begin(): Promise<Record<string, unknown>> {
    this.status();
    if (['starting', 'pending', 'connecting', 'ready'].includes(this.state)) {
      return this.protect({
        ...this.status(),
        ...(this.state === 'pending' ? this.flow?.approval : {}),
      });
    }
    this.reset('starting');
    const generation = this.generation;
    const { signal } = this.controller;
    try {
      await (this.dependencies.checkResource?.(signal) ??
        this.checkResource(signal));
      const endpoints = await discoverDeviceEndpoints(
        this.profile,
        signal,
        this.dependencies.runtime,
      );
      const flow = await DeviceAuthorization.start(
        this.profile,
        endpoints,
        signal,
        this.dependencies.runtime,
      );
      if (generation !== this.generation) return this.status();
      this.flow = flow;
      this.state = 'pending';
      void this.finish(flow, endpoints.jwks, generation, signal);
      return this.protect({ ...this.status(), ...flow.approval });
    } catch (error) {
      if (generation === this.generation) this.fail(error);
      return this.status();
    }
  }

  private async checkResource(signal: AbortSignal): Promise<void> {
    const target = new URL(this.profile.resource);
    const url = `${target.origin}/.well-known/oauth-protected-resource${target.pathname}`;
    const response = await fetchJson(url, { signal }, 5000);
    const body = response.body as {
      resource?: unknown;
      authorization_servers?: unknown;
    } | null;
    if (
      !response.ok ||
      !response.json ||
      body?.resource !== this.profile.resource ||
      !Array.isArray(body.authorization_servers) ||
      !body.authorization_servers.includes(this.profile.issuer)
    ) {
      throw new Error('resource_metadata_invalid');
    }
  }

  private async finish(
    flow: DeviceAuthorization,
    jwks: string,
    generation: number,
    signal: AbortSignal,
  ): Promise<void> {
    try {
      const result = await flow.poll(signal);
      if (generation !== this.generation) return;
      this.token = result.accessToken;
      this.state = 'connecting';
      const verified = await new JwtVerifier({
        audience: this.profile.resource,
        clockToleranceS: 0,
        issuer: this.profile.issuer,
        jwksUri: jwks,
      }).verify(result.accessToken);
      if (!verified.ok) throw new Error('token_rejected');
      const { claims, scopes, clientId, subject } = verified.identity;
      if (
        clientId !== this.profile.clientId ||
        (Array.isArray(claims.aud) && claims.aud.length !== 1) ||
        this.profile.scope
          .split(' ')
          .filter((s) => s !== 'openid')
          .some((s) => !scopes.includes(s)) ||
        typeof claims.email !== 'string' ||
        claims.email.length > 254 ||
        !/^[^\s@]+@[^\s@]+$/.test(claims.email)
      ) {
        throw new Error('token_rejected');
      }
      const expiry = Math.min(
        (claims.exp as number) * 1000,
        this.now() + result.expiresIn * 1000,
      );
      if (expiry <= this.now()) throw new Error('token_rejected');
      const upstream = await (this.dependencies.connect ?? connectUpstream)(
        this.profile.resource,
        result.accessToken,
        signal,
      );
      if (generation !== this.generation || expiry <= this.now()) {
        await upstream.close();
        if (generation === this.generation) this.reset('reauth_required');
        return;
      }
      this.upstream = upstream;
      this.expiry = expiry;
      this.subject = subject;
      this.state = 'ready';
      this.expiryTimer = setTimeout(
        () => this.reset('reauth_required'),
        expiry - this.now(),
      );
      this.expiryTimer.unref();
      this.changed();
    } catch (error) {
      if (generation === this.generation) this.fail(error);
    }
  }

  private fail(error: unknown): void {
    const reason =
      error instanceof DeviceFlowError ? error.code : 'authorization_failed';
    this.reset(
      reason === 'access_denied'
        ? 'denied'
        : reason === 'expired_token'
          ? 'expired'
          : 'error',
    );
    this.failure = reason;
  }

  tools(): Tool[] {
    this.status();
    return this.state === 'ready' && this.upstream
      ? this.protect(
          this.upstream.tools.map((tool) => ({
            ...tool,
            name: `upstream__${tool.name}`,
          })),
        )
      : [];
  }

  async call(
    name: string,
    args: Record<string, unknown> | undefined,
    signal: AbortSignal,
  ): Promise<CallToolResult> {
    this.status();
    const upstream = this.upstream;
    const generation = this.generation;
    if (
      this.state !== 'ready' ||
      !upstream ||
      !upstream.tools.some((tool) => `upstream__${tool.name}` === name)
    )
      return toolError('AUTHORIZATION_REQUIRED');
    try {
      const result = await upstream.call(
        name.slice('upstream__'.length),
        args,
        signal,
      );
      if (generation !== this.generation)
        return toolError('AUTHORIZATION_REQUIRED');
      this.status();
      if (this.state !== 'ready') return toolError('AUTHORIZATION_REQUIRED');
      return this.protect(result);
    } catch {
      if (generation === this.generation) this.reset('reauth_required');
      return toolError('UPSTREAM_CALL_FAILED_CHECK_RESULT_BEFORE_RETRY');
    }
  }
}

export function toolError(code: string): CallToolResult {
  return {
    content: [{ text: JSON.stringify({ code }), type: 'text' }],
    isError: true,
  };
}
