/** Reuse one SignetClient instance; the executor owns no token cache or lock. */
export interface BearerTokenProvider {
  getAccessToken(): Promise<string>;
  invalidateToken(rejectedToken: string): void | Promise<void>;
}

export interface BearerAttempt {
  token: string;
  attempt: 1 | 2;
}

/** Normalize HTTP failures into responses; thrown errors mean request failures. */
export interface BearerResponse<T> {
  status: number;
  value: T;
  /** Release unused response resources. Called for every non-2xx response. */
  dispose?: () => void | Promise<void>;
}

export type BearerOperation<T> = (
  context: BearerAttempt,
) => Promise<BearerResponse<T>>;

export interface BearerRequestOptions {
  /** Explicit assertion that invoking the operation again is safe. Default false. */
  retryOnUnauthorized?: boolean;
  /** Safe, credential-free notification after disposal and before token refresh. */
  onRetry?: () => void | Promise<void>;
}

const TRANSPORT_CODES = [
  'ECONNABORTED',
  'ETIMEDOUT',
  'ENOTFOUND',
  'EAI_AGAIN',
  'ECONNREFUSED',
  'ECONNRESET',
  'ERR_NETWORK',
  'ERR_CANCELED',
  'ERR_BAD_REQUEST',
  'ERR_BAD_RESPONSE',
] as const;
export type BearerTransportCode = (typeof TRANSPORT_CODES)[number];

const ERROR_CODES = [
  'INVALID_CONFIGURATION',
  'TOKEN_REQUEST_FAILED',
  'INVALID_TOKEN_RESPONSE',
  'RESOURCE_HTTP_ERROR',
  'RESOURCE_NETWORK_ERROR',
  'RESOURCE_REQUEST_FAILED',
  'INVALID_RESOURCE_RESPONSE',
  'RESOURCE_DISPOSAL_FAILED',
  'RESOURCE_BODY_UNAVAILABLE',
  'RETRY_CALLBACK_FAILED',
] as const;
export type SignetRequestErrorCode = (typeof ERROR_CODES)[number];
export type SignetRequestPhase = 'configuration' | 'token' | 'resource';

function property(value: unknown, key: string): unknown {
  try {
    return value !== null &&
      (typeof value === 'object' || typeof value === 'function')
      ? Reflect.get(value, key)
      : undefined;
  } catch {
    return undefined;
  }
}

function httpStatus(value: unknown): number | undefined {
  return typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 100 &&
    value <= 599
    ? value
    : undefined;
}

function transportCode(value: unknown): BearerTransportCode | undefined {
  return TRANSPORT_CODES.find((code) => code === value);
}

/** Fixed classifications only; never retains an upstream error, body or cause. */
export class SignetRequestError extends Error {
  readonly phase: SignetRequestPhase;
  readonly code: SignetRequestErrorCode;
  readonly attempt: 1 | 2;
  readonly status?: number;
  readonly transportCode?: BearerTransportCode;
  readonly afterUnauthorized: boolean;
  readonly retryExhausted: boolean;

  constructor(
    phase: SignetRequestPhase,
    code: SignetRequestErrorCode,
    attempt: 1 | 2 = 1,
    status?: number,
    networkCode?: BearerTransportCode,
  ) {
    const safePhase = ['configuration', 'token', 'resource'].find(
      (p) => p === phase,
    ) as SignetRequestPhase | undefined;
    const safeCode =
      ERROR_CODES.find((c) => c === code) ?? 'INVALID_CONFIGURATION';
    const safeStatus = httpStatus(status);
    super(
      `Signet request: ${safePhase ?? 'configuration'}/${safeCode}${safeStatus ? ` (HTTP ${safeStatus})` : ''}`,
    );
    this.name = 'SignetRequestError';
    this.phase = safePhase ?? 'configuration';
    this.code = safeCode;
    this.attempt = attempt === 2 ? 2 : 1;
    this.status = safeStatus;
    this.transportCode = transportCode(networkCode);
    this.afterUnauthorized = this.attempt === 2;
    this.retryExhausted =
      this.phase === 'resource' &&
      safeCode === 'RESOURCE_HTTP_ERROR' &&
      safeStatus === 401 &&
      this.attempt === 2;
  }
}

class FetchTransportError extends Error {
  readonly transportCode?: BearerTransportCode;
  constructor(error: unknown) {
    super('Fetch transport failed');
    this.transportCode =
      transportCode(property(error, 'code')) ??
      transportCode(property(property(error, 'cause'), 'code'));
  }
}

/**
 * Run a replayable operation with Bearer auth. Only a resource 401 may trigger
 * one explicitly enabled replay. Factories own payload replayability and
 * business idempotency; two sends do not imply exactly-once execution.
 */
export async function executeWithBearer<T>(
  client: BearerTokenProvider,
  operation: BearerOperation<T>,
  options: BearerRequestOptions = {},
): Promise<T> {
  const acquire = property(client, 'getAccessToken');
  const invalidate = property(client, 'invalidateToken');
  const replayPolicy = property(options, 'retryOnUnauthorized');
  const onRetry = property(options, 'onRetry');
  if (
    !client ||
    typeof acquire !== 'function' ||
    typeof invalidate !== 'function' ||
    typeof operation !== 'function' ||
    !options ||
    typeof options !== 'object' ||
    Array.isArray(options) ||
    (replayPolicy !== undefined && typeof replayPolicy !== 'boolean') ||
    (onRetry !== undefined && typeof onRetry !== 'function')
  ) {
    throw new SignetRequestError('configuration', 'INVALID_CONFIGURATION');
  }
  const retry = replayPolicy === true;
  for (const attempt of [1, 2] as const) {
    let token: string;
    try {
      token = await acquire.call(client);
      if (
        typeof token !== 'string' ||
        !token ||
        /[\s\x00-\x1f\x7f]/.test(token)
      ) {
        throw new SignetRequestError(
          'token',
          'INVALID_TOKEN_RESPONSE',
          attempt,
        );
      }
    } catch (error) {
      const code = property(error, 'code');
      throw new SignetRequestError(
        'token',
        code === 'INVALID_CONFIGURATION' || code === 'INVALID_TOKEN_RESPONSE'
          ? code
          : 'TOKEN_REQUEST_FAILED',
        attempt,
        httpStatus(property(error, 'status')),
      );
    }
    let response: BearerResponse<T>;
    try {
      response = await operation({ token, attempt });
    } catch (error) {
      if (
        error instanceof SignetRequestError &&
        property(error, 'phase') === 'configuration' &&
        property(error, 'code') === 'INVALID_CONFIGURATION'
      ) {
        throw new SignetRequestError(
          'configuration',
          'INVALID_CONFIGURATION',
          attempt,
        );
      }
      const networkCode = transportCode(property(error, 'code'));
      const fetchError = error instanceof FetchTransportError;
      const code =
        error instanceof SignetRequestError &&
        property(error, 'code') === 'RESOURCE_BODY_UNAVAILABLE'
          ? 'RESOURCE_BODY_UNAVAILABLE'
          : fetchError || networkCode
            ? 'RESOURCE_NETWORK_ERROR'
            : 'RESOURCE_REQUEST_FAILED';
      throw new SignetRequestError(
        'resource',
        code,
        attempt,
        undefined,
        fetchError
          ? transportCode(property(error, 'transportCode'))
          : networkCode,
      );
    }
    const status = httpStatus(property(response, 'status'));
    const dispose = property(response, 'dispose');
    const release = async () => {
      try {
        if (typeof dispose === 'function') await dispose.call(response);
      } catch {
        throw new SignetRequestError(
          'resource',
          'RESOURCE_DISPOSAL_FAILED',
          attempt,
          status,
        );
      }
    };
    if (
      status === undefined ||
      (dispose !== undefined && typeof dispose !== 'function')
    ) {
      await release();
      throw new SignetRequestError(
        'resource',
        'INVALID_RESOURCE_RESPONSE',
        attempt,
      );
    }
    if (status >= 200 && status < 300) {
      try {
        return await response.value;
      } catch {
        await release();
        throw new SignetRequestError(
          'resource',
          'INVALID_RESOURCE_RESPONSE',
          attempt,
          status,
        );
      }
    }
    let invalidationFailed = false;
    if (status === 401) {
      try {
        await invalidate.call(client, token);
      } catch {
        invalidationFailed = true;
      }
    }
    await release();
    if (invalidationFailed)
      throw new SignetRequestError(
        'configuration',
        'INVALID_CONFIGURATION',
        attempt,
      );
    if (status === 401 && retry && attempt === 1) {
      try {
        if (typeof onRetry === 'function') await onRetry();
      } catch {
        throw new SignetRequestError(
          'resource',
          'RETRY_CALLBACK_FAILED',
          attempt,
          status,
        );
      }
      continue;
    }
    throw new SignetRequestError(
      'resource',
      'RESOURCE_HTTP_ERROR',
      attempt,
      status,
    );
  }
  throw new SignetRequestError('configuration', 'INVALID_CONFIGURATION');
}

/**
 * Native fetch adapter. Each invocation asks the factory for a fresh Request.
 * HTTPS and redirect:error protect Bearer credentials; one-shot bodies cannot
 * be reused, including when a custom transport does not mark them consumed.
 */
export function createFetchOperation(
  factory: (attempt: 1 | 2) => Request | Promise<Request>,
  fetch: typeof globalThis.fetch = globalThis.fetch,
): BearerOperation<Response> {
  if (typeof factory !== 'function' || typeof fetch !== 'function') {
    throw new SignetRequestError('configuration', 'INVALID_CONFIGURATION');
  }
  const bodies = new WeakSet<ReadableStream>();
  return async ({ token, attempt }) => {
    const request = await factory(attempt);
    if (
      !(request instanceof Request) ||
      new URL(request.url).protocol !== 'https:'
    ) {
      throw new SignetRequestError('configuration', 'INVALID_CONFIGURATION');
    }
    if (
      request.body &&
      (request.bodyUsed || request.body.locked || bodies.has(request.body))
    ) {
      throw new SignetRequestError(
        'resource',
        'RESOURCE_BODY_UNAVAILABLE',
        attempt,
      );
    }
    if (request.body) bodies.add(request.body);
    const headers = new Headers(request.headers);
    headers.set('Authorization', `Bearer ${token}`);
    let response: Response;
    const authenticated = new Request(request, { headers, redirect: 'error' });
    try {
      response = await fetch(authenticated);
    } catch (error) {
      throw new FetchTransportError(error);
    }
    return {
      status: response.status,
      value: response,
      dispose: () => response.body?.cancel(),
    };
  };
}
