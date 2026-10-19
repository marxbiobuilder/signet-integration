// The login flow's two calls to the issuer -- discovery and the token
// endpoint -- made one way: no redirects followed (a 307 would carry a POST
// body holding the code and the PKCE verifier to wherever it pointed), one
// timeout covering the body as well as the headers, and a JSON body parsed
// apart from the transport so the two failures stay distinguishable.

// Any rejection of fetch() or of reading its body: refused, reset, a
// redirect refused, timed out, a body that stalled. fetch() cannot tell those
// from its own argument errors, so the URLs are checked before they get
// here (the issuer at construction, the endpoints by discovery) and nothing
// else this file passes can be malformed. `detail` is transportFailure()'s.
export class LoginTransportError extends Error {
  constructor(readonly detail: string) {
    super(`signet login transport failed: ${detail}`);
    this.name = 'LoginTransportError';
  }
}

export interface JsonResponse {
  // Undefined when `json` is false.
  readonly body: unknown;
  readonly json: boolean;
  readonly ok: boolean;
  readonly status: number;
}

export async function fetchJson(
  url: string,
  init: { body?: URLSearchParams; method?: 'GET' | 'POST' },
  timeoutMs: number,
): Promise<JsonResponse> {
  // Outside the try: a bad timeout is this process's defect, not transport.
  const signal = AbortSignal.timeout(timeoutMs);
  let response: Response;
  let text: string;
  try {
    response = await fetch(url, {
      body: init.body,
      headers: {
        accept: 'application/json',
        ...(init.body === undefined
          ? {}
          : { 'content-type': 'application/x-www-form-urlencoded' }),
      },
      method: init.method ?? 'GET',
      redirect: 'error',
      signal,
    });
    // Inside the try: the timeout covers the body too.
    text = await response.text();
  } catch (error) {
    throw new LoginTransportError(transportFailure(error));
  }
  try {
    return {
      body: JSON.parse(text) as unknown,
      json: true,
      ok: response.ok,
      status: response.status,
    };
  } catch {
    return {
      body: undefined,
      json: false,
      ok: response.ok,
      status: response.status,
    };
  }
}

// A fetch that never produced a response, as `<name>[:<cause>]`: the error's
// name, then its cause's code when it has one, else its cause's name. On
// Node 22's undici that reads TimeoutError (a timeout, the body's included),
// TypeError:ECONNREFUSED (nothing listening), TypeError:UND_ERR_SOCKET (the
// connection reset) and TypeError:Error (a redirect refused). The exact
// labels are undici's and may shift with it; the shape is this function's.
// Never a message, which can carry the URL. Matched by shape: undici's
// DOMException and Node's system errors are created outside a test runner's
// vm realm, where instanceof Error is false.
export function transportFailure(error: unknown): string {
  const { cause, name } = (error ?? {}) as {
    cause?: { code?: unknown; name?: unknown };
    name?: unknown;
  };
  const label = typeof name === 'string' && name !== '' ? name : 'unknown';
  if (typeof cause?.code === 'string') return `${label}:${cause.code}`;
  if (typeof cause?.name === 'string' && cause.name !== '') {
    return `${label}:${cause.name}`;
  }
  return label;
}
