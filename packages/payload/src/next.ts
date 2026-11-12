import type { Payload } from 'payload';
import type { XignetPayloadIntegration } from './types.js';

/** Standard Request/Response handlers for Next.js server route modules. */
export function createXignetRouteHandlers(
  integration: XignetPayloadIntegration,
  options?: { getPayload: () => Promise<Payload> },
) {
  if (integration.loginEnabled && !options)
    throw new Error('SSO routes require a getPayload provider');
  return {
    metadata: async () => integration.metadata(),
    login: (request: Request) => integration.login(request),
    callback: async (request: Request) => {
      if (!integration.loginEnabled || !options)
        return new Response(null, { status: 404 });
      const payload = await options.getPayload();
      if (!payload.config.serverURL)
        return integration.callback(request, payload);
      // Standalone Next requests may use an internal hostname and port.
      // Only configured serverURL supplies the public origin, never headers.
      const incoming = new URL(request.url);
      const callback = new URL(payload.config.serverURL);
      callback.pathname = incoming.pathname;
      callback.search = incoming.search;
      callback.hash = incoming.hash;
      return integration.callback(new Request(callback, request), payload);
    },
  };
}
