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
      return integration.callback(request, await options.getPayload());
    },
  };
}
