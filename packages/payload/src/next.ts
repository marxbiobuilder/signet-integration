import type { XignetPayloadIntegration } from './types.js';

/** Standard Request/Response handlers, usable from a Next.js route module. */
export function createXignetRouteHandlers(
  integration: XignetPayloadIntegration,
) {
  return { metadata: async () => integration.metadata() };
}
