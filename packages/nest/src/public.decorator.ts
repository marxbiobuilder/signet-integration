import { SetMetadata } from '@nestjs/common';

// Marks a route, or a whole controller, as reachable without a Bearer
// credential. SignetBearerGuard lets a marked route through before running
// the strategy; a consumer's own credential dispatcher reads the same key.
export const IS_PUBLIC_ROUTE = 'signet-integration:public-route';

export const Public = (): ClassDecorator & MethodDecorator =>
  SetMetadata(IS_PUBLIC_ROUTE, true);
