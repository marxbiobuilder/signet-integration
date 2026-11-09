import {
  createParamDecorator,
  type ExecutionContext,
  InternalServerErrorException,
} from '@nestjs/common';

import { type SignetIntegrationOptions } from './options';

// A parameter decorator that reads the principal the Bearer guard attached
// under `requestPrincipalKey`. Built per consumer from the same options the
// guard runs with, because a decorator is evaluated at class definition,
// before any provider exists, so the key cannot come through injection.
//
// `validate` is the runtime shape check: nothing at runtime enforces a
// principal on a handler someone mounted without the guard, and Nest does not
// check the parameter's declared type against what arrives. A failing check
// is a 500, because a missing principal on a protected route is a wiring
// bug, not a caller's credential problem.
export function createSignetPrincipalDecorator<P>(
  options: Pick<SignetIntegrationOptions, 'requestPrincipalKey'>,
  validate: (value: unknown) => value is P,
): () => ParameterDecorator {
  const { requestPrincipalKey } = options;
  return createParamDecorator((_data: unknown, context: ExecutionContext) => {
    const request = context
      .switchToHttp()
      .getRequest<Record<string, unknown>>();
    const value = request[requestPrincipalKey];
    if (!validate(value)) {
      throw new InternalServerErrorException(
        `no principal on request.${requestPrincipalKey}: is the Bearer guard mounted on this route?`,
      );
    }
    return value;
  });
}
