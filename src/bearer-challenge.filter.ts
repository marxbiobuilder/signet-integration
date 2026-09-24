import {
  type ArgumentsHost,
  Catch,
  ForbiddenException,
  Inject,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { BaseExceptionFilter, HttpAdapterHost } from '@nestjs/core';
import type { Request, Response } from 'express';

import { challengeFor } from './bearer-challenge';
import { type ChannelFlags, readChannelFlags } from './config';
import { SignetDeploymentProfileService } from './deployment-profile';
import { sanitiseLogToken } from './log-sanitise';
import {
  SIGNET_INTEGRATION_OPTIONS,
  type SignetIntegrationOptions,
} from './options';

// Attaches `WWW-Authenticate` to the refusals that admit one (RFC 6750 §3,
// RFC 9728 §5.1). A 401 raised anywhere the Nest router reaches -- a guard,
// an interceptor, a handler -- carries the same header. Middleware mounted on
// the http adapter (Swagger's Basic auth, say) never reaches the router and
// keeps its own challenge.
//
// The rendering of the response itself is untouched -- `super.catch` is
// Nest's own -- so the body stays whatever the exception carries, and only
// the header is added. A consumer that renders its own bodies keeps its own
// filter and calls `challengeFor` from it instead of registering this one.
//
// With the Signet channel on, a 401 from a route that authenticates with a
// different credential gets the Bearer challenge too.
@Catch(ForbiddenException, UnauthorizedException)
export class BearerChallengeFilter extends BaseExceptionFilter {
  private readonly logger = new Logger(BearerChallengeFilter.name);
  private readonly channels: ChannelFlags;

  constructor(
    private readonly profiles: SignetDeploymentProfileService,
    adapterHost: HttpAdapterHost,
    configService: ConfigService,
    @Inject(SIGNET_INTEGRATION_OPTIONS)
    private readonly options: SignetIntegrationOptions,
  ) {
    super(adapterHost.httpAdapter);
    this.channels = readChannelFlags(options, configService);
  }

  override catch(
    exception: ForbiddenException | UnauthorizedException,
    host: ArgumentsHost,
  ): void {
    const request = host.switchToHttp().getRequest<Request>();
    const decision = challengeFor(
      this.options,
      this.profiles.profile,
      this.channels,
      exception,
      request.path,
    );
    if (decision.header !== null) {
      host
        .switchToHttp()
        .getResponse<Response>()
        .setHeader('WWW-Authenticate', decision.header);
    } else if (decision.malformedCarrier) {
      // A 403 that CARRIES `requiredScopes` in a shape that cannot be
      // rendered is a bug in a carrier: still answered bare (a broken header
      // helps no one), but not SILENTLY bare -- the structural check would
      // otherwise turn a bug into a correct-looking response.
      this.logger.warn(
        `403 carries malformed requiredScopes, answered without challenge: metric=scope_challenge_malformed errorName=${sanitiseLogToken(exception.name)}`,
      );
    }
    super.catch(exception, host);
  }
}
