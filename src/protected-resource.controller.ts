import {
  Controller,
  Get,
  Inject,
  Logger,
  NotFoundException,
  type Type,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { type SchemaObject } from '@nestjs/swagger/dist/interfaces/open-api-spec.interface';
import { SkipThrottle } from '@nestjs/throttler';

import { protectedResourceMetadataPath } from './bearer-challenge';
import { readSignetAuthConfig, type SignetAuthConfig } from './config';
import { SignetDeploymentProfileService } from './deployment-profile';
import {
  SIGNET_INTEGRATION_OPTIONS,
  type SignetIntegrationOptions,
} from './options';
import { Public } from './public.decorator';

// RFC 9728 §2, the subset a discovery client reads.
export interface ProtectedResourceMetadata {
  readonly authorization_servers: readonly string[];
  readonly bearer_methods_supported: readonly string[];
  readonly resource: string;
  readonly scopes_supported: readonly string[];
}

const PROTECTED_RESOURCE_METADATA_SCHEMA: SchemaObject = {
  properties: {
    authorization_servers: { items: { type: 'string' }, type: 'array' },
    bearer_methods_supported: { items: { type: 'string' }, type: 'array' },
    resource: { type: 'string' },
    scopes_supported: { items: { type: 'string' }, type: 'array' },
  },
  required: [
    'authorization_servers',
    'bearer_methods_supported',
    'resource',
    'scopes_supported',
  ],
  type: 'object',
};

// Tells a client WHICH authorization server issues tokens for this resource
// (RFC 9728). This controller's whole part in authorisation: it issues
// nothing, it points. An OAuth client goes 401 → the challenge's
// `resource_metadata` → this document's `authorization_servers` → issuer
// discovery → login.
//
// A FACTORY rather than a class, because the route path is a decorator
// argument -- evaluated at class definition, before any provider exists --
// and it is derived from the consumer's canonical resource. The consumer
// calls this once with its options and declares the returned class in the
// module of the process that serves the resource. Nothing else about the
// class depends on the options at definition time; the values it publishes
// are read through injection, from the SAME settings the verifier uses,
// never a second set -- metadata and verification that can be configured
// apart will drift apart.
//
// Public: a client that has no token yet is the one that needs to read it.
// Throttling is skipped: discovery precedes login and must not compete with
// a client's own request budget.
//
// The factory's `options` choose the route; the injected options choose the
// published values. They are the same object in every sane wiring, and the
// constructor refuses to start if they disagree on the metadata path.
export function createProtectedResourceController(
  options: SignetIntegrationOptions,
): Type<{ metadata(): ProtectedResourceMetadata }> {
  const mountedPath = protectedResourceMetadataPath(options);
  @ApiTags('OAuth')
  @Public()
  @Controller(mountedPath)
  class ProtectedResourceController {
    private readonly logger = new Logger(ProtectedResourceController.name);
    private config: SignetAuthConfig | undefined;

    constructor(
      private readonly configService: ConfigService,
      private readonly profiles: SignetDeploymentProfileService,
      @Inject(SIGNET_INTEGRATION_OPTIONS)
      private readonly injected: SignetIntegrationOptions,
    ) {
      const injectedPath = protectedResourceMetadataPath(injected);
      if (injectedPath !== mountedPath) {
        throw new Error(
          `protected resource metadata is mounted at ${mountedPath} but the injected options put it at ${injectedPath}; pass the same options to createProtectedResourceController and to SignetIntegrationModule.forRoot`,
        );
      }
    }

    @Get()
    @SkipThrottle()
    @ApiOkResponse({
      description: 'RFC 9728 protected resource metadata',
      schema: PROTECTED_RESOURCE_METADATA_SCHEMA,
    })
    @ApiNotFoundResponse({
      description: 'The Signet Bearer channel is disabled in this deployment',
    })
    @ApiOperation({
      description:
        'OAuth 2.0 Protected Resource Metadata (RFC 9728) for this ' +
        'resource. Public; no credential required. Available only while ' +
        'the Signet Bearer channel is enabled -- 404 otherwise, so a ' +
        'discovery client is never pointed at an issuer this deployment does ' +
        'not accept tokens from.',
      summary: 'Protected resource metadata',
    })
    metadata(): ProtectedResourceMetadata {
      this.config ??= readSignetAuthConfig(
        this.injected,
        this.configService,
        this.profiles.profile,
      );
      const { jwt } = this.config;
      if (jwt === null) {
        // The 404 body says nothing; this line is what tells it apart from
        // an ingress or routing miss.
        this.logger.warn(
          'protected resource metadata not served: metric=metadata_channel_disabled reason=signet_disabled',
        );
        throw new NotFoundException();
      }
      return {
        authorization_servers: [jwt.issuer],
        bearer_methods_supported: ['header'],
        resource: jwt.audience,
        scopes_supported: this.injected.scopesSupported,
      };
    }
  }
  return ProtectedResourceController;
}
