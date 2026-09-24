export {
  bearerChallenge,
  carriesScopeChallenge,
  type ChallengeDecision,
  challengeFor,
  insufficientScopeChallenge,
  InsufficientScopeException,
  isResourceRequest,
  protectedResourceMetadataPath,
  protectedResourceMetadataUrl,
  type ScopeChallengeCarrier,
} from './bearer-challenge';
export { BearerChallengeFilter } from './bearer-challenge.filter';
export {
  type ChannelFlags,
  type JwtSettings,
  readChannelFlags,
  readSignetAuthConfig,
  type SignetAuthConfig,
  type SignetEnvOptions,
} from './config';
export {
  type DeploymentProfile,
  type DeploymentProfileInput,
  type DeploymentProfileResolution,
  resolveDeploymentProfile,
  SignetDeploymentProfileService,
} from './deployment-profile';
export { SignetBearerGuard } from './guard';
export {
  type JwtRejection,
  JwtRejectionEnum,
  JwtVerifier,
  REMOTE_JWKS_OPTIONS,
  type VerifiedSignetIdentity,
  type VerifyResult,
} from './jwt-verifier';
export {
  type ResolverProvider,
  SignetIntegrationModule,
  type SignetIntegrationModuleOptions,
} from './module';
export {
  DEVELOPMENT_ENVIRONMENT,
  SIGNET_INTEGRATION_OPTIONS,
  type SignetDeployedProfile,
  type SignetDevelopmentProfile,
  type SignetEnvNames,
  type SignetIntegrationOptions,
} from './options';
export { createSignetPrincipalDecorator } from './principal.decorator';
export {
  type PrincipalResolution,
  PrincipalStoreUnavailableError,
  SIGNET_PRINCIPAL_RESOLVER,
  type SignetPrincipalResolver,
} from './principal-resolver';
export {
  createProtectedResourceController,
  type ProtectedResourceMetadata,
} from './protected-resource.controller';
export { IS_PUBLIC_ROUTE, Public } from './public.decorator';
export {
  createScopeVocabulary,
  type ScopeVocabulary,
  type ScopeVocabularyInput,
  type TokenScopeRead,
} from './scope-vocabulary';
export {
  bearerToken,
  SIGNET_JWT_STRATEGY,
  SignetJwtStrategy,
} from './strategy';
export { validateSignetIntegrationOptions } from './validate-options';
