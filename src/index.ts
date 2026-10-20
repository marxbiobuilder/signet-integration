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
export { type DecisionContext, SignetDecision } from './decision';
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
export { type SignetLoginEntry } from './login-entry';
export {
  SignetLoginError,
  type SignetLoginFailure,
  SignetLoginFailureEnum,
} from './login-error';
export {
  SignetLoginStrategy,
  type SignetLoginStrategyBase,
} from './login-strategy';
export {
  type ResolverProvider,
  SignetIntegrationModule,
  type SignetIntegrationModuleOptions,
  type SignetPassportModuleOptions,
} from './module';
export {
  DEVELOPMENT_ENVIRONMENT,
  SIGNET_INTEGRATION_OPTIONS,
  type SignetDeployedProfile,
  type SignetDevelopmentProfile,
  type SignetEnvNames,
  type SignetIntegrationOptions,
} from './options';
export {
  type AuthenticatedRequest,
  SignetPassportGuard,
} from './passport-guard';
export { createSignetPrincipalDecorator } from './principal.decorator';
export {
  type PrincipalResolution,
  PrincipalStoreUnavailableError,
  SIGNET_PRINCIPAL_RESOLVER,
  type SignetPrincipalResolver,
} from './principal-resolver';
export { SignetPrincipalStrategy } from './principal-strategy';
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
  type SignetBearerRejection,
  SignetBearerRejectionEnum,
  SignetBearerVerification,
  SignetJwtStrategy,
} from './strategy';
export { validateSignetIntegrationOptions } from './validate-options';
