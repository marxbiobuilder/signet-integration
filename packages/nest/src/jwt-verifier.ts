// Preserve the Nest package's public verifier contract while sharing its
// implementation with framework-independent resource servers.
export {
  type IdTokenVerifyResult,
  type JwtRejection,
  JwtRejectionEnum,
  JwtVerifier,
  REMOTE_JWKS_OPTIONS,
  type VerifiedSignetIdentity,
  type VerifyResult,
} from '@xignet/core';
