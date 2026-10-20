import * as main from './index';
import * as passport from './passport';

// The /passport entry promises everything the main one exports except the
// RFC 9728 metadata controller. The two lists are kept by hand, so a name
// added to one and forgotten in the other is caught here rather than by a
// consumer whose import stops compiling -- for a type-only name, once it is
// also in the tuple below, a third list kept by hand.
describe('entry points', () => {
  it('exports at runtime everything the main entry does, except the metadata controller', () => {
    const missing = Object.keys(main).filter((name) => !(name in passport));
    const extra = Object.keys(passport).filter((name) => !(name in main));
    expect({ extra, missing }).toEqual({
      extra: [],
      missing: ['createProtectedResourceController'],
    });
  });

  // Type-only exports leave nothing at runtime: the compiler checks them,
  // through this tuple naming, from /passport, every one the main entry
  // has bar the controller's ProtectedResourceMetadata.
  it('exports every type-only name of the main entry', () => {
    type PassportTypes = [
      passport.AuthenticatedRequest,
      passport.ChallengeDecision,
      passport.ChannelFlags,
      passport.DecisionContext<unknown>,
      passport.DeploymentProfile,
      passport.DeploymentProfileInput,
      passport.DeploymentProfileResolution<string>,
      passport.IdTokenVerifyResult,
      passport.JwtRejection,
      passport.JwtSettings,
      passport.PrincipalResolution<unknown>,
      passport.ResolverProvider,
      passport.ScopeChallengeCarrier,
      passport.ScopeVocabulary<string>,
      passport.ScopeVocabularyInput<string>,
      passport.SignetAuthConfig,
      passport.SignetBearerRejection,
      passport.SignetDeployedProfile,
      passport.SignetDevelopmentProfile,
      passport.SignetEnvNames,
      passport.SignetEnvOptions,
      passport.SignetIntegrationModuleOptions,
      passport.SignetIntegrationOptions,
      passport.SignetLoginContext,
      passport.SignetLoginEntry,
      passport.SignetLoginFailure,
      passport.SignetLoginStrategyBase<unknown>,
      passport.SignetPassportModuleOptions,
      passport.SignetPrincipalResolver<unknown>,
      passport.TokenScopeRead<string>,
      passport.VerifiedSignetIdentity,
      passport.VerifyResult,
    ];
    const none: PassportTypes | null = null;
    expect(none).toBeNull();
  });
});
