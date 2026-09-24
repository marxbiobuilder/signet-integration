// Token-level narrowing: one token carries no more than the scopes it was
// issued with, even when its holder's local authorization says more. The
// consumer supplies its action vocabulary; this file supplies the rules.

export interface TokenScopeRead<A extends string> {
  readonly actions: ReadonlySet<A>;
}

export interface ScopeVocabularyInput<A extends string> {
  // The OAuth scope that admits a token to the service at all; published
  // first in `scopes_supported` and prepended to every re-authorisation
  // advice, because RFC 6750 §3 defines `scope` as "the scope necessary to
  // access the protected resource" and a client re-authorising without it is
  // refused at the door.
  readonly admissionScope: string;
  // Every business action the consumer distinguishes.
  readonly actions: readonly A[];
  // What a token that asked for nothing recognisable may do. Fail-closed: a
  // token carrying no recognised scope gets this default, not everything.
  // Must be a subset of `actions`.
  readonly defaultActions: ReadonlySet<A>;
  // How an action is spelled as an OAuth scope: one scope per action, one
  // action per scope, so a scope string says what it permits without a lookup
  // and a new action cannot widen a token that carries explicit action
  // scopes. Identity by default. Checked at construction to be one-to-one and
  // disjoint from the admission scope.
  readonly tokenScopeFor?: (action: A) => string;
}

export interface ScopeVocabulary<A extends string> {
  // The inverse, derived from the encoder rather than from the action names
  // so the two directions cannot drift. A Map because `scope` is open text
  // from a token: `constructor` and `__proto__` must not resolve to anything.
  readonly actionByScope: ReadonlyMap<string, A>;
  // Reads a token's granted scopes. An unrecognised scope contributes no
  // action; no recognised scope at all yields the default.
  readonly readTokenScopes: (scopes: readonly string[]) => TokenScopeRead<A>;
  // The scope set a token needs in order to exercise `action` WITHOUT losing
  // what it already carries -- the union of `held` and `action`, plus the
  // admission scope -- rendered into the insufficient_scope challenge. Advice
  // naming the missing action alone would mint a credential that drops
  // everything the token has.
  readonly scopesForAction: (
    action: A,
    held: ReadonlySet<A>,
  ) => readonly string[];
  // `scopes_supported` for the RFC 9728 metadata: admission scope first, then
  // every action scope. A scope absent here is one no caller can discover.
  readonly supportedScopes: readonly string[];
  readonly tokenScopeFor: (action: A) => string;
}

export function createScopeVocabulary<A extends string>(
  input: ScopeVocabularyInput<A>,
): ScopeVocabulary<A> {
  const tokenScopeFor = input.tokenScopeFor ?? ((action: A) => action);
  const actionByScope: ReadonlyMap<string, A> = new Map(
    input.actions.map((action) => [tokenScopeFor(action), action]),
  );
  // The invariants the rest of this file relies on, refused rather than
  // silently repaired: a non-injective encoder would make the Map keep the
  // later action (a scope grants the wrong thing and `supportedScopes` loses
  // one); an action spelled as the admission scope would make admission grant
  // a business action; a default outside the vocabulary could never be
  // narrowed away.
  if (actionByScope.size !== new Set(input.actions).size) {
    throw new Error(
      'scope vocabulary: tokenScopeFor must map actions to distinct scopes',
    );
  }
  for (const scope of actionByScope.keys()) {
    if (scope === '' || /[\s"\\]/.test(scope)) {
      throw new Error(
        `scope vocabulary: ${JSON.stringify(scope)} is not a scope token (no space, quote or backslash)`,
      );
    }
  }
  if (actionByScope.has(input.admissionScope)) {
    throw new Error(
      `scope vocabulary: an action is spelled as the admission scope ${input.admissionScope}`,
    );
  }
  for (const action of input.defaultActions) {
    if (!input.actions.includes(action)) {
      throw new Error(
        `scope vocabulary: default action ${String(action)} is not in actions`,
      );
    }
  }
  return {
    actionByScope,
    readTokenScopes: (scopes) => {
      const actions = new Set<A>();
      for (const scope of scopes) {
        const action = actionByScope.get(scope);
        if (action !== undefined) actions.add(action);
      }
      if (actions.size > 0) return { actions };
      return { actions: input.defaultActions };
    },
    scopesForAction: (action, held) => {
      const actions = new Set(held);
      actions.add(action);
      return [input.admissionScope, ...[...actions].map(tokenScopeFor).sort()];
    },
    supportedScopes: [
      input.admissionScope,
      ...[...actionByScope.keys()].sort(),
    ],
    tokenScopeFor,
  };
}
