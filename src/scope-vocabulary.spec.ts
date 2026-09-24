import { createScopeVocabulary } from './scope-vocabulary';

type Action = 'widgets:read' | 'widgets:write' | 'orders:read';
const ACTIONS: readonly Action[] = [
  'widgets:read',
  'widgets:write',
  'orders:read',
];

const vocabulary = createScopeVocabulary<Action>({
  actions: ACTIONS,
  admissionScope: 'acme:access',
  defaultActions: new Set<Action>(['widgets:read']),
});

describe('createScopeVocabulary', () => {
  it('spells each action as itself by default and lists the admission scope first', () => {
    expect(vocabulary.tokenScopeFor('widgets:write')).toBe('widgets:write');
    expect(vocabulary.supportedScopes).toEqual([
      'acme:access',
      'orders:read',
      'widgets:read',
      'widgets:write',
    ]);
  });

  it('reads recognised scopes and falls back to the default when none is recognised', () => {
    expect(
      vocabulary.readTokenScopes(['acme:access', 'widgets:write', 'x:y']),
    ).toEqual({ actions: new Set(['widgets:write']) });
    expect(vocabulary.readTokenScopes(['acme:access', 'x:y'])).toEqual({
      actions: new Set(['widgets:read']),
    });
    // Open text from a token must not resolve prototype members.
    expect(vocabulary.readTokenScopes(['constructor', '__proto__'])).toEqual({
      actions: new Set(['widgets:read']),
    });
  });

  it('advises the union of held and needed actions, admission scope first', () => {
    expect(
      vocabulary.scopesForAction(
        'orders:read',
        new Set<Action>(['widgets:write']),
      ),
    ).toEqual(['acme:access', 'orders:read', 'widgets:write']);
  });

  it('honours a custom encoder in both directions', () => {
    const prefixed = createScopeVocabulary<Action>({
      actions: ACTIONS,
      admissionScope: 'acme:access',
      defaultActions: new Set<Action>(),
      tokenScopeFor: (action) => `acme.${action.replace(':', '.')}`,
    });
    expect(prefixed.supportedScopes).toEqual([
      'acme:access',
      'acme.orders.read',
      'acme.widgets.read',
      'acme.widgets.write',
    ]);
    expect(prefixed.readTokenScopes(['acme.widgets.write'])).toEqual({
      actions: new Set(['widgets:write']),
    });
  });

  // The invariants the file's comments state, refused rather than repaired.
  it('refuses an encoder that maps two actions to one scope', () => {
    expect(() =>
      createScopeVocabulary<Action>({
        actions: ACTIONS,
        admissionScope: 'acme:access',
        defaultActions: new Set<Action>(),
        tokenScopeFor: (action) => action.split(':')[0],
      }),
    ).toThrow(/distinct scopes/);
  });

  it('refuses an action spelled as the admission scope', () => {
    expect(() =>
      createScopeVocabulary<Action>({
        actions: ACTIONS,
        admissionScope: 'widgets:read',
        defaultActions: new Set<Action>(),
      }),
    ).toThrow(/admission scope/);
  });

  it('refuses an encoder that produces a non-token scope', () => {
    expect(() =>
      createScopeVocabulary<Action>({
        actions: ACTIONS,
        admissionScope: 'acme:access',
        defaultActions: new Set<Action>(),
        tokenScopeFor: (action) => `acme ${action}`,
      }),
    ).toThrow(/not a scope token/);
  });

  it('refuses a default action outside the vocabulary', () => {
    expect(() =>
      createScopeVocabulary<Action>({
        actions: ['widgets:read'],
        admissionScope: 'acme:access',
        defaultActions: new Set<Action>(['orders:read']),
      }),
    ).toThrow(/not in actions/);
  });
});
