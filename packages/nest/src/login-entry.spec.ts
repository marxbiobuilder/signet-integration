import { LOGIN_ENTRY } from './__spec__/login-fixture';
import {
  checkLoginEntryEnvironments,
  type SignetLoginEntry,
  validateLoginEntry,
} from './login-entry';

describe('validateLoginEntry', () => {
  const withUri = (environment: string, uri: string): SignetLoginEntry => ({
    ...LOGIN_ENTRY,
    redirectUris: { ...LOGIN_ENTRY.redirectUris, [environment]: uri },
  });

  it.each([
    ['https://acme.example/cb#', 'must not carry a fragment'],
    ['https://acme.example/cb#x', 'must not carry a fragment'],
    ['https://user:pass@acme.example/cb', 'must not carry credentials'],
  ])('refuses %s', (uri, message) => {
    expect(() => validateLoginEntry(withUri('production', uri))).toThrow(
      message,
    );
  });

  it.each(['', 'two words', 'quote"d', 'back\\slash'])(
    'refuses the scope %j',
    (scope) => {
      expect(() =>
        validateLoginEntry({ ...LOGIN_ENTRY, scopes: ['openid', scope] }),
      ).toThrow('is not a scope token (RFC 6749 §3.3)');
    },
  );

  it.each([[['email']], [[]]])(
    'refuses scopes without openid (%j): there would be no ID token',
    (scopes) => {
      expect(() => validateLoginEntry({ ...LOGIN_ENTRY, scopes })).toThrow(
        'scopes must include openid',
      );
    },
  );

  it('accepts scope tokens with the RFC’s punctuation', () => {
    expect(() =>
      validateLoginEntry({
        ...LOGIN_ENTRY,
        scopes: ['openid', 'acme:access', 'https://x.example/read'],
      }),
    ).not.toThrow();
  });

  it('returns a frozen copy, so mutating the caller’s object changes nothing it kept', () => {
    const mutable: {
      name: string;
      redirectUris: Record<string, string>;
      scopes: string[];
    } = {
      name: 'acme-login',
      redirectUris: { ...LOGIN_ENTRY.redirectUris },
      scopes: ['openid'],
    };
    const kept = validateLoginEntry(mutable);
    mutable.redirectUris.production = 'https://evil.example/cb';
    mutable.scopes.push('everything');
    expect(kept.redirectUris.production).toBe(
      LOGIN_ENTRY.redirectUris.production,
    );
    expect(kept.scopes).toEqual(['openid']);
    expect(Object.isFrozen(kept)).toBe(true);
    expect(Object.isFrozen(kept.redirectUris)).toBe(true);
    expect(Object.isFrozen(kept.scopes)).toBe(true);
  });
});

describe('checkLoginEntryEnvironments', () => {
  it('accepts exactly the deployed environments plus development', () => {
    expect(() =>
      checkLoginEntryEnvironments(LOGIN_ENTRY, ['production', 'staging']),
    ).not.toThrow();
  });

  it('names every missing environment', () => {
    expect(() =>
      checkLoginEntryEnvironments(LOGIN_ENTRY, [
        'production',
        'staging',
        'qa',
        'demo',
      ]),
    ).toThrow('no redirect URI for qa, demo');
  });
});
