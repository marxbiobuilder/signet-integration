import {
  loginStateCookieName,
  loginStateKey,
  newLoginState,
  openLoginState,
  readCookie,
  sealLoginState,
} from './login-state';

const NAME = loginStateCookieName('acme-login');

describe('readCookie', () => {
  it('reads nothing from an absent header', () => {
    expect(readCookie(undefined, NAME)).toEqual([]);
  });

  it('returns every value under the name, in the order sent', () => {
    expect(readCookie(`${NAME}=a; other=x; ${NAME}=b`, NAME)).toEqual([
      'a',
      'b',
    ]);
  });

  it('matches the whole name, not a prefix of a longer one', () => {
    expect(readCookie(`${NAME}-2=wrong; ${NAME}=right`, NAME)).toEqual([
      'right',
    ]);
  });

  it('keeps an "=" inside the value, and trims the space around name and value', () => {
    expect(readCookie(`  ${NAME} =  a=b=  ;x=y`, NAME)).toEqual(['a=b=']);
  });

  it('skips a pair without "="', () => {
    expect(readCookie(`garbage; ${NAME}=v`, NAME)).toEqual(['v']);
  });
});

describe('loginStateKey', () => {
  it('names the variable when the secret is too short', () => {
    expect(() => loginStateKey('short', 'MY_SECRET')).toThrow(
      'MY_SECRET: the login state secret must be at least 32 bytes',
    );
  });
});

describe('openLoginState', () => {
  const key = loginStateKey('a-login-state-secret-of-32-bytes!', 'spec');

  it('opens what sealLoginState sealed', async () => {
    const state = newLoginState('acme-login');
    expect(await openLoginState(key, await sealLoginState(key, state))).toEqual(
      { ok: true, state },
    );
  });

  it('answers unopenable for something that is not a sealed state', async () => {
    expect(await openLoginState(key, 'not-a-jwe')).toEqual({
      ok: false,
      reason: 'unopenable',
    });
  });

  it('rethrows what is not jose refusing the value: a defect, not a bad cookie', async () => {
    const sealed = await sealLoginState(key, newLoginState('acme-login'));
    await expect(
      openLoginState('not a key' as unknown as Uint8Array, sealed),
    ).rejects.toBeInstanceOf(TypeError);
  });
});
