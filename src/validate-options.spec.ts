import { type SignetIntegrationOptions } from './options';
import { FIXTURE_OPTIONS } from './testing/fixture';
import { validateSignetIntegrationOptions } from './validate-options';

type Options = SignetIntegrationOptions<'production' | 'staging'>;

describe('validateSignetIntegrationOptions', () => {
  it('returns valid options unchanged', () => {
    expect(validateSignetIntegrationOptions(FIXTURE_OPTIONS)).toBe(
      FIXTURE_OPTIONS,
    );
  });

  // Each row is a mistake a second consumer can make with no type error, and
  // the fragment of the message that names the field.
  it.each<[string, Partial<Options>, RegExp]>([
    ['an empty admission scope', { admissionScope: '' }, /admissionScope/],
    [
      'a quote in the admission scope (would break WWW-Authenticate)',
      { admissionScope: 'acme:"access' },
      /admissionScope/,
    ],
    ['a backslash in the realm', { realm: 'ac\\me' }, /realm/],
    [
      'scopes_supported without the admission scope',
      { scopesSupported: ['widgets:read'] },
      /scopesSupported must include/,
    ],
    [
      'a request key Express already uses',
      { requestPrincipalKey: 'body' },
      /requestPrincipalKey body/,
    ],
    [
      'duplicate namespaces',
      {
        deployedProfiles: {
          production: { host: 'a.example', namespace: 'same' },
          staging: { host: 'b.example', namespace: 'same' },
        },
      },
      /namespaces must be unique/,
    ],
    [
      'duplicate hosts',
      {
        deployedProfiles: {
          production: { host: 'same.example', namespace: 'a' },
          staging: { host: 'same.example', namespace: 'b' },
        },
      },
      /hosts must be unique/,
    ],
    [
      'a development profile whose path differs from the deployed resources',
      {
        developmentProfile: {
          canonicalResource: 'http://localhost/api/mcp',
          host: 'localhost',
          namespace: 'development',
        },
      },
      /every profile must share one resource path/,
    ],
    [
      'a canonical resource with a query string',
      { canonicalResourceFor: (host) => `https://${host}/mcp?x=1` },
      /query or fragment/,
    ],
  ])('refuses %s', (_label, override, message) => {
    expect(() =>
      validateSignetIntegrationOptions({ ...FIXTURE_OPTIONS, ...override }),
    ).toThrow(message);
  });

  it('refuses a deployed environment named development', () => {
    const options = {
      ...FIXTURE_OPTIONS,
      deployedProfiles: {
        ...FIXTURE_OPTIONS.deployedProfiles,
        development: { host: 'dev.example', namespace: 'dev' },
      },
    } as unknown as SignetIntegrationOptions;
    expect(() => validateSignetIntegrationOptions(options)).toThrow(
      /must not contain development/,
    );
  });

  it('accepts a bare-origin resource with a bare-origin development profile', () => {
    expect(() =>
      validateSignetIntegrationOptions({
        ...FIXTURE_OPTIONS,
        canonicalResourceFor: (host) => `https://${host}`,
        developmentProfile: {
          canonicalResource: 'http://localhost',
          host: 'localhost',
          namespace: 'development',
        },
      }),
    ).not.toThrow();
  });
});
