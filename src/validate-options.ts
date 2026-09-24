import {
  DEVELOPMENT_ENVIRONMENT,
  type SignetDeployedProfile,
  type SignetIntegrationOptions,
} from './options';

/**
 * Request properties Express and Nest already use; a principal written there
 * would overwrite them.
 */
const RESERVED_REQUEST_KEYS: ReadonlySet<string> = new Set([
  'app',
  'body',
  'cookies',
  'headers',
  'hostname',
  'ip',
  'ips',
  'method',
  'originalUrl',
  'params',
  'path',
  'protocol',
  'query',
  'rawHeaders',
  'res',
  'route',
  'signedCookies',
  'url',
]);

/**
 * Characters that would break out of the quoted value in a
 * `WWW-Authenticate` parameter (RFC 7235 quoted-string).
 */
const QUOTE_BREAKERS = /["\\\r\n]/;

/**
 * Checks the invariants the mechanism relies on and the comments state, once,
 * at construction (`SignetIntegrationModule.forRoot`). Every rule here is one
 * a second consumer could break by mistake without any type error; each
 * throws with the field named. Returns the options for chaining.
 */
export function validateSignetIntegrationOptions<E extends string>(
  options: SignetIntegrationOptions<E>,
): SignetIntegrationOptions<E> {
  const fail = (reason: string): never => {
    throw new Error(`invalid SignetIntegrationOptions: ${reason}`);
  };
  if (
    options.admissionScope === '' ||
    QUOTE_BREAKERS.test(options.admissionScope)
  ) {
    fail(
      'admissionScope must be non-empty and contain no quote, backslash or newline',
    );
  }
  if (options.realm === '' || QUOTE_BREAKERS.test(options.realm)) {
    fail('realm must be non-empty and contain no quote, backslash or newline');
  }
  if (!options.scopesSupported.includes(options.admissionScope)) {
    fail(
      `scopesSupported must include the admission scope ${options.admissionScope}`,
    );
  }
  if (RESERVED_REQUEST_KEYS.has(options.requestPrincipalKey)) {
    fail(
      `requestPrincipalKey ${options.requestPrincipalKey} is a request property Express or Nest already uses`,
    );
  }
  const profiles = Object.entries(options.deployedProfiles) as [
    E,
    SignetDeployedProfile,
  ][];
  if (profiles.length === 0)
    fail('deployedProfiles must name at least one environment');
  if (
    (profiles as [string, SignetDeployedProfile][]).some(
      ([e]) => e === DEVELOPMENT_ENVIRONMENT,
    )
  ) {
    fail(
      `deployedProfiles must not contain ${DEVELOPMENT_ENVIRONMENT}; the resolver stamps it`,
    );
  }
  const namespaces = new Set(profiles.map(([, p]) => p.namespace));
  if (namespaces.size !== profiles.length)
    fail('deployedProfiles namespaces must be unique');
  const hosts = new Set(profiles.map(([, p]) => p.host));
  if (hosts.size !== profiles.length)
    fail('deployedProfiles hosts must be unique');
  // Every canonical resource -- deployed and development -- must carry the
  // same path with no query or fragment: the metadata route is mounted once,
  // on that path, and the challenge points at it.
  const resourcePath = (resource: string, label: string): string => {
    const url = new URL(resource);
    if (url.search !== '' || url.hash !== '') {
      fail(`${label} must not carry a query or fragment: ${resource}`);
    }
    return url.pathname;
  };
  const developmentPath = resourcePath(
    options.developmentProfile.canonicalResource,
    'developmentProfile.canonicalResource',
  );
  for (const [environment, { host }] of profiles) {
    const path = resourcePath(
      options.canonicalResourceFor(host),
      `canonicalResourceFor(${host})`,
    );
    if (path !== developmentPath) {
      fail(
        `canonicalResourceFor(${host}) has path ${path} but developmentProfile has ${developmentPath} (environment ${environment}); every profile must share one resource path`,
      );
    }
  }
  return options;
}
