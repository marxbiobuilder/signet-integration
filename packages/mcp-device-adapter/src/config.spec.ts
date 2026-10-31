import { parseArgs, profileFor } from './config';

it('binds the service, environment, client and resource together', () => {
  expect(profileFor('rover', 'production')).toMatchObject({
    clientId: 'rover-command',
    resource: 'https://rover.marxbio.tech/api/mcp',
    scope: 'openid purchase-orders:create',
  });
  expect(profileFor('lander', 'staging')).toMatchObject({
    clientId: 'lander-query-staging',
    resource: 'https://lander.marxbiotech.dev/api/mcp',
    scope: 'openid queries:read',
  });
  expect(parseArgs(['--service', 'rover'])).toMatchObject({
    environment: 'staging',
  });
});

it.each([
  [],
  ['--service', 'unknown'],
  ['--service', 'rover', '--env', 'dev'],
  ['--service', 'rover', '--issuer', 'https://attacker.example'],
  ['--service', 'rover', '--env', 'staging', '--env', 'production'],
  ['--service', 'rover', '--token', 'secret'],
])(
  'refuses arbitrary endpoint and credential overrides: %j',
  (...args: string[]) => {
    expect(() => parseArgs(args)).toThrow();
  },
);
