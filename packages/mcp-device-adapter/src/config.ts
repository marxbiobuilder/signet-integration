import { type DeviceOptions } from '../../../src/core/device-flow';

export interface AdapterProfile extends DeviceOptions {
  readonly service: 'rover' | 'lander';
  readonly environment: 'staging' | 'production';
}

export function profileFor(
  service: string,
  environment: string,
): AdapterProfile {
  if (service !== 'rover' && service !== 'lander')
    throw new Error('invalid_service');
  if (environment !== 'staging' && environment !== 'production') {
    throw new Error('invalid_environment');
  }
  const domain =
    environment === 'production' ? 'marxbio.tech' : 'marxbiotech.dev';
  const suffix = environment === 'production' ? '' : '-staging';
  return Object.freeze({
    clientId: `${service === 'rover' ? 'rover-command' : 'lander-query'}${suffix}`,
    environment,
    issuer: 'https://signet.marxbio.tech',
    resource: `https://${service}.${domain}/api/mcp`,
    scope: `openid ${service === 'rover' ? 'purchase-orders:create' : 'queries:read'}`,
    service,
  });
}

export function parseArgs(args: readonly string[]): AdapterProfile | 'help' {
  if (args.length === 1 && (args[0] === '--help' || args[0] === '-h'))
    return 'help';
  const flags = new Map<string, string>();
  for (let i = 0; i < args.length; i += 2) {
    const key = args[i];
    const value = args[i + 1];
    if (!['--service', '--env'].includes(key) || !value || flags.has(key))
      throw new Error('invalid_arguments');
    flags.set(key, value);
  }
  return profileFor(
    flags.get('--service') ?? '',
    flags.get('--env') ?? 'staging',
  );
}
