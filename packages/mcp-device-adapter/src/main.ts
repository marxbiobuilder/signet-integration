#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { parseArgs } from './config';
import { createAdapter } from './server';

async function main(): Promise<void> {
  const profile = parseArgs(process.argv.slice(2));
  if (profile === 'help') {
    process.stdout.write(
      'Usage: mcp-device-adapter --service rover|lander [--env staging|production]\nCredentials stay in memory. The default environment is staging.\n',
    );
    return;
  }
  const { server, session } = createAdapter(profile);
  const shutdown = () => {
    session.disconnect();
    void server.close().finally(() => process.exit(0));
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
  await server.connect(new StdioServerTransport());
}

void main().catch(() => {
  process.stderr.write(
    'Adapter failed. Check arguments, runtime and connection settings.\n',
  );
  process.exitCode = 1;
});
