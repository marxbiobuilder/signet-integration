import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const temporary = await mkdtemp(join(tmpdir(), 'signet-adapter-pack-'));
function run(command, args, cwd = process.cwd()) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    timeout: 120000,
  });
  assert.equal(result.status, 0, `${command} failed: ${result.stderr}`);
  return result.stdout;
}
try {
  const packed = JSON.parse(
    run('npm', [
      'pack',
      './packages/mcp-device-adapter',
      '--ignore-scripts',
      '--json',
      '--pack-destination',
      temporary,
    ]),
  );
  const files = packed[0].files.map((file) => file.path);
  assert(files.includes('dist/main.cjs'));
  assert(files.includes('LICENSE'));
  assert(
    files.every((file) =>
      ['package.json', 'README.md', 'LICENSE', 'dist/main.cjs'].includes(file),
    ),
  );
  const install = join(temporary, 'installed');
  run('npm', [
    'install',
    '--prefix',
    install,
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
    '--prefer-offline',
    join(temporary, packed[0].filename),
  ]);
  const installed = join(
    install,
    'node_modules/@marxbiotech/mcp-device-adapter',
  );
  const manifest = JSON.parse(
    await readFile(join(installed, 'package.json'), 'utf8'),
  );
  assert(!manifest.peerDependencies);
  assert(
    !Object.values(manifest.dependencies).some((version) =>
      version.startsWith('workspace:'),
    ),
  );
  assert(!(await readdir(join(install, 'node_modules'))).includes('@nestjs'));
  const executable = join(installed, manifest.bin['mcp-device-adapter']);
  assert(
    run(process.execPath, [executable, '--help']).includes(
      '--service rover|lander',
    ),
  );
  const bundled = await readFile(executable, 'utf8');
  assert(!bundled.includes('require("@nestjs/'));

  const require = createRequire(
    resolve('packages/mcp-device-adapter/package.json'),
  );
  const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
  const {
    StdioClientTransport,
  } = require('@modelcontextprotocol/sdk/client/stdio.js');
  for (const service of ['rover', 'lander']) {
    const client = new Client({ name: 'package-smoke', version: '1.0.0' });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [executable, '--service', service, '--env', 'staging'],
      stderr: 'pipe',
    });
    let diagnostic = '';
    transport.stderr?.on('data', (chunk) => {
      diagnostic += chunk.toString();
    });
    try {
      await client.connect(transport, { timeout: 10000 });
      const { tools } = await client.listTools();
      assert.deepEqual(
        tools.map((tool) => tool.name),
        ['signet_auth_begin', 'signet_auth_status', 'signet_auth_disconnect'],
      );
      const status = await client.callTool({ name: 'signet_auth_status' });
      assert.equal(JSON.parse(status.content[0].text).service, service);
      assert.equal(diagnostic, '');
    } finally {
      await client.close();
    }
  }
  console.log(
    'Packed adapter installs without NestJS and serves stdio MCP for Rover and Lander.',
  );
} finally {
  await rm(temporary, { recursive: true, force: true });
}
