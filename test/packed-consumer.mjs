import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pnpm = process.env.npm_execpath;
assert.ok(pnpm?.includes('pnpm'), 'Run with pnpm test:packed');
const temporary = mkdtempSync(join(tmpdir(), 'xignet-packed-consumer-'));
const run = (args, cwd) => {
  try {
    return execFileSync(process.execPath, [pnpm, ...args], {
      cwd,
      encoding: 'utf8',
      maxBuffer: 8 * 1024 * 1024,
    });
  } catch (error) {
    process.stderr.write(error.stdout || '');
    process.stderr.write(error.stderr || '');
    throw error;
  }
};

try {
  const archives = {};
  const manifests = {};
  for (const name of ['core', 'client', 'payload']) {
    const directory = join(root, 'packages', name);
    const manifest = JSON.parse(readFileSync(join(directory, 'package.json')));
    manifests[name] = manifest;
    run(['pack', '--pack-destination', temporary], directory);
    archives[`@xignet/${name}`] =
      `file:${join(temporary, `xignet-${name}-${manifest.version}.tgz`)}`;
  }
  // Match the supported host stack, but do not add TypeScript here. The packed
  // SDK must declare the peer required by MCP's runtime schema conversion.
  writeFileSync(
    join(temporary, 'package.json'),
    JSON.stringify({
      name: 'xignet-packed-consumer-fixture',
      private: true,
      type: 'module',
      dependencies: {
        ...archives,
        payload: manifests.payload.peerDependencies.payload,
        '@payloadcms/plugin-mcp':
          manifests.payload.peerDependencies['@payloadcms/plugin-mcp'],
        '@payloadcms/ui': manifests.payload.peerDependencies['@payloadcms/ui'],
        react: manifests.payload.devDependencies.react,
        'react-dom': manifests.payload.devDependencies.react,
      },
      pnpm: {
        overrides: {
          '@xignet/core': archives['@xignet/core'],
          '@xignet/client': archives['@xignet/client'],
        },
      },
    }),
  );
  run(['install', '--ignore-scripts'], temporary);
  writeFileSync(
    join(temporary, 'smoke.mjs'),
    `import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import * as core from '@xignet/core';
import * as client from '@xignet/client';
import { createDirectoryClient } from '@xignet/client/directory';
import { xignetPlugin, isXignetService } from '@xignet/payload';
import { createXignetRouteHandlers } from '@xignet/payload/next';
const require = createRequire(import.meta.url);
assert.ok(Object.keys(core).length);
assert.ok(Object.keys(client).length);
assert.ok(Object.keys(require('@xignet/core')).length);
assert.ok(Object.keys(require('@xignet/client')).length);
assert.equal(typeof createDirectoryClient, 'function');
assert.equal(typeof xignetPlugin, 'function');
assert.equal(typeof isXignetService, 'function');
assert.equal(typeof createXignetRouteHandlers, 'function');
console.log(JSON.stringify({ packedConsumer: true, esm: true, cjs: true, directory: true, payload: true, next: true }));
`,
  );
  process.stdout.write(
    execFileSync(process.execPath, ['smoke.mjs'], {
      cwd: temporary,
      encoding: 'utf8',
    }),
  );
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
