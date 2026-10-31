import { build } from 'esbuild';
import { copyFile } from 'node:fs/promises';
await build({
  entryPoints: ['src/main.ts'],
  outfile: 'dist/main.cjs',
  bundle: true,
  platform: 'node',
  target: 'node22',
  format: 'cjs',
  packages: 'external',
  sourcemap: false,
});
await copyFile('../../LICENSE', 'LICENSE');
