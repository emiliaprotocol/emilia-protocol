import { chmod, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { build } from 'esbuild';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outputPath = resolve(packageRoot, 'bundle.js');

await build({
  entryPoints: [resolve(packageRoot, 'index.js')],
  outfile: outputPath,
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node20',
  minifyWhitespace: true,
  external: [
    '@emilia-protocol/verify/*',
    '../packages/verify/strict-json.js',
  ],
});

// Some upstream template literals contain space-only lines. They are
// semantically irrelevant but violate this repository's diff discipline.
const generated = await readFile(outputPath, 'utf8');
const normalized = `${generated
  .split('\n')
  .map((line) => line.trimEnd())
  .join('\n')
  .replace(/\n*$/, '')}\n`;
await writeFile(outputPath, normalized, 'utf8');
await chmod(outputPath, 0o755);

console.log(`MCP BUNDLE: generated (${Buffer.byteLength(normalized)} bytes)`);
