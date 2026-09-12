// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { build } from 'esbuild';

const here = dirname(fileURLToPath(import.meta.url));
const output = join(here, 'adapter.mjs');
const sourceFiles = [
  'adapter-src.mjs',
  'bundle-primitives.mjs',
  'package.json',
  'package-lock.json',
];

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

await build({
  entryPoints: [join(here, 'adapter-src.mjs')],
  outfile: output,
  bundle: true,
  format: 'esm',
  minify: true,
  platform: 'node',
  treeShaking: true,
  banner: {
    js: [
      '// SPDX-License-Identifier: Apache-2.0',
      '// @ts-nocheck -- generated dependency bundle; test adapter-src.mjs instead.',
      '// Generated from adapter-src.mjs; dependencies are pinned by package-lock.json.',
    ].join('\n'),
  },
});

const bytes = await readFile(output);
const digest = sha256(bytes);
await writeFile(join(here, 'adapter.sha256'), `${digest}  adapter.mjs\n`);
const sourceDigests = Object.fromEntries(
  await Promise.all(
    sourceFiles.map(async (file) => [file, sha256(await readFile(join(here, file)))])
  )
);
await writeFile(
  join(here, 'dependency-bundle.json'),
  `${JSON.stringify(
    {
      '@version': 'INSIGHT-AEB-PINNED-DEPENDENCY-BUNDLE-v1',
      bundle: 'adapter.mjs',
      bundle_digest: digest,
      bundle_bytes: bytes.length,
      build: 'npm ci && npm run build',
      lockfile: 'package-lock.json',
      dependencies: {
        '@noble/curves': '1.9.7',
        canonicalize: '4.0.0',
        'verify-insight-receipt': '0.2.0',
        viem: '2.56.3',
        esbuild: '0.28.1',
      },
      source_digests: sourceDigests,
    },
    null,
    2
  )}\n`
);
console.log(`${bytes.length} bytes ${digest}`);
