#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const gateRoot = resolve(repositoryRoot, 'packages/gate');
const committedDist = resolve(gateRoot, 'dist');
const tsc = resolve(repositoryRoot, 'node_modules/typescript/bin/tsc');
const scratch = mkdtempSync(join(tmpdir(), 'emilia-gate-runtime-'));
const freshDist = resolve(scratch, 'dist');

function runtimeFiles(root, current = root) {
  return readdirSync(current).flatMap((name) => {
    const absolute = resolve(current, name);
    if (statSync(absolute).isDirectory()) return runtimeFiles(root, absolute);
    return name.endsWith('.js') ? [relative(root, absolute)] : [];
  });
}

try {
  const build = spawnSync(process.execPath, [
    tsc,
    '-p',
    resolve(gateRoot, 'tsconfig.json'),
    '--outDir',
    freshDist,
  ], {
    cwd: repositoryRoot,
    env: { ...process.env, FORCE_COLOR: '0', TZ: 'UTC' },
    stdio: 'inherit',
  });

  if (build.error) throw build.error;
  if (build.status !== 0) process.exit(build.status ?? 1);

  const stale = [];
  const files = runtimeFiles(freshDist);
  for (const path of files) {
    let expected = readFileSync(resolve(freshDist, path), 'utf8');
    // packages/gate/postbuild-ts-nocheck.mjs applies this pragma only to
    // top-level runtime files. Reproduce that transform in memory so this
    // check remains read-only.
    if (!path.includes('/') && !expected.startsWith('// @ts-nocheck\n')) {
      expected = `// @ts-nocheck\n${expected}`;
    }

    let actual = null;
    try {
      actual = readFileSync(resolve(committedDist, path), 'utf8');
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    if (actual !== expected) stale.push(path);
  }

  if (stale.length > 0) {
    console.error('GATE RUNTIME FRESHNESS: FAIL');
    for (const path of stale.slice(0, 20)) console.error(`- ${path}`);
    if (stale.length > 20) console.error(`- and ${stale.length - 20} more`);
    console.error('Run npm --prefix packages/gate run build and review the generated runtime changes.');
    process.exit(1);
  }

  console.log(`GATE RUNTIME FRESHNESS: PASS (${files.length} compiled runtime files)`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
