// SPDX-License-Identifier: Apache-2.0
// Explicit maintainer operation. Checking the profile never refreshes its pins.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../../..');
const lockPath = resolve(here, 'source-lock.json');
const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
const hash = (path) => createHash('sha256').update(readFileSync(resolve(root, path))).digest('hex');
const local = new Set();
function add(path) {
  if (local.has(path)) return;
  local.add(path);
  if (!/\.(?:m?js|ts)$/.test(path)) return;
  const source = readFileSync(resolve(root, path), 'utf8');
  // All runtime imports in this dependency closure are static ES modules.
  for (const match of source.matchAll(/(?:\bfrom\s*|\bimport\s*)['"](\.[^'"]+)['"]/g)) {
    add(relative(root, resolve(root, dirname(path), match[1])));
  }
  if (path.startsWith('packages/verify/dist/') && path.endsWith('.js')) {
    const ts = path.replace('/dist/', '/src/').replace(/\.js$/, '.ts');
    if (existsSync(resolve(root, ts))) local.add(ts);
  }
}
for (const name of [
  'README.md', 'run.mjs', 'run.node-test.mjs', 'vectors.json',
  'executor-profile.mjs', 'executor-profile.node-test.mjs',
  'check.mjs', 'refresh-source-lock.mjs',
]) add(relative(root, resolve(here, name)));
add('conformance/composition/coaz-translation-v0.1/vectors.json');
add('.github/workflows/authzen-pep-profile.yml');
lock.assembled = '2026-09-03';
lock.public_dependency_base = '761ff724cb3c96fe5863023f978512d406d6b84c';
delete lock.native_compiler;
lock.evidence_evaluator = {
  version: 'AEB-EVALUATION-v1',
  path: 'packages/verify/dist/aeb-adapter-contract.js',
  source_path: 'packages/verify/src/aeb-adapter-contract.ts',
  claim_scope: 'unsigned local preflight; not an accepted evaluation credential or local authorization',
};
for (const key of ['evidence_evaluator', 'native_attestation_bridge', 'aeb_kernel']) {
  lock[key].sha256 = hash(lock[key].path);
  if (lock[key].source_path) lock[key].source_sha256 = hash(lock[key].source_path);
}
lock.local_files = [...local].sort().map((path) => ({ path, sha256: hash(path) }));
writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
process.stdout.write(`Refreshed ${lock.local_files.length} local file pins. Review changes, then explicitly regenerate and check both reports.\n`);
