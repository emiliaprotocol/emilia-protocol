// SPDX-License-Identifier: Apache-2.0
// tsc's compiled output has its type annotations erased, so re-checking it with
// checkJs elsewhere in the repo (lib/verify-web.js, lib/strict-json.js vendor
// these files verbatim) hits control-flow-inference gaps the original .ts
// source never had (e.g. `let x = null` narrowed to exactly `null`). The fix
// is a file-level pragma, applied here so every regeneration stays consistent
// rather than relying on a hand-edited committed copy drifting from a fresh build.
import { readFileSync, writeFileSync } from 'node:fs';

const PRAGMA = '// @ts-nocheck\n';
const targets = ['dist/web.js', 'dist/strict-json.js'];

for (const rel of targets) {
  const content = readFileSync(rel, 'utf8');
  if (content.startsWith(PRAGMA)) continue;
  writeFileSync(rel, PRAGMA + content);
}
