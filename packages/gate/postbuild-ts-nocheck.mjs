// SPDX-License-Identifier: Apache-2.0
// tsc's compiled output has its type annotations erased, so re-checking it with
// checkJs elsewhere in the repo (tsconfig.core.json includes packages/gate/**/*.js;
// app/api routes importing @emilia-protocol/gate pull dist/*.js in transitively for
// type resolution regardless of tsconfig exclude lists) hits control-flow-inference
// gaps the original .ts source never had. The fix is a file-level pragma, applied
// here so every regeneration stays consistent rather than relying on a hand-edited
// committed copy drifting from a fresh build. Mirrors packages/verify's identical
// script; unlike verify (2 fixed targets), gate applies this to every dist/*.js
// since the package is still mid-conversion and the file set keeps growing.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';

const PRAGMA = '// @ts-nocheck\n';

for (const entry of readdirSync('dist')) {
  if (!entry.endsWith('.js')) continue;
  const rel = `dist/${entry}`;
  const content = readFileSync(rel, 'utf8');
  if (content.startsWith(PRAGMA)) continue;
  writeFileSync(rel, PRAGMA + content);
}
