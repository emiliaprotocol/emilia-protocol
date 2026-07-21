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
  let content = readFileSync(rel, 'utf8');
  if (!content.startsWith(PRAGMA)) content = PRAGMA + content;
  // The vendored strict JSON runtime carries its map beside the copy in lib/.
  // Keep one stable EOF newline so regeneration remains byte-identical there.
  if (rel === 'dist/strict-json.js' && !content.endsWith('\n')) content += '\n';
  writeFileSync(rel, content);
}

// The app vendors these compiled runtimes in lib/. Their sourceMappingURL
// comments resolve beside the vendored file, so emit matching maps whose source
// paths point back to the authoritative TypeScript instead of producing a Vite
// warning (or silently dropping source attribution) on newer Node runtimes.
for (const name of ['web', 'strict-json']) {
  const sourceMap = JSON.parse(readFileSync(`dist/${name}.js.map`, 'utf8'));
  sourceMap.sources = [`../packages/verify/src/${name}.ts`];
  writeFileSync(`../../lib/${name}.js.map`, JSON.stringify(sourceMap));
}
