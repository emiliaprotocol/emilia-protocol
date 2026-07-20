// SPDX-License-Identifier: Apache-2.0
// Shared helper for scripts that read repo source files by a literal relative
// path (fs.readFileSync/existsSync — NOT an import specifier, which the loader
// in resolve-ts.mjs already covers). During the TypeScript migration, files
// get renamed .js -> .ts; a caller passing the old literal 'lib/foo.js' should
// still find 'lib/foo.ts' without every call site needing an update.
import { existsSync } from 'node:fs';
import { join, dirname, extname } from 'node:path';

const TS_FOR_JS = { '.js': ['.ts', '.tsx'], '.jsx': ['.tsx'], '.mjs': ['.mts'] };

/**
 * Resolve `rel` (relative to `root`) to whichever of the literal path or its
 * TypeScript-renamed counterpart actually exists on disk.
 * @param {string} root
 * @param {string} rel
 * @returns {string} the relative path that exists (unchanged if the literal one does)
 */
export function resolveSourcePath(root, rel) {
  if (existsSync(join(root, rel))) return rel;
  const ext = extname(rel);
  for (const tsExt of TS_FOR_JS[ext] || []) {
    const candidate = rel.slice(0, -ext.length) + tsExt;
    if (existsSync(join(root, candidate))) return candidate;
  }
  return rel; // let the caller's own fs call raise the real ENOENT
}
