// SPDX-License-Identifier: Apache-2.0
// Node ESM loader hook: when a specifier ends in .js or .mjs and resolves to a
// TypeScript source file on disk (the file was renamed .js -> .ts during the
// migration but import specifiers were deliberately left unchanged, per the
// bundler/NodeNext convention already used across the repo and mirrored in
// next.config.js's webpack resolve.extensionAlias), resolve to the .ts/.mts
// file instead of failing with ERR_MODULE_NOT_FOUND. This is the plain-Node
// (non-bundled) analogue of that same extensionAlias, for scripts, examples,
// and `node --test` runs that don't go through webpack or vite.
//
// Registered via `node --import ./scripts/ts-loader/register.mjs <script>` or
// NODE_OPTIONS="--import ./scripts/ts-loader/register.mjs". Requires Node's
// built-in TypeScript stripping (Node >=22.6 with --experimental-strip-types,
// or Node >=23.6 unflagged) to actually execute the resolved .ts file; this
// hook only fixes resolution, not execution.

import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const TS_FOR_JS = { '.js': ['.ts', '.tsx'], '.mjs': ['.mts'] };

export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context);
  } catch (err) {
    if (err?.code !== 'ERR_MODULE_NOT_FOUND') throw err;
    if (!(specifier.startsWith('./') || specifier.startsWith('../'))) throw err;

    const dotIndex = specifier.lastIndexOf('.');
    const ext = dotIndex === -1 ? '' : specifier.slice(dotIndex);
    const candidates = TS_FOR_JS[ext];
    if (!candidates) throw err;

    const parentPath = context.parentURL ? fileURLToPath(context.parentURL) : process.cwd();
    const base = join(dirname(parentPath), specifier.slice(0, dotIndex));

    for (const tsExt of candidates) {
      const candidatePath = base + tsExt;
      if (existsSync(candidatePath)) {
        return nextResolve(pathToFileURL(candidatePath).href, context);
      }
    }
    throw err;
  }
}
