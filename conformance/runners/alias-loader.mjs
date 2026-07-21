// SPDX-License-Identifier: Apache-2.0
// Generated from alias-loader.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// Minimal ESM resolve hook that maps the repo's "@/" path alias (defined in
// jsconfig.json / vitest.config.js) to the repository root, so alias-using
// production modules (e.g. lib/handshake/invariants.js -> "@/lib/crypto") can be
// imported by a bare-node CLI runner without a bundler. Registered via
// module.register() from run-invariants.mjs.
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve as pathResolve } from 'node:path';
const ROOT = pathResolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
export async function resolve(specifier, context, nextResolve) {
    if (specifier === '@' || specifier.startsWith('@/')) {
        const rel = specifier === '@' ? '' : specifier.slice(2);
        const base = pathResolve(ROOT, rel);
        // Bare-node ESM does not add extensions or resolve directory indexes the way
        // the bundler alias does; try the same candidate set the resolver expects.
        const candidates = [base, `${base}.js`, `${base}.mjs`, pathResolve(base, 'index.js'), pathResolve(base, 'index.mjs')];
        for (const candidate of candidates) {
            try {
                return await nextResolve(pathToFileURL(candidate).href, context);
            }
            catch {
                // try the next candidate
            }
        }
    }
    return nextResolve(specifier, context);
}
