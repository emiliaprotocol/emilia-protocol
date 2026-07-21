// SPDX-License-Identifier: Apache-2.0
//
// Generate the zero-dependency, copy-in Receipt-Required gate: `dist/emilia-gate.mjs`.
//
// WHY: conservative maintainers (Supabase #309, Portkey #15) won't add an
// `@emilia-protocol/*` runtime dependency for one tool. This emits ONE self-
// contained file they paste into their repo — no package, no supply chain, no
// version surface they have to own. It is GENERATED from the real, reviewed
// source (index.js + gate.js, both node:crypto-only), never hand-written, so the
// verifier in the drop-in is byte-for-byte the same code as the published package.
//
// The only dependency in this package is `jose`, used solely by the JWS profile
// (jws.js). That path is excluded here, so the drop-in is genuinely zero-dep.
//
// Run: `npm run build:drop-in` (from packages/require-receipt). CI enforces this:
// tests/require-receipt-dropin-fidelity.test.js regenerates to a temp path and
// asserts byte-equality with every committed copy (dist/ + the eve example), so
// a stale checked-in drop-in fails CI instead of silently drifting.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(here, 'package.json'), 'utf8'));

// The package's public .js files are compatibility launchers after the
// TypeScript migration. Generate the zero-dependency artifact from the
// compiled runtime instead of the launcher, preserving the old source markers.
const runtimeDir = join(here, 'dist');
let index = readFileSync(join(runtimeDir, 'index.js'), 'utf8');
let gate = readFileSync(join(runtimeDir, 'gate.js'), 'utf8');
let strictJson = readFileSync(join(runtimeDir, 'strict-json.js'), 'utf8');
let acquisition = readFileSync(join(runtimeDir, 'acquisition.js'), 'utf8');
// Source maps belong to the package build, not to a copy-in artifact. Remove
// compiler trailers so adopters do not get broken relative-map warnings.
index = index.replace(/\n?\/\/# sourceMappingURL=.*\s*$/m, '\n');
gate = gate.replace(/\n?\/\/# sourceMappingURL=.*\s*$/m, '\n');
strictJson = strictJson.replace(/\n?\/\/# sourceMappingURL=.*\s*$/m, '\n');
acquisition = acquisition.replace(/\n?\/\/# sourceMappingURL=.*\s*$/m, '\n');

// Inline the nested-JSON ambiguity guard so the copy-in artifact stays zero-dep.
index = index.replace("import { strictJsonGate } from './strict-json.js';\n", '');
index = index.replace("export { strictJsonGate } from './strict-json.js';\n", '');
strictJson = strictJson
  .replace(/export const /g, 'const ')
  .replace(/export function /g, 'function ')
  .replace(/\nexport default \{ strictJsonGate, MAX_JSON_DEPTH \};\n?/, '\n');

// Inline the acquisition contract too. It uses only node:crypto plus the
// platform fetch supplied by the caller, so the copy-in remains zero-dep while
// preserving the package's challenge and self-service behavior byte-for-byte.
index = index.replace(/export \{[\s\S]*?\} from '\.\/acquisition\.js';\n/, '');
index = index.replace(/import \{[\s\S]*?\} from '\.\/acquisition\.js';\n/, '');
acquisition = acquisition.replace("import crypto from 'node:crypto';\n", '');
acquisition = acquisition.replace("import { strictJsonGate } from './strict-json.js';\n", '');

// 1. Drop the JWS profile re-export (the only path that pulls in `jose`).
const jwsMarker = '// EP-RECEIPT-JWS-PROFILE-v1:';
const jwsAt = index.indexOf(jwsMarker);
if (jwsAt === -1) throw new Error('build-drop-in: JWS marker not found in index.js — source changed; update the generator.');
index = index.slice(0, jwsAt).trimEnd() + '\n';

// 2. Drop the `export { makeReceiptGate } from './gate.js';` re-export (with its
//    preceding comment) — we inline gate.js instead.
const gateReExport = /\n\/\/ Canonical hardened gate:[\s\S]*?export \{ makeReceiptGate \} from '\.\/gate\.js';\n/;
if (!gateReExport.test(index)) throw new Error('build-drop-in: gate re-export not found in index.js — source changed; update the generator.');
index = index.replace(gateReExport, '\n');

// 3. Strip gate.js's import-from-index block — those symbols are now in-file.
const gateImport = /import \{[\s\S]*?\} from '\.\/index\.js';\n/;
if (!gateImport.test(gate)) throw new Error('build-drop-in: gate.js import block not found — source changed; update the generator.');
gate = gate.replace(gateImport, '').trimStart();
gate = gate.replace(/\nexport \{ receiptAssuranceTier \};\n/, '\n');

const body = `${strictJson.trimEnd()}\n\n// ── inlined from acquisition.js ────────────────────────────────────────────\n\n${acquisition.trimEnd()}\n\n// ── inlined from index.js ──────────────────────────────────────────────────\n\n${index.trimEnd()}\n\n// ── inlined from gate.js ───────────────────────────────────────────────────\n\n${gate.trimEnd()}\n`;

// Guard: the drop-in must import nothing but node: builtins.
const moduleSpecifiers = [...body.matchAll(
  /^(?:import|export)\s+(?:[\s\S]*?\sfrom\s+)?['"]([^'"]+)['"];?\s*$/gm,
)].map((match) => match[1]);
const badImports = moduleSpecifiers
  .filter((s) => !s.startsWith('node:'));
if (badImports.length) throw new Error(`build-drop-in: drop-in is not zero-dep — non-node imports: ${badImports.join(', ')}`);

const hash = createHash('sha256').update(body).digest('hex').slice(0, 16);

const banner = `// @ts-nocheck
// This file is compiled output (from dist/, itself compiled from src/*.ts);
// its type annotations are already erased, so re-checking it elsewhere in the
// repo with checkJs hits control-flow-inference gaps the original .ts source
// never had. It is already verified by the TypeScript build that produced it.
// SPDX-License-Identifier: Apache-2.0
//
// emilia-gate.mjs — the EMILIA Receipt-Required gate, as a single drop-in file.
//
//   • Zero dependencies (Node built-in crypto only). Copy this file into your
//     repo — no npm package, no supply-chain or version surface to own.
//   • The gate blocks an irreversible action unless it arrives with a valid,
//     action-bound, non-replayed EMILIA authorization receipt at the configured
//     assurance tier, verified offline (Ed25519/WebAuthn over canonical bytes).
//   • Off by default: you decide which actions require a receipt.
//
//   Quick use:
//     import { makeReceiptGate } from './emilia-gate.mjs';
//     const gate = makeReceiptGate({ action: 'db.records.delete', trustedKeys: [ISSUER_SPKI_B64URL] });
//     const r = await gate.run(receipt, { target: 'customers' }, async () => doDelete());
//     if (!r.ok) return reply(r.status, r.body);   // 428 Receipt-Required challenge
//
//   PRODUCTION NOTES (the two things easy to get wrong):
//     1. Pass trustedKeys (issuer SPKI keys). Do NOT rely on allowInlineKey for
//        real actions — an inline key proves integrity, not WHO authorized.
//     2. The default consumed-store is in-memory (process-local). For restart-
//        durable / multi-instance one-time consumption, pass a shared store:
//        makeReceiptGate({ ..., store: { reserve, commit, release } }).
//        reserve MUST be an atomic insert-if-absent. Once execution begins, an
//        indeterminate result is committed, never released for automatic retry.
//
//   Conformance: this drop-in passes EMILIA RR-1 (challenge-on-missing, runs-on-
//   valid, replay-refused, forged-refused). Verify with @emilia-protocol/fire-drill.
//
//   GENERATED — do not edit by hand. Regenerate with:
//     npx @emilia-protocol/require-receipt   (or: node build-drop-in.mjs)
//   source: @emilia-protocol/require-receipt@${pkg.version}  ·  content-sha256:${hash}
//   docs: https://www.emiliaprotocol.ai/gate   spec: draft-schrock-ep-authorization-receipts

`;

const out = banner + body;

// Emit the SAME bytes to every committed copy of the drop-in. The canonical
// artifact is dist/emilia-gate.mjs; the reference example ships a byte-identical
// copy (its README tells adopters to curl the dist file, so they must match).
// Keeping the writes here means one regeneration syncs every copy — and
// tests/require-receipt-dropin-fidelity.test.js asserts byte-equality, so a
// stale copy fails CI instead of silently drifting (that drift previously let
// the example miss the quorum-distinctness and freshness fail-closed fixes).
const repoRoot = join(here, '..', '..');
// Default: write in place to every committed copy. When EP_DROPIN_OUT_DIR is
// set, write both copies (flat, distinct names) into that directory instead —
// so the fidelity test can regenerate in isolation and diff against the
// committed files WITHOUT mutating them.
const outDir = process.env.EP_DROPIN_OUT_DIR;
const targets = outDir
  ? [join(outDir, 'dist-emilia-gate.mjs'), join(outDir, 'example-emilia-gate.mjs')]
  : [
    join(here, 'dist', 'emilia-gate.mjs'),
    join(repoRoot, 'examples', 'eve-receipt-required', 'lib', 'emilia-gate.mjs'),
  ];
for (const target of targets) {
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, out);
}

// eslint-disable-next-line no-console
console.log(`wrote ${targets.length} copies of emilia-gate.mjs — ${out.length} bytes, source v${pkg.version}, sha256:${hash}, zero-dep ✓`);
