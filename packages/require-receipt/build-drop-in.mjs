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
// Run: `npm run build:drop-in` (from packages/require-receipt) — or it is checked
// in CI that the committed dist/ matches a fresh regeneration.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(here, 'package.json'), 'utf8'));

let index = readFileSync(join(here, 'index.js'), 'utf8');
let gate = readFileSync(join(here, 'gate.js'), 'utf8');

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

const body = `${index.trimEnd()}\n\n// ── inlined from gate.js ───────────────────────────────────────────────────\n\n${gate.trimEnd()}\n`;

// Guard: the drop-in must import nothing but node: builtins.
const badImports = [...body.matchAll(/from\s+['"]([^'"]+)['"]/g)]
  .map((m) => m[1])
  .filter((s) => !s.startsWith('node:'));
if (badImports.length) throw new Error(`build-drop-in: drop-in is not zero-dep — non-node imports: ${badImports.join(', ')}`);

const hash = createHash('sha256').update(body).digest('hex').slice(0, 16);

const banner = `// SPDX-License-Identifier: Apache-2.0
//
// emilia-gate.mjs — the EMILIA Receipt-Required gate, as a single drop-in file.
//
//   • Zero dependencies (Node built-in crypto only). Copy this file into your
//     repo — no npm package, no supply-chain or version surface to own.
//   • The gate blocks an irreversible action unless it arrives with a valid,
//     action-bound, non-replayed EMILIA authorization receipt (proof a named
//     human approved THIS exact action), verified offline (Ed25519 over JCS).
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
//        makeReceiptGate({ ..., store: { has:(id)=>kv.has(id), add:(id)=>kv.add(id) } }).
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
mkdirSync(join(here, 'dist'), { recursive: true });
writeFileSync(join(here, 'dist', 'emilia-gate.mjs'), out);

// eslint-disable-next-line no-console
console.log(`wrote dist/emilia-gate.mjs — ${out.length} bytes, source v${pkg.version}, sha256:${hash}, zero-dep ✓`);
