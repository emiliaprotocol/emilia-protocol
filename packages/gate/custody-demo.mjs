/**
 * EMILIA Gate — production custody demo. Run: node custody-demo.mjs
 *
 * Shows the three custody controls a serious buyer asks for:
 *   1. ROTATION  — a new issuer key takes over without breaking the old one.
 *   2. REVOCATION — a compromised issuer key is rejected immediately, live.
 *   3. RETENTION  — the evidence log classifies hot/cold/expired + exports.
 * @license Apache-2.0
 */
import { createGate, createKeyRegistry, createEg1Harness } from './index.js';
import { DEFAULT_GATE_MANIFEST } from './action-packs.js';

const SEL = { protocol: 'mcp', tool: 'release_payment' };
const k1 = createEg1Harness({ idPrefix: 'k1' });
const k2 = createEg1Harness({ idPrefix: 'k2' });
const registry = createKeyRegistry([{ kid: 'issuer-1', key: k1.publicKey }]);
const gate = createGate({ manifest: DEFAULT_GATE_MANIFEST, keyRegistry: registry });

const G = (s) => `\x1b[32m${s}\x1b[0m`; const R = (s) => `\x1b[31m${s}\x1b[0m`;
const line = (s) => console.log(s);
async function pay(label, harness) {
  const out = await gate.run({ selector: SEL, receipt: harness.mint({ outcome: 'allow_with_signoff' }), observedAction: harness.action }, async () => ({ wire: 'ok' }));
  line(`  ${label} -> ${out.ok ? G('ALLOWED') : R(`REFUSED (${out.authorization.reason})`)}`);
}

line('='.repeat(64));
line('  EMILIA Gate — production custody: rotate, revoke, retain');
line('='.repeat(64));
await pay('1. payout, issuer-1 (current)            ', k1);
registry.revoke('issuer-1');
line('     ↳ issuer-1 reported COMPROMISED — registry.revoke("issuer-1")');
await pay('2. payout, issuer-1 (revoked)            ', k1);
registry.add({ kid: 'issuer-2', key: k2.publicKey });
line('     ↳ rotated in issuer-2 — registry.add(issuer-2)');
await pay('3. payout, issuer-2 (rotated in)         ', k2);

const exp = gate.retentionExport();
line('  ' + '-'.repeat(60));
line(`  retention: ${exp.counts.total} evidence entries (hot ${exp.counts.hot} / cold ${exp.counts.cold} / expired ${exp.counts.expired}), head ${String(exp.evidence_head).slice(0, 12)}…`);
line('  Revoke a leaked issuer key live. No redeploy. Every decision retained + provable.');
line('='.repeat(64));
