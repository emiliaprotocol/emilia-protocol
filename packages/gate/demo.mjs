/**
 * EMILIA Gate — end-to-end demo. Run: node demo.mjs
 * Shows the Trusted Action Firewall refusing and allowing a consequential
 * action, defeating replay and tampering, and emitting a verifiable audit log.
 * @license Apache-2.0
 */
import crypto from 'node:crypto';
import { createGate } from './index.js';

const canon = (v) => v == null ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
  : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
  : JSON.stringify(v);
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
let n = 0;
const receipt = (outcome) => {
  const payload = { receipt_id: `rcpt_${++n}`, subject: 'agent:finance-bot', issuer: 'ep:org:demo', created_at: new Date().toISOString(), claim: { action_type: 'payment.release', outcome, approver: 'ep:approver:cfo', amount_usd: 40000 } };
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url') } };
};

const manifest = { '@version': 'EP-ACTION-RISK-MANIFEST-v0.1', actions: [
  { id: 'pay', action_type: 'payment.release', receipt_required: true, risk: 'critical', assurance_class: 'class_a', match: { protocol: 'mcp', tool: 'release_payment' } },
  { id: 'read', action_type: 'read.balance', receipt_required: false, match: { protocol: 'mcp', tool: 'read_balance' } },
]};
const gate = createGate({ manifest, trustedKeys: [pub] });
const PAY = { protocol: 'mcp', tool: 'release_payment' };
const line = (s) => console.log(s);
const r = (o) => o.allow ? `\x1b[32mALLOW\x1b[0m` : `\x1b[31mREFUSE ${o.status}\x1b[0m (${o.reason})`;

line('='.repeat(64));
line('  EMILIA Gate — Trusted Action Firewall  (release_payment, critical)');
line('='.repeat(64));
line(`\n  1. read_balance (not guarded)            -> ${r(await gate.check({ selector: { protocol: 'mcp', tool: 'read_balance' } }))}`);
line(`  2. release_payment, no receipt          -> ${r(await gate.check({ selector: PAY }))}`);
line(`  3. release_payment, software receipt    -> ${r(await gate.check({ selector: PAY, receipt: receipt('allow') }))}   (needs class_a)`);
const good = receipt('allow_with_signoff');
const a4 = await gate.check({ selector: PAY, receipt: good });
line(`  4. release_payment, class_a signoff      -> ${r(a4)}`);
const exec = await gate.recordExecution({ authorization: a4, outcome: 'executed' });
line(`     ↳ executed -> execution receipt bound to decision ${exec.authorizes_decision.slice(0, 12)}…`);
line(`  5. release_payment, SAME receipt again   -> ${r(await gate.check({ selector: PAY, receipt: good }))}`);
const bad = receipt('allow_with_signoff'); bad.payload.claim.amount_usd = 9_999_999;
line(`  6. release_payment, tampered amount      -> ${r(await gate.check({ selector: PAY, receipt: bad }))}`);

const chain = gate.evidence.verify();
line(`\n  evidence log: ${gate.evidence.all().length} decisions, chain ${chain.ok ? '\x1b[32mINTACT\x1b[0m' : '\x1b[31mBROKEN\x1b[0m'}`);
line('  ' + '-'.repeat(60));
line('  Deny by default. No receipt, no execution. Every decision is provable.');
line('='.repeat(64));
