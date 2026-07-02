/**
 * EMILIA Gate — end-to-end demo. Run: node demo.mjs
 * Shows the Trusted Action Firewall refusing and allowing a consequential
 * action, defeating replay and tampering, and emitting a verifiable audit log.
 * @license Apache-2.0
 */
import crypto from 'node:crypto';
import { createTrustedActionFirewall, mintDeviceSignoff } from './index.js';

const canon = (v) => v == null ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
  : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
  : JSON.stringify(v);
const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
let n = 0;
const action = {
  action_type: 'payment.release',
  amount_usd: 40000,
  currency: 'USD',
  payment_instruction_id: 'pi_demo_40000',
  beneficiary_account_hash: 'sha256:demo-beneficiary',
};
// action_hash the CFO's device assertion is bound to.
const actionHash = crypto.createHash('sha256').update(canon(action), 'utf8').digest('hex');
const receipt = (outcome, extra = {}) => {
  const payload = { receipt_id: `rcpt_${++n}`, subject: 'agent:finance-bot', issuer: 'ep:org:demo', created_at: new Date().toISOString(), claim: { ...action, outcome, approver: 'ep:approver:cfo', ...extra } };
  // class_a is EARNED by a genuine WebAuthn device signoff, not by the outcome
  // string. A software receipt (outcome 'allow') carries no signoff.
  if (outcome === 'allow_with_signoff') {
    const s = mintDeviceSignoff({ actionHash, approver: 'ep:approver:cfo' });
    payload.signoff = s.signoff;
    payload.approver_public_key = s.approver_public_key;
  }
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url') } };
};

const gate = createTrustedActionFirewall({ trustedKeys: [pub] });
const PAY = { protocol: 'mcp', tool: 'release_payment' };
const line = (s) => console.log(s);
const r = (o) => o.allow ? `\x1b[32mALLOW\x1b[0m` : `\x1b[31mREFUSE ${o.status}\x1b[0m (${o.reason})`;

line('='.repeat(64));
line('  EMILIA Gate — Trusted Action Firewall  (release_payment, critical)');
line('='.repeat(64));
line(`\n  1. read_status (not guarded)             -> ${r(await gate.check({ selector: { protocol: 'mcp', tool: 'read_status' } }))}`);
line(`  2. release_payment, no receipt          -> ${r(await gate.check({ selector: PAY }))}`);
line(`  3. release_payment, software receipt    -> ${r(await gate.check({ selector: PAY, receipt: receipt('allow'), observedAction: action }))}   (needs class_a)`);
const good = receipt('allow_with_signoff');
line(`  4. release_payment, observed drift      -> ${r(await gate.check({ selector: PAY, receipt: good, observedAction: { ...action, amount_usd: 999999 } }))}`);
const run = await gate.run({ selector: PAY, receipt: good, observedAction: action }, async () => ({ released: true, id: 'wire_123' }));
const a4 = run.authorization;
line(`  5. release_payment, class_a + bound      -> ${r(a4)}`);
const exec = run.execution;
line(`     ↳ executed -> execution receipt bound to decision ${exec.authorizes_decision.slice(0, 12)}…`);
line(`  6. release_payment, SAME receipt again   -> ${r(await gate.check({ selector: PAY, receipt: good, observedAction: action }))}`);
const bad = receipt('allow_with_signoff'); bad.payload.claim.amount_usd = 9_999_999;
line(`  7. release_payment, tampered amount      -> ${r(await gate.check({ selector: PAY, receipt: bad, observedAction: action }))}`);

const chain = gate.evidence.verify();
const packet = run.packet;
line(`\n  reliance packet: ${packet.verdict.toUpperCase()}  decision=${packet.summary.decision_hash.slice(0, 12)}… execution=${packet.summary.execution_hash.slice(0, 12)}…`);
line(`  evidence log: ${gate.evidence.all().length} decisions, chain ${chain.ok ? '\x1b[32mINTACT\x1b[0m' : '\x1b[31mBROKEN\x1b[0m'}`);
line('  ' + '-'.repeat(60));
line('  Deny by default. No receipt, no execution. Every decision is provable.');
line('='.repeat(64));
