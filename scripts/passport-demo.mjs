/**
 * passport-demo — proves the EMILIA receipt is a portable key, not a local gate.
 * @license Apache-2.0
 *
 * A counterparty service demands an EMILIA receipt for `payment.release`.
 * We try to get through the door six ways. Only a fresh, untampered, action-
 * bound receipt signed by a TRUSTED issuer opens it — that's the difference
 * between a permission ("our system said yes") and a credential ("prove it to me").
 *
 *   node scripts/passport-demo.mjs
 */
import crypto from 'node:crypto';
import { requireEmiliaReceipt } from '../packages/require-receipt/index.js';

function canonicalize(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(v[k])).join(',')}}`;
  return JSON.stringify(v);
}
const pubOf = (priv) => crypto.createPublicKey(priv).export({ type: 'spki', format: 'der' }).toString('base64url');

function mint(action, privKey, { outcome = 'allow_with_signoff', ageSec = 0 } = {}) {
  const payload = {
    receipt_id: `agtgate_${crypto.randomUUID()}`,
    issuer: 'ep_agent_gate',
    subject: 'agent:invoice-bot',
    claim: { action_type: action, outcome, context: { reasons: ['AI-agent financial action requires human accountability.'] } },
    created_at: new Date(Date.now() - ageSec * 1000).toISOString(),
    protocol_version: 'EP-CORE-v1.0',
  };
  const value = crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), privKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', signer: 'ep_agent_gate', value }, public_key: pubOf(privKey) };
}

// Two issuers: one the counterparty trusts, one it doesn't.
const trusted = crypto.generateKeyPairSync('ed25519').privateKey;
const rogue = crypto.generateKeyPairSync('ed25519').privateKey;
const TRUSTED_KEYS = [pubOf(trusted)];

// The counterparty's policy: payment.release needs a fresh receipt from a trusted issuer.
const gate = requireEmiliaReceipt({ trustedKeys: TRUSTED_KEYS, action: 'payment.release', maxAgeSec: 900 });

function callService(receiptDoc) {
  const req = { headers: {}, body: {} };
  if (receiptDoc) req.headers['x-emilia-receipt'] = Buffer.from(JSON.stringify(receiptDoc)).toString('base64');
  let out = null;
  const res = {
    _s: 200,
    setHeader() {},
    status(s) { this._s = s; return this; },
    json(b) { out = { status: this._s, reason: b.rejected?.reason || (b.allowed ? 'ok' : 'challenge') }; return this; },
  };
  gate(req, res, () => { out = { status: 200, reason: 'ALLOWED' }; });
  return out;
}

const tamper = (() => { const r = mint('payment.release', trusted); r.payload.claim.context.reasons = ['(silently changed after signing)']; return r; })();

/** @type {Array<[string, any]>} */
const cases = [
  ['1. agent sends NO receipt', null],
  ['2. valid receipt, TRUSTED issuer, right action', mint('payment.release', trusted)],
  ['3. receipt signed by a ROGUE (untrusted) issuer', mint('payment.release', rogue)],
  ['4. TAMPERED receipt (edited after signing)', tamper],
  ['5. valid receipt but for the WRONG action (data.export)', mint('data.export', trusted)],
  ['6. valid issuer but STALE receipt (2h old)', mint('payment.release', trusted, { ageSec: 7200 })],
];

console.log('\n  Counterparty requires an EMILIA receipt for "payment.release".');
console.log('  Trusted issuer key pinned. Watch who gets through the door:\n');
console.log('  ' + 'CASE'.padEnd(52) + 'HTTP   VERDICT');
console.log('  ' + '-'.repeat(80));
for (const [label, doc] of cases) {
  const r = callService(doc);
  const verdict = r.status === 200 ? '✅ let through' : `⛔ blocked (${r.reason})`;
  console.log('  ' + label.padEnd(52) + String(r.status).padEnd(7) + verdict);
}
console.log('\n  → Only case 2 opens the door. The receipt is a portable key a stranger can verify —');
console.log('    not a permission you have to be trusted to grant. That is the whole company.\n');
