/**
 * @emilia-protocol/gate tests — run with `node --test`.
 * @license Apache-2.0
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createGate, createTrustedActionFirewall, DEFAULT_GATE_MANIFEST, HIGH_RISK_ACTION_PACKS, receiptAssuranceTier } from './index.js';

function canon(v) {
  if (v === null || v === undefined) return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  if (typeof v === 'object') return `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`;
  return JSON.stringify(v);
}
function makeKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
function mint(privateKey, payload) {
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value } };
}
let n = 0;
function receipt(privateKey, { action = 'payment.release', outcome = 'allow', extra = {} } = {}) {
  return mint(privateKey, {
    receipt_id: `rcpt_${++n}`, subject: 'agent:test', issuer: 'ep:org:test',
    created_at: new Date().toISOString(), claim: { action_type: action, outcome, ...extra },
  });
}

const MANIFEST = {
  '@version': 'EP-ACTION-RISK-MANIFEST-v0.1',
  actions: [
    { id: 'pay', action_type: 'payment.release', receipt_required: true, risk: 'critical', assurance_class: 'class_a', match: { protocol: 'mcp', tool: 'release_payment' } },
    { id: 'read', action_type: 'read.balance', receipt_required: false, match: { protocol: 'mcp', tool: 'read_balance' } },
  ],
};
const PAY = { protocol: 'mcp', tool: 'release_payment' };

test('passes through non-guarded actions', async () => {
  const { pub } = makeKey();
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub] });
  const out = await g.check({ selector: { protocol: 'mcp', tool: 'read_balance' } });
  assert.equal(out.allow, true);
  assert.equal(out.reason, 'not_guarded');
});

test('missing receipt -> 428 challenge', async () => {
  const { pub } = makeKey();
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub] });
  const out = await g.check({ selector: PAY });
  assert.equal(out.allow, false);
  assert.equal(out.status, 428);
  assert.ok(out.challenge.required);
  assert.match(out.header, /action=/);
});

test('valid class_a receipt -> allow; same receipt again -> replay refused', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub] });
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  const a = await g.check({ selector: PAY, receipt: r });
  assert.equal(a.allow, true, a.reason);
  const b = await g.check({ selector: PAY, receipt: r });
  assert.equal(b.allow, false);
  assert.equal(b.reason, 'replay_refused');
});

test('tampered receipt -> rejected', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub] });
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  r.payload.claim.amount_usd = 999; // mutate a signed field
  const out = await g.check({ selector: PAY, receipt: r });
  assert.equal(out.allow, false);
  assert.match(out.reason, /receipt_rejected/);
});

test('assurance too low (software receipt where class_a required) -> refused', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub] });
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow' }); // software tier
  const out = await g.check({ selector: PAY, receipt: r });
  assert.equal(out.allow, false);
  assert.equal(out.reason, 'assurance_too_low');
});

test('untrusted issuer key -> refused', async () => {
  const { pub } = makeKey();
  const attacker = makeKey();
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub] });
  const r = receipt(attacker.privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  const out = await g.check({ selector: PAY, receipt: r });
  assert.equal(out.allow, false);
});

test('wrong action_type -> refused', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub] });
  const r = receipt(privateKey, { action: 'payment.refund', outcome: 'allow_with_signoff' });
  const out = await g.check({ selector: PAY, receipt: r });
  assert.equal(out.allow, false);
});

test('guard() wrapper throws when refused, runs when allowed', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub] });
  const release = g.guard(async (amt) => `sent ${amt}`, { selector: () => PAY, receipt: (amt, r) => r });
  await assert.rejects(() => release(100, null), /EMILIA Gate refused/);
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  assert.equal(await release(100, r), 'sent 100');
});

test('evidence log is hash-chained and tamper-evident', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub] });
  await g.check({ selector: PAY }); // a denial
  await g.check({ selector: PAY, receipt: receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' }) }); // an allow
  assert.equal(g.evidence.verify().ok, true);
  assert.equal(g.evidence.all().length, 2);
  // Tamper: flip a recorded decision in place. The hash chain must catch it.
  g.evidence.all()[0].allow = true;
  const v = g.evidence.verify();
  assert.equal(v.ok, false);
  assert.equal(v.at, 0);
});

test('execution receipt binds to the authorization decision (full loop)', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub] });
  const out = await g.check({ selector: PAY, receipt: receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' }) });
  assert.equal(out.allow, true, out.reason);
  const exec = await g.recordExecution({ authorization: out, outcome: 'executed' });
  assert.equal(exec.kind, 'execution');
  assert.equal(exec.outcome, 'executed');
  assert.equal(exec.authorizes_decision, out.evidence.hash); // cryptographically bound to the decision
  assert.equal(g.evidence.verify().ok, true);
});

test('guard() emits an execution receipt after a guarded run', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub] });
  const release = g.guard(async (amt) => `sent ${amt}`, { selector: () => PAY, receipt: (amt, r) => r });
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  assert.equal(await release(100, r), 'sent 100');
  const recs = g.evidence.all();
  const exec = recs.find((x) => x.kind === 'execution');
  assert.ok(exec, 'execution receipt present');
  assert.equal(exec.outcome, 'executed');
  assert.equal(g.evidence.verify().ok, true);
});

test('run() releases a reserved receipt when the side effect fails before mutation', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub] });
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  await assert.rejects(
    () => g.run({ selector: PAY, receipt: r }, async () => {
      throw new Error('bank API unavailable');
    }),
    /bank API unavailable/,
  );
  assert.equal(g.store.size, 0, 'failed pre-mutation run must not consume approval');
  const retry = await g.run({ selector: PAY, receipt: r }, async () => 'sent');
  assert.equal(retry.ok, true);
  assert.equal(retry.result, 'sent');
});

test('receiptAssuranceTier classification', () => {
  assert.equal(receiptAssuranceTier({ payload: { quorum: { m: 2, signers: ['a', 'b'] } } }), 'quorum');
  assert.equal(receiptAssuranceTier({ payload: { claim: { outcome: 'allow_with_signoff' } } }), 'class_a');
  assert.equal(receiptAssuranceTier({ payload: { claim: { outcome: 'allow' } } }), 'software');
});

test('default product pack guards the seven high-risk action families', () => {
  assert.equal(DEFAULT_GATE_MANIFEST['@version'], 'EP-ACTION-RISK-MANIFEST-v0.1');
  const guarded = HIGH_RISK_ACTION_PACKS.filter((a) => a.receipt_required);
  assert.equal(guarded.length, 7);
  assert.deepEqual(
    guarded.map((a) => a.action_type).sort(),
    [
      'data.export',
      'deploy.production',
      'payment.bank_details.change',
      'payment.release',
      'permission.admin.change',
      'record.delete',
      'regulated.decision.override',
    ].sort(),
  );
  for (const action of guarded) {
    assert.ok(['class_a', 'quorum'].includes(action.assurance_class), `${action.id} must require human-grade assurance`);
    assert.ok(action.execution_binding?.required_fields?.length >= 4, `${action.id} must bind material execution fields`);
  }
});

test('createTrustedActionFirewall uses default high-risk packs', async () => {
  const { pub } = makeKey();
  const g = createTrustedActionFirewall({ trustedKeys: [pub] });
  const out = await g.check({ selector: { protocol: 'mcp', tool: 'release_payment' } });
  assert.equal(out.allow, false);
  assert.equal(out.status, 428);
  assert.equal(out.challenge.required.assurance_class, 'class_a');
});

test('execution binding refuses a mismatched system-of-record mutation without consuming the receipt', async () => {
  const { pub, privateKey } = makeKey();
  const g = createTrustedActionFirewall({ trustedKeys: [pub] });
  const selector = { protocol: 'mcp', tool: 'release_payment' };
  const signedFields = {
    action_type: 'payment.release',
    amount_usd: 40000,
    currency: 'USD',
    payment_instruction_id: 'pi_123',
    beneficiary_account_hash: 'bene_hash_123',
  };
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff', extra: signedFields });

  const mismatch = await g.check({
    selector,
    receipt: r,
    observedAction: { ...signedFields, amount_usd: 999999 },
  });
  assert.equal(mismatch.allow, false);
  assert.equal(mismatch.reason, 'execution_binding_failed');
  assert.deepEqual(mismatch.evidence.execution_binding.mismatched_fields, ['amount_usd']);
  assert.equal(g.store.size, 0, 'failed binding must not consume the receipt');

  const allowed = await g.check({ selector, receipt: r, observedAction: signedFields });
  assert.equal(allowed.allow, true, allowed.reason);
});

test('reliance packet ties allow decision, execution attestation, field binding, and evidence head', async () => {
  const { pub, privateKey } = makeKey();
  const g = createTrustedActionFirewall({ trustedKeys: [pub] });
  const selector = { protocol: 'mcp', tool: 'release_payment' };
  const observedAction = {
    action_type: 'payment.release',
    amount_usd: 40000,
    currency: 'USD',
    payment_instruction_id: 'pi_456',
    beneficiary_account_hash: 'bene_hash_456',
  };
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff', extra: observedAction });
  const authorization = await g.check({ selector, receipt: r, observedAction });
  const execution = await g.recordExecution({ authorization, observedAction, outcome: 'executed' });
  const packet = g.reliancePacket({ authorization, execution });

  assert.equal(packet.verdict, 'rely');
  assert.equal(packet.summary.decision_hash, authorization.evidence.hash);
  assert.equal(packet.summary.execution_hash, execution.hash);
  assert.equal(packet.checks.find((c) => c.id === 'execution_fields_bound').ok, true);
  assert.equal(packet.checks.find((c) => c.id === 'execution_attests_decision').ok, true);
  assert.equal(packet.checks.find((c) => c.id === 'evidence_log_intact').ok, true);
});
