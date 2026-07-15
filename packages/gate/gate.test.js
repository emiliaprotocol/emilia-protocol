/**
 * @emilia-protocol/gate tests — run with `node --test`.
 * @license Apache-2.0
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createGate, createTrustedActionFirewall, createEg1Harness, DEFAULT_GATE_MANIFEST, HIGH_RISK_ACTION_PACKS, receiptAssuranceTier, mintDeviceSignoff, mintQuorumEvidence } from './index.js';

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
const HASH_FOR = (action) => crypto.createHash('sha256').update(canon({ action_type: action }), 'utf8').digest('hex');
const WEBAUTHN_SCOPE = {
  rpId: 'emiliaprotocol.ai',
  allowedOrigins: ['https://www.emiliaprotocol.ai'],
};
const TEST_QUORUM_POLICY = {
  mode: 'threshold',
  required: 2,
  distinct_humans: true,
  window_sec: 900,
  approvers: [
    { role: 'cfo', approver: 'ep:approver:cfo' },
    { role: 'controller', approver: 'ep:approver:controller' },
  ],
};

function pinnedQuorumInputs(q) {
  return {
    quorumPolicy: structuredClone(q.policy),
    approverKeys: Object.fromEntries(q.members.map((member, index) => [`member_${index}`, {
      approver_id: member.signoff.context.approver,
      public_key: member.approver_public_key,
      key_class: 'A',
    }])),
  };
}
let n = 0;
// Mint a receipt. When outcome === 'allow_with_signoff', embed a GENUINE WebAuthn
// device signoff so the receipt cryptographically earns class_a (post-audit: the
// Gate no longer credits a bare outcome string). When quorum:true, embed a real
// EP-QUORUM-v1 doc.
function receipt(privateKey, { action = 'payment.release', outcome = 'allow', extra = {}, quorum = false } = {}) {
  const claim = { action_type: action, outcome, ...extra };
  const payload = {
    receipt_id: `rcpt_${++n}`, subject: 'agent:test', issuer: 'ep:org:test',
    created_at: new Date().toISOString(), claim,
  };
  if (quorum) {
    payload.quorum = mintQuorumEvidence({ actionHash: HASH_FOR(action), threshold: 2 });
  } else if (outcome === 'allow_with_signoff') {
    const s = mintDeviceSignoff({ actionHash: HASH_FOR(action), approver: 'ep:approver:test' });
    payload.signoff = s.signoff;
    payload.approver_public_key = s.approver_public_key;
  }
  return mint(privateKey, payload);
}
function fixtureAssurance(doc) {
  const claim = doc?.payload?.claim || {};
  const q = claim.quorum || doc?.payload?.quorum;
  const signers = Array.isArray(q?.signers) ? q.signers : [];
  const threshold = Number(q?.threshold ?? q?.m ?? 0);
  if (threshold >= 2 && new Set(signers).size >= threshold) {
    return { ok: true, tier: 'quorum', reason: 'fixture_assurance_verified' };
  }
  if (claim.outcome === 'allow_with_signoff' || doc?.payload?.signoff) {
    return { ok: true, tier: 'class_a', reason: 'fixture_assurance_verified' };
  }
  return { ok: true, tier: 'software', reason: 'fixture_assurance_verified' };
}
function gateOpts(opts = {}) {
  return { verifyAssurance: fixtureAssurance, ...opts };
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
  const g = createGate(gateOpts({ manifest: MANIFEST, trustedKeys: [pub] }));
  const out = await g.check({ selector: { protocol: 'mcp', tool: 'read_balance' } });
  assert.equal(out.allow, true);
  assert.equal(out.reason, 'not_guarded');
});

test('missing receipt -> 428 challenge', async () => {
  const { pub } = makeKey();
  const g = createGate(gateOpts({ manifest: MANIFEST, trustedKeys: [pub] }));
  const out = await g.check({ selector: PAY });
  assert.equal(out.allow, false);
  assert.equal(out.status, 428);
  assert.ok(out.challenge.required);
  assert.match(out.header, /action=/);
});

test('valid class_a receipt -> allow; same receipt again -> replay refused', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate(gateOpts({ manifest: MANIFEST, trustedKeys: [pub] }));
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  const a = await g.check({ selector: PAY, receipt: r });
  assert.equal(a.allow, true, a.reason);
  const b = await g.check({ selector: PAY, receipt: r });
  assert.equal(b.allow, false);
  assert.equal(b.reason, 'replay_refused');
});

test('tampered receipt -> rejected', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate(gateOpts({ manifest: MANIFEST, trustedKeys: [pub] }));
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  r.payload.claim.amount_usd = 999; // mutate a signed field
  const out = await g.check({ selector: PAY, receipt: r });
  assert.equal(out.allow, false);
  assert.match(out.reason, /receipt_rejected/);
});

test('assurance too low (software receipt where class_a required) -> refused', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate(gateOpts({ manifest: MANIFEST, trustedKeys: [pub] }));
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow' }); // software tier
  const out = await g.check({ selector: PAY, receipt: r });
  assert.equal(out.allow, false);
  assert.equal(out.reason, 'assurance_too_low');
});

test('untrusted issuer key -> refused', async () => {
  const { pub } = makeKey();
  const attacker = makeKey();
  const g = createGate(gateOpts({ manifest: MANIFEST, trustedKeys: [pub] }));
  const r = receipt(attacker.privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  const out = await g.check({ selector: PAY, receipt: r });
  assert.equal(out.allow, false);
});

test('wrong action_type -> refused', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate(gateOpts({ manifest: MANIFEST, trustedKeys: [pub] }));
  const r = receipt(privateKey, { action: 'payment.refund', outcome: 'allow_with_signoff' });
  const out = await g.check({ selector: PAY, receipt: r });
  assert.equal(out.allow, false);
});

test('guard() wrapper throws when refused, runs when allowed', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate(gateOpts({ manifest: MANIFEST, trustedKeys: [pub] }));
  const release = g.guard(async (amt) => `sent ${amt}`, { selector: () => PAY, receipt: (amt, r) => r });
  await assert.rejects(() => release(100, null), /EMILIA Gate refused/);
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  assert.equal(await release(100, r), 'sent 100');
});

test('evidence log is hash-chained and tamper-evident', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate(gateOpts({ manifest: MANIFEST, trustedKeys: [pub] }));
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
  const g = createGate(gateOpts({ manifest: MANIFEST, trustedKeys: [pub] }));
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
  const g = createGate(gateOpts({ manifest: MANIFEST, trustedKeys: [pub] }));
  const release = g.guard(async (amt) => `sent ${amt}`, { selector: () => PAY, receipt: (amt, r) => r });
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  assert.equal(await release(100, r), 'sent 100');
  const recs = g.evidence.all();
  const exec = recs.find((x) => x.kind === 'execution');
  assert.ok(exec, 'execution receipt present');
  assert.equal(exec.outcome, 'executed');
  assert.equal(g.evidence.verify().ok, true);
});

test('run() consumes an indeterminate attempt when the executor throws', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate(gateOpts({ manifest: MANIFEST, trustedKeys: [pub] }));
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  let externalEffects = 0;
  await assert.rejects(
    () => g.run({ selector: PAY, receipt: r }, async () => {
      externalEffects += 1; // The bank applied it, but its response was lost.
      throw new Error('bank response lost for SECRET-ACCOUNT-448193');
    }),
    /bank response lost/,
  );
  assert.equal(g.store.size, 1, 'an attempted effect must consume the approval');
  const retry = await g.run({ selector: PAY, receipt: r }, async () => {
    externalEffects += 1;
    return 'sent-again';
  });
  assert.equal(retry.ok, false);
  assert.match(retry.authorization.reason, /replay/);
  assert.equal(externalEffects, 1, 'the ambiguous external effect is never repeated');
  const indeterminate = g.evidence.all().find((entry) => entry.kind === 'execution');
  assert.equal(indeterminate?.outcome, 'indeterminate');
  assert.deepEqual(indeterminate?.detail, { code: 'effect_attempted_outcome_unknown' });
  assert.doesNotMatch(JSON.stringify(indeterminate), /SECRET-ACCOUNT-448193/);
});

test('run() commits a successful effect and permanently refuses replay', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate(gateOpts({ manifest: MANIFEST, trustedKeys: [pub] }));
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  let executions = 0;
  const first = await g.run({ selector: PAY, receipt: r }, async () => {
    executions += 1;
    return 'settled';
  });
  assert.equal(first.ok, true);
  assert.equal(first.result, 'settled');

  const replay = await g.run({ selector: PAY, receipt: r }, async () => {
    executions += 1;
    return 'settled-again';
  });
  assert.equal(replay.ok, false);
  assert.match(replay.authorization.reason, /replay/);
  assert.equal(executions, 1);
});

test('receiptAssuranceTier is cryptographically verified, not payload-inferred (DoD audit)', () => {
  // A fabricated quorum block with NO per-signer signatures earns only software.
  assert.equal(receiptAssuranceTier({ payload: { quorum: { m: 2, signers: ['a', 'b'], threshold: 2 } } }), 'software');
  // A self-asserted outcome string with NO WebAuthn device signoff earns only software.
  assert.equal(receiptAssuranceTier({ payload: { claim: { outcome: 'allow_with_signoff' } } }), 'software');
  // A plain software receipt is software.
  assert.equal(receiptAssuranceTier({ payload: { claim: { outcome: 'allow' } } }), 'software');

  // A GENUINE self-contained device signoff. The signoff VERIFIES, but its
  // approver key travels inside the receipt: by DEFAULT (no opt-in, no pinned
  // keys) that key does NOT elevate the tier — crediting it would let anyone mint
  // a keypair, self-sign, and launder VERIFIED into ACCEPTED. So it stays software.
  const s = mintDeviceSignoff({ actionHash: HASH_FOR('payment.release'), approver: 'ep:approver:test' });
  const signoffDoc = { payload: { signoff: s.signoff, approver_public_key: s.approver_public_key } };
  assert.equal(receiptAssuranceTier(signoffDoc), 'software');
  // With the explicit self-contained opt-in, the same embedded signoff earns class_a.
  assert.equal(receiptAssuranceTier(signoffDoc, { allowEmbeddedApproverKeys: true, ...WEBAUTHN_SCOPE }), 'class_a');
  // OR when the embedded approver key is one the relying party PINNED.
  assert.equal(
    receiptAssuranceTier(signoffDoc, { approverKeys: { device: { approver_id: s.signoff.context.approver, public_key: s.approver_public_key } }, ...WEBAUTHN_SCOPE }),
    'class_a',
  );

  // A GENUINE self-contained quorum (real per-signer assertions). Same guard: by
  // DEFAULT the embedded member keys do not elevate. A blanket embedded-key
  // opt-in is deliberately insufficient for organizational quorum.
  const q = mintQuorumEvidence({ actionHash: HASH_FOR('payment.release'), threshold: 2 });
  const quorumDoc = { payload: { quorum: q } };
  assert.equal(receiptAssuranceTier(quorumDoc), 'software');
  assert.equal(receiptAssuranceTier(quorumDoc, { allowEmbeddedApproverKeys: true, ...WEBAUTHN_SCOPE }), 'software');
  // Quorum requires both identity-bound pinned keys and the RP-pinned policy.
  assert.equal(receiptAssuranceTier(quorumDoc, { ...pinnedQuorumInputs(q), ...WEBAUTHN_SCOPE }), 'quorum');

  // A quorum evidence doc with a broken (tampered) member signature is NOT credited
  // quorum even under the opt-in — the cryptographic check still fails closed.
  const tampered = mintQuorumEvidence({ actionHash: HASH_FOR('payment.release'), threshold: 2 });
  tampered.members[0].signoff.context.approver = 'ep:approver:someone_else'; // breaks challenge binding
  assert.equal(receiptAssuranceTier({ payload: { quorum: tampered } }, { ...pinnedQuorumInputs(tampered), ...WEBAUTHN_SCOPE }), 'software');

  // The pinned-proof / caller-supplied-verifier path (main) still credits class_a
  // when an explicit verifier attests it — self-assertion alone never does.
  assert.equal(receiptAssuranceTier({ payload: { claim: { outcome: 'allow_with_signoff' } } }, { verifyAssurance: fixtureAssurance }), 'class_a');
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
  const g = createTrustedActionFirewall(gateOpts({ trustedKeys: [pub] }));
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
  const g = createTrustedActionFirewall(gateOpts({ trustedKeys: [pub] }));
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

// =============================================================================
// DoD AUDIT: the credited tier MUST be cryptographically verified, not inferred
// from self-asserted payload content. These prove the deeper hole is closed.
// =============================================================================

const QUORUM_MANIFEST = {
  '@version': 'EP-ACTION-RISK-MANIFEST-v0.1',
  actions: [
    { id: 'grant_admin', action_type: 'permission.admin.change', receipt_required: true, risk: 'critical', assurance_class: 'quorum', match: { protocol: 'mcp', tool: 'grant_admin' } },
  ],
};
const GRANT = { protocol: 'mcp', tool: 'grant_admin' };

test('AUDIT: a fabricated quorum block (no per-signer signatures) is REFUSED', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate({ manifest: QUORUM_MANIFEST, trustedKeys: [pub], quorumPolicy: TEST_QUORUM_POLICY, ...WEBAUTHN_SCOPE });
  // A receipt that merely CLAIMS quorum — signers + threshold, but no members,
  // no WebAuthn assertions. Signed by a trusted issuer, so the Ed25519 check
  // passes; the fraud is that the quorum is self-asserted.
  const resigned = mint(privateKey, {
    receipt_id: 'rcpt_fabquorum', subject: 'agent:test', issuer: 'ep:org:test',
    created_at: new Date().toISOString(),
    claim: { action_type: 'permission.admin.change', outcome: 'allow' },
    quorum: { signers: ['ep:a', 'ep:b'], threshold: 2 }, // fabricated: no members, no signatures
  });
  const out = await g.check({ selector: GRANT, receipt: resigned });
  assert.equal(out.allow, false);
  assert.equal(out.reason, 'assurance_too_low');
  assert.equal(out.evidence.have_tier, 'software'); // fabricated quorum earns nothing above software
  assert.equal(out.evidence.need_tier, 'quorum');
  assert.equal(out.evidence.assurance_tier_source, 'cryptographic_verification');
});

test('AUDIT: a single-issuer software receipt does NOT satisfy class_a', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub], ...WEBAUTHN_SCOPE }); // class_a required
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow' }); // software only
  const out = await g.check({ selector: PAY, receipt: r });
  assert.equal(out.allow, false);
  assert.equal(out.reason, 'assurance_too_low');
  assert.equal(out.evidence.have_tier, 'software');
});

test('AUDIT: outcome:allow_with_signoff string WITHOUT WebAuthn evidence does NOT satisfy class_a', async () => {
  const { pub, privateKey } = makeKey();
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub], ...WEBAUTHN_SCOPE });
  // Self-asserted outcome string, but NO signoff evidence attached.
  const r = mint(privateKey, {
    receipt_id: 'rcpt_selfassert', subject: 'agent:test', issuer: 'ep:org:test',
    created_at: new Date().toISOString(),
    claim: { action_type: 'payment.release', outcome: 'allow_with_signoff' },
  });
  const out = await g.check({ selector: PAY, receipt: r });
  assert.equal(out.allow, false);
  assert.equal(out.reason, 'assurance_too_low');
  assert.equal(out.evidence.have_tier, 'software');
});

test('AUDIT: a single-issuer software receipt does NOT satisfy quorum', async () => {
  const { pub, privateKey } = makeKey();
  // allowEmbeddedApproverKeys:true opts into the self-contained embedded-evidence
  // mode so a genuine embedded signoff still earns class_a (which is below quorum).
  const g = createGate({ manifest: QUORUM_MANIFEST, trustedKeys: [pub], quorumPolicy: TEST_QUORUM_POLICY, allowEmbeddedApproverKeys: true, ...WEBAUTHN_SCOPE });
  const r = receipt(privateKey, { action: 'permission.admin.change', outcome: 'allow_with_signoff' }); // class_a at best
  const out = await g.check({ selector: GRANT, receipt: r });
  assert.equal(out.allow, false);
  assert.equal(out.reason, 'assurance_too_low');
  assert.equal(out.evidence.have_tier, 'class_a'); // genuine signoff, but quorum needs more
  assert.equal(out.evidence.need_tier, 'quorum');
});

test('AUDIT: a genuinely quorum-verified receipt PASSES a quorum gate', async () => {
  const { pub, privateKey } = makeKey();
  const r = receipt(privateKey, { action: 'permission.admin.change', quorum: true });
  const g = createGate({ manifest: QUORUM_MANIFEST, trustedKeys: [pub], ...pinnedQuorumInputs(r.payload.quorum), ...WEBAUTHN_SCOPE });
  const out = await g.check({ selector: GRANT, receipt: r });
  assert.equal(out.allow, true, out.reason);
  assert.equal(out.evidence.have_tier, 'quorum');
  assert.equal(out.evidence.assurance_tier_source, 'cryptographic_verification');
});

test('AUDIT: receipt-supplied 1-of-1 policy cannot weaken the pinned 2-of-2 rule', async () => {
  const { pub, privateKey } = makeKey();
  const q = mintQuorumEvidence({
    actionHash: HASH_FOR('permission.admin.change'),
    threshold: 1,
    approvers: [{ role: 'cfo', approver: 'ep:approver:cfo' }],
  });
  const r = mint(privateKey, {
    receipt_id: 'rcpt_weak_quorum', subject: 'agent:test', issuer: 'ep:org:test',
    created_at: new Date().toISOString(),
    claim: { action_type: 'permission.admin.change', outcome: 'allow' },
    quorum: q,
  });
  const approverKeys = {
    cfo: {
      approver_id: q.members[0].signoff.context.approver,
      public_key: q.members[0].approver_public_key,
      key_class: 'A',
    },
  };
  const g = createGate({
    manifest: QUORUM_MANIFEST,
    trustedKeys: [pub],
    approverKeys,
    quorumPolicy: TEST_QUORUM_POLICY,
    ...WEBAUTHN_SCOPE,
  });
  const out = await g.check({ selector: GRANT, receipt: r });
  assert.equal(out.allow, false);
  assert.equal(out.reason, 'assurance_too_low');
  assert.equal(out.evidence.have_tier, 'software');
});

test('AUDIT: a genuine WebAuthn device signoff PASSES a class_a gate', async () => {
  const { pub, privateKey } = makeKey();
  // Self-contained embedded signoff: opt in so the embedded approver key may
  // elevate the tier (default OFF now guards against trust-laundering).
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub], allowEmbeddedApproverKeys: true, ...WEBAUTHN_SCOPE });
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  const out = await g.check({ selector: PAY, receipt: r });
  assert.equal(out.allow, true, out.reason);
  assert.equal(out.evidence.have_tier, 'class_a');
});

test('AUDIT: embedded approver key does NOT elevate the tier by DEFAULT (trust-laundering guard)', async () => {
  const { pub, privateKey } = makeKey();
  // Same genuine embedded signoff, but the gate does NOT opt into embedded keys
  // and pins no approver keys. The signoff still VERIFIES cryptographically, but
  // an approver key carried inside the receipt is not proof the relying party
  // trusts that human — so it must NOT elevate above software. Fail closed.
  const g = createGate({ manifest: MANIFEST, trustedKeys: [pub], ...WEBAUTHN_SCOPE });
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  const out = await g.check({ selector: PAY, receipt: r });
  assert.equal(out.allow, false);
  assert.equal(out.reason, 'assurance_too_low');
  assert.equal(out.evidence.have_tier, 'software');
  // The signoff verified, but its embedded key was not trusted, so no elevation.
  assert.equal(out.evidence.tier_evidence.signoff.valid, true);
  assert.equal(out.evidence.tier_evidence.signoff.embedded_key_trusted, false);
});

test('AUDIT: a PINNED embedded approver key elevates the tier without a blanket opt-in', async () => {
  const { pub, privateKey } = makeKey();
  // Mint a real signoff, then pin its approver key. No allowEmbeddedApproverKeys:
  // the tier elevates because the embedded key is one the relying party pinned.
  const s = mintDeviceSignoff({ actionHash: HASH_FOR('payment.release'), approver: 'ep:approver:test' });
  const payload = {
    receipt_id: `rcpt_pinned_${Date.now()}`, subject: 'agent:test', issuer: 'ep:org:test',
    created_at: new Date().toISOString(),
    claim: { action_type: 'payment.release', outcome: 'allow_with_signoff' },
    signoff: s.signoff, approver_public_key: s.approver_public_key,
  };
  const r = mint(privateKey, payload);
  const g = createGate({
    manifest: MANIFEST, trustedKeys: [pub],
    approverKeys: { device: { approver_id: s.signoff.context.approver, public_key: s.approver_public_key, key_class: 'A' } },
    ...WEBAUTHN_SCOPE,
  });
  const out = await g.check({ selector: PAY, receipt: r });
  assert.equal(out.allow, true, out.reason);
  assert.equal(out.evidence.have_tier, 'class_a');
});

test('AUDIT: Class-A execution refuses when WebAuthn RP and origin are not pinned', async () => {
  const harness = createEg1Harness();
  const g = createTrustedActionFirewall({
    trustedKeys: [harness.publicKey],
    approverKeys: harness.approverKeys,
  });
  const out = await g.check({
    selector: { protocol: 'mcp', tool: 'release_payment' },
    receipt: harness.mint(),
    observedAction: harness.action,
  });
  assert.equal(out.allow, false);
  assert.equal(out.reason, 'assurance_context_unpinned');
});

test('AUDIT: a quorum receipt whose one member signature is broken is NOT credited quorum', async () => {
  const { pub, privateKey } = makeKey();
  const q = mintQuorumEvidence({ actionHash: HASH_FOR('permission.admin.change'), threshold: 2 });
  const pinned = pinnedQuorumInputs(q);
  const g = createGate({ manifest: QUORUM_MANIFEST, trustedKeys: [pub], ...pinned, ...WEBAUTHN_SCOPE });
  q.members[1].signoff.webauthn.signature = Buffer.from('forged').toString('base64url'); // break one signer
  const r = mint(privateKey, {
    receipt_id: 'rcpt_brokenquorum', subject: 'agent:test', issuer: 'ep:org:test',
    created_at: new Date().toISOString(),
    claim: { action_type: 'permission.admin.change', outcome: 'allow_with_signoff' },
    quorum: q,
  });
  const out = await g.check({ selector: GRANT, receipt: r });
  assert.equal(out.allow, false);
  assert.equal(out.reason, 'assurance_too_low');
  assert.equal(out.evidence.have_tier, 'software');
});

test('AUDIT: an unknown / mis-cased required tier fails CLOSED (no silent downgrade to software)', async () => {
  const { pub, privateKey } = makeKey();
  // No manifest: the required tier comes from the selector, which is NOT run
  // through the manifest validator — a mis-cased 'Class_A' reaches the tier check.
  const g = createGate({ trustedKeys: [pub] });
  // Even a genuine class_a signoff must not satisfy a tier the gate does not model.
  const r = receipt(privateKey, { action: 'payment.release', outcome: 'allow_with_signoff' });
  const out = await g.check({ selector: { action_type: 'payment.release', assurance_class: 'Class_A' }, receipt: r });
  assert.equal(out.allow, false);
  assert.equal(out.reason, 'unknown_required_tier');
});
