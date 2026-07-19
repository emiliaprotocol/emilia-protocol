// SPDX-License-Identifier: Apache-2.0
// Hardened-gate conformance for makeReceiptGate: target binding, indeterminate-
// outcome consumption, replay safety (post-commit AND in-flight), and sanitized
// rejections.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { makeReceiptGate, receiptAssuranceTier } from './gate.js';
import { evaluateReceiptAssurance } from './index.js';

const canon = (v) => (v === null || v === undefined ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));
const sha256Hex = (v) => crypto.createHash('sha256').update(v, 'utf8').digest('hex');
const sha256Bytes = (v) => crypto.createHash('sha256').update(v).digest();
const ASSURANCE_SCOPE = {
  rpId: 'www.emiliaprotocol.ai',
  allowedOrigins: ['https://www.emiliaprotocol.ai'],
};

// Mint a valid EP-RECEIPT-v1 bound to exactly `actionType`.
function mint(actionType, { outcome = 'allow_with_signoff', quorum = null, omitId = false } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const payload = {
    ...(omitId ? {} : { receipt_id: 'rcpt_' + crypto.randomBytes(6).toString('hex') }),
    subject: 'agent:autonomous',
    created_at: new Date().toISOString(),
    claim: {
      action_type: actionType,
      outcome,
      approver: 'jane@yourco.example',
      ...(quorum ? { quorum } : {}),
    },
  };
  const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
  return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value }, public_key: pub };
}

function fixtureAssurance(doc) {
  const claim = doc?.payload?.claim || {};
  const q = claim.quorum;
  const signers = Array.isArray(q?.signers) ? q.signers : [];
  const threshold = Number(q?.threshold ?? q?.m ?? 0);
  if (threshold >= 2 && new Set(signers).size >= threshold) {
    return { ok: true, tier: 'quorum', reason: 'fixture_assurance_verified' };
  }
  if (claim.outcome === 'allow_with_signoff') {
    return { ok: true, tier: 'class_a', reason: 'fixture_assurance_verified' };
  }
  return { ok: true, tier: 'software', reason: 'fixture_assurance_verified' };
}

const gate = () => makeReceiptGate({ action: 'db.records.delete', allowInlineKey: true, maxAgeSec: 900 });

// Parity with packages/gate redteam HI-5 and app/api/v1/guarded: a receipt that
// verifies but carries no receipt_id has no consumption identity, so it must be
// refused BEFORE the store is touched. Otherwise every no-id receipt reserves the
// same empty key: distinct authorizations collide, and a store that does not
// equate empty keys re-executes the guarded action on every replay.
test('receipt without receipt_id -> refused before any reservation', async () => {
  const calls = [];
  const spy = {
    async reserve(id) { calls.push(['reserve', id]); return true; },
    async commit(id) { calls.push(['commit', id]); return true; },
    async release(id) { calls.push(['release', id]); return true; },
  };
  const g = makeReceiptGate({ action: 'db.records.delete', allowInlineKey: true, maxAgeSec: 900, store: spy });

  const r = await g.check(mint('db.records.delete:customers', { omitId: true }), { target: 'customers' });
  assert.equal(r.ok, false);
  assert.equal(r.body.rejected.reason, 'missing_receipt_id');
  assert.deepEqual(calls, [], 'consumption store must not be touched for a no-id receipt');

  // A second, independently minted no-id receipt is refused identically rather
  // than colliding with the first on a shared empty consume key.
  const r2 = await g.check(mint('db.records.delete:customers', { omitId: true }), { target: 'customers' });
  assert.equal(r2.ok, false);
  assert.equal(r2.body.rejected.reason, 'missing_receipt_id');
  assert.deepEqual(calls, []);

  // The guarded effect never runs.
  let ran = false;
  const out = await g.run(mint('db.records.delete:customers', { omitId: true }), { target: 'customers' }, async () => { ran = true; });
  assert.equal(ran, false);
  assert.equal(out.ok, false);
});

test('missing receipt -> 428 challenge, no rejected detail', async () => {
  let ran = false;
  const r = await gate().run(null, { target: 'customers' }, async () => { ran = true; });
  assert.equal(r.ok, false);
  assert.equal(r.status, 428);
  assert.ok(r.body.required, 'challenge tells the agent what to bring');
  assert.equal(r.body.rejected, undefined, 'a plain missing-receipt challenge carries no rejected detail');
  assert.equal(ran, false, 'the action never ran');
});

test('valid, target-bound receipt -> runs and commits', async () => {
  const g = gate();
  let ran = false;
  const rc = mint('db.records.delete:customers');
  const r = await g.run(rc, { target: 'customers' }, async () => { ran = true; return 'deleted'; });
  assert.equal(r.ok, true);
  assert.equal(r.result, 'deleted');
  assert.equal(ran, true);
});

test('replay after success -> refused, sanitized, action not re-run', async () => {
  const g = gate();
  const rc = mint('db.records.delete:customers');
  await g.run(rc, { target: 'customers' }, async () => 'ok');
  let ranAgain = false;
  const r = await g.run(rc, { target: 'customers' }, async () => { ranAgain = true; });
  assert.equal(r.ok, false);
  assert.equal(r.body.rejected.reason, 'replay_refused');
  assert.deepEqual(Object.keys(r.body.rejected), ['reason'], 'rejection sanitized to { reason } only');
  assert.equal(ranAgain, false);
});

test('forged receipt -> refused, sanitized (no signer/subject leak)', async () => {
  const g = gate();
  const rc = mint('db.records.delete:customers');
  rc.payload.claim.action_type = 'db.records.delete:customers'; // tamper AFTER signing
  rc.payload.subject = 'attacker';
  const r = await g.run(rc, { target: 'customers' }, async () => { throw new Error('should not run'); });
  assert.equal(r.ok, false);
  assert.equal(r.body.rejected.reason, 'untrusted_or_invalid_signature');
  assert.deepEqual(Object.keys(r.body.rejected), ['reason']);
});

test('cross-target -> a receipt for customers cannot delete orders', async () => {
  const g = gate();
  const rc = mint('db.records.delete:customers');
  let ran = false;
  const r = await g.run(rc, { target: 'orders' }, async () => { ran = true; });
  assert.equal(r.ok, false);
  assert.equal(r.body.rejected.reason, 'action_mismatch');
  assert.deepEqual(Object.keys(r.body.rejected), ['reason']);
  assert.equal(ran, false);
});

test('indeterminate effect -> receipt is burned and cannot duplicate the action', async () => {
  const g = gate();
  const rc = mint('db.records.delete:customers');
  let effects = 0;
  await assert.rejects(g.run(rc, { target: 'customers' }, async () => {
    effects += 1; // the external effect happened
    throw new Error('response lost after effect');
  }));
  const retry = await g.run(rc, { target: 'customers' }, async () => {
    effects += 1;
    return 'duplicated';
  });
  assert.equal(retry.ok, false);
  assert.equal(retry.body.rejected.reason, 'replay_refused');
  assert.equal(effects, 1, 'an ambiguous response must never make an approval retryable');
});

test('in-flight replay -> the same receipt cannot drive two concurrent actions', async () => {
  const g = gate();
  const rc = mint('db.records.delete:customers');
  let release;
  const gate1 = g.run(rc, { target: 'customers' }, () => new Promise((res) => { release = res; }));
  // While the first action is still in progress, a second attempt is refused.
  const second = await g.run(rc, { target: 'customers' }, async () => 'should-not-run');
  assert.equal(second.ok, false);
  assert.equal(second.body.rejected.reason, 'replay_refused');
  release('done');
  const first = await gate1;
  assert.equal(first.ok, true);
});

test('two gate instances sharing an atomic store admit exactly one effect', async () => {
  const states = new Map();
  const store = {
    async reserve(id) {
      if (states.has(id)) return false;
      states.set(id, 'reserved');
      return true;
    },
    async commit(id) {
      if (states.get(id) !== 'reserved') throw new Error('not owner');
      states.set(id, 'committed');
      return true;
    },
    async release(id) {
      if (states.get(id) !== 'reserved') throw new Error('not owner');
      states.delete(id);
      return true;
    },
  };
  const a = makeReceiptGate({ action: 'db.records.delete', allowInlineKey: true, store });
  const b = makeReceiptGate({ action: 'db.records.delete', allowInlineKey: true, store });
  const receipt = mint('db.records.delete:customers');
  let effects = 0;
  const results = await Promise.all([
    a.run(receipt, { target: 'customers' }, async () => { effects += 1; return 'a'; }),
    b.run(receipt, { target: 'customers' }, async () => { effects += 1; return 'b'; }),
  ]);
  assert.equal(results.filter((result) => result.ok).length, 1);
  assert.equal(effects, 1, 'atomic reservation must prevent cross-instance duplicate effects');
});

test('legacy check-then-add stores are rejected as not fleet-safe', () => {
  assert.throws(
    () => makeReceiptGate({ action: 'db.records.delete', store: { has() { return false; }, add() {} } }),
    /legacy \{has, add\} stores are not fleet-safe/,
  );
});

test('reservation backend failure is a typed refusal and never invokes the effect', async () => {
  const store = {
    async reserve() { throw new Error('database unavailable'); },
    async commit() { return true; },
    async release() { return true; },
  };
  const g = makeReceiptGate({ action: 'db.records.delete', allowInlineKey: true, store });
  let ran = false;
  const r = await g.run(mint('db.records.delete'), {}, async () => { ran = true; });
  assert.equal(r.ok, false);
  assert.equal(r.body.rejected.reason, 'consumption_store_unavailable');
  assert.equal(ran, false);
});

test('custom assurance requires explicit success and exceptions fail closed', () => {
  const doc = mint('payment.release');
  const implicit = evaluateReceiptAssurance(doc, 'class_a', {
    verifyAssurance: () => ({ tier: 'quorum' }),
  });
  assert.equal(implicit.ok, false, 'a missing ok:true must not elevate assurance');
  assert.equal(implicit.reason, 'custom_assurance_verifier');

  const throwing = evaluateReceiptAssurance(doc, 'class_a', {
    verifyAssurance: () => { throw new Error('HSM unavailable'); },
  });
  assert.equal(throwing.ok, false);
  assert.equal(throwing.reason, 'assurance_verification_failed');
});

test('target binding via action function', async () => {
  const g = makeReceiptGate({ action: (t) => `block.delete:${t}`, allowInlineKey: true });
  const rc = mint('block.delete:abc123');
  const r = await g.run(rc, { target: 'abc123' }, async () => 'gone');
  assert.equal(r.ok, true);
});

test('assuranceClass=class_a refuses a software-only receipt', async () => {
  const g = makeReceiptGate({ action: 'payment.release', assuranceClass: 'class_a', allowInlineKey: true });
  const rc = mint('payment.release', { outcome: 'allow' });
  const r = await g.run(rc, {}, async () => {
    throw new Error('should not run');
  });
  assert.equal(r.ok, false);
  assert.equal(r.body.rejected.reason, 'assurance_proof_required');
});

test('assuranceClass=quorum refuses self-asserted high assurance without proof', async () => {
  const g = makeReceiptGate({ action: 'deploy.production', assuranceClass: 'quorum', allowInlineKey: true });
  const rc = mint('deploy.production', {
    quorum: { threshold: 2, signers: ['ep:approver:a', 'ep:approver:b'] },
  });
  const r = await g.run(rc, {}, async () => {
    throw new Error('should not run');
  });
  assert.equal(r.ok, false);
  assert.equal(r.body.rejected.reason, 'quorum_policy_required');
});

test('assuranceClass=quorum refuses a verified single human signoff', async () => {
  const g = makeReceiptGate({ action: 'deploy.production', assuranceClass: 'quorum', allowInlineKey: true, verifyAssurance: fixtureAssurance });
  const rc = mint('deploy.production');
  const r = await g.run(rc, {}, async () => {
    throw new Error('should not run');
  });
  assert.equal(r.ok, false);
  assert.equal(r.body.rejected.reason, 'assurance_too_low');
});

test('assuranceClass=quorum accepts threshold-2 distinct-human quorum evidence', async () => {
  const g = makeReceiptGate({ action: 'deploy.production', assuranceClass: 'quorum', allowInlineKey: true, verifyAssurance: fixtureAssurance });
  const rc = mint('deploy.production', {
    quorum: { threshold: 2, signers: ['ep:approver:a', 'ep:approver:b'] },
  });
  const r = await g.run(rc, {}, async () => 'deployed');
  assert.equal(r.ok, true, r.body?.rejected?.reason);
  assert.equal(r.result, 'deployed');
});

test('receiptAssuranceTier does not count duplicate quorum signers', () => {
  assert.equal(receiptAssuranceTier({
    payload: { claim: { outcome: 'allow_with_signoff', quorum: { threshold: 2, signers: ['same', 'same'] } } },
  }), 'software');
  assert.equal(receiptAssuranceTier({
    payload: { claim: { outcome: 'allow_with_signoff', quorum: { threshold: 2, signers: ['same', 'same'] } } },
  }, { verifyAssurance: fixtureAssurance }), 'class_a');
});

// ── Pinned-key quorum distinctness: a real EP-ASSURANCE-PROOF-v1, verified with
//    pinned approver keys, must count DISTINCT SIGNING KEYS — never the free-text
//    `approver` label. One key cannot satisfy a two-person rule. ────────────────

// A minimal pinned-key proof toolkit modeled on the EG-1 harness. Class-B (Ed25519)
// and Class-A (WebAuthn) signoffs both sign the EP-ASSURANCE-CONTEXT-v1 digest.
function assuranceKit() {
  const keys = {};
  function addKeyB(keyId, approverId = keyId) {
    const kp = crypto.generateKeyPairSync('ed25519');
    keys[keyId] = { approver_id: approverId, public_key: kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'), key_class: 'B' };
    return { keyId, privateKey: kp.privateKey };
  }
  function addKeyA(keyId, approverId = keyId) {
    const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    keys[keyId] = { approver_id: approverId, public_key: kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'), key_class: 'A' };
    return { keyId, privateKey: kp.privateKey };
  }
  function contextDigest(payload) {
    const context = {
      '@version': 'EP-ASSURANCE-CONTEXT-v1',
      receipt_id: payload.receipt_id,
      claim_hash: `sha256:${sha256Hex(canon(payload.claim))}`,
    };
    const contextHash = `sha256:${sha256Hex(canon(context))}`;
    return { contextHash, digest: Buffer.from(contextHash.replace(/^sha256:/, ''), 'hex') };
  }
  function signB(signer, digest, approver) {
    return {
      approver: approver ?? signer.keyId,
      approver_key_id: signer.keyId,
      key_class: 'B',
      signature: crypto.sign(null, digest, signer.privateKey).toString('base64url'),
    };
  }
  function signA(signer, digest, approver, {
    rpId = 'www.emiliaprotocol.ai',
    origin = 'https://www.emiliaprotocol.ai',
    duplicateChallenge = false,
  } = {}) {
    const challenge = Buffer.from(digest).toString('base64url');
    const clientDataJSON = Buffer.from(duplicateChallenge
      ? `{"type":"webauthn.get","challenge":"attacker","challenge":"${challenge}","origin":"${origin}"}`
      : JSON.stringify({ type: 'webauthn.get', challenge, origin }), 'utf8');
    const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
    const authData = Buffer.concat([rpIdHash, Buffer.from([0x05]), Buffer.from([0, 0, 0, 0])]); // UP + UV
    const signedData = Buffer.concat([authData, sha256Bytes(clientDataJSON)]);
    return {
      approver: approver ?? signer.keyId,
      approver_key_id: signer.keyId,
      key_class: 'A',
      webauthn: {
        authenticator_data: authData.toString('base64url'),
        client_data_json: clientDataJSON.toString('base64url'),
        signature: crypto.sign('sha256', signedData, signer.privateKey).toString('base64url'),
      },
    };
  }
  // Build a receipt doc carrying an EP-ASSURANCE-PROOF-v1 with the given signoffs.
  function receipt(threshold, makeSignoffs, claimApprover) {
    const payload = {
      receipt_id: 'rcpt_' + crypto.randomBytes(6).toString('hex'),
      subject: 'agent:autonomous',
      created_at: new Date().toISOString(),
      claim: {
        action_type: 'deploy.production',
        outcome: 'allow_with_signoff',
        ...(claimApprover ? { approver: claimApprover } : {}),
      },
    };
    const { contextHash, digest } = contextDigest(payload);
    payload.assurance_proof = {
      '@version': 'EP-ASSURANCE-PROOF-v1',
      context_hash: contextHash,
      threshold,
      signoffs: makeSignoffs(digest),
    };
    return { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value: 'unused-here' } };
  }
  return { keys, addKeyB, addKeyA, signB, signA, receipt };
}

function policyFor(...approvers) {
  return {
    mode: 'threshold', required: 2, distinct_humans: true, window_sec: 900,
    approvers: approvers.map((approver, index) => ({ role: `role_${index + 1}`, approver })),
  };
}

test('quorum: one key signing twice under two approver names does NOT satisfy threshold 2', () => {
  const kit = assuranceKit();
  const solo = kit.addKeyB('ep:key:controller#1');
  const doc = kit.receipt(2, (digest) => [
    kit.signB(solo, digest, 'ep:approver:alice'),
    kit.signB(solo, digest, 'ep:approver:bob'), // SAME key, different label — the attack
  ]);
  const r = evaluateReceiptAssurance(doc, 'quorum', { approverKeys: kit.keys, quorumPolicy: policyFor(solo.keyId, 'ep:key:other'), ...ASSURANCE_SCOPE });
  assert.equal(r.ok, false, 'a single key must not clear a two-person rule');
  assert.equal(r.have, 'software', 'one valid Class-B key -> software, never quorum');
});

test('quorum: one key signing twice under the IDENTICAL approver name does NOT satisfy threshold 2', () => {
  const kit = assuranceKit();
  const solo = kit.addKeyB('ep:key:controller#1');
  const doc = kit.receipt(2, (digest) => [
    kit.signB(solo, digest, 'ep:approver:same'),
    kit.signB(solo, digest, 'ep:approver:same'),
  ]);
  const r = evaluateReceiptAssurance(doc, 'quorum', { approverKeys: kit.keys, quorumPolicy: policyFor(solo.keyId, 'ep:key:other'), ...ASSURANCE_SCOPE });
  assert.equal(r.ok, false);
  assert.equal(r.have, 'software');
});

test('quorum: one Class-A key signing twice does NOT satisfy threshold 2', () => {
  const kit = assuranceKit();
  const solo = kit.addKeyA('ep:key:cfo#1');
  const doc = kit.receipt(2, (digest) => [
    kit.signA(solo, digest, 'ep:approver:alice'),
    kit.signA(solo, digest, 'ep:approver:bob'),
  ]);
  const r = evaluateReceiptAssurance(doc, 'quorum', { approverKeys: kit.keys, quorumPolicy: policyFor(solo.keyId, 'ep:key:other'), ...ASSURANCE_SCOPE });
  assert.equal(r.ok, false, 'a single Class-A key must not clear a two-person rule');
  assert.equal(r.have, 'class_a', 'still Class-A on one valid key');
});

test('quorum: TWO DISTINCT keys still satisfy threshold 2 (legitimate two-person rule)', () => {
  const kit = assuranceKit();
  const a = kit.addKeyA('ep:key:cfo#1');
  const b = kit.addKeyA('ep:key:controller#1');
  const doc = kit.receipt(2, (digest) => [
    kit.signA(a, digest, 'ep:approver:cfo'),
    kit.signA(b, digest, 'ep:approver:controller'),
  ]);
  const r = evaluateReceiptAssurance(doc, 'quorum', { approverKeys: kit.keys, quorumPolicy: policyFor(a.keyId, b.keyId), ...ASSURANCE_SCOPE });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.have, 'quorum');
});

test('quorum: one SPKI registered under two key IDs cannot fill two seats', () => {
  const kit = assuranceKit();
  const signer = kit.addKeyA('ep:key:shared#1', 'ep:approver:alice');
  kit.keys['ep:key:shared#2'] = {
    ...kit.keys['ep:key:shared#1'],
    approver_id: 'ep:approver:bob',
  };
  const alias = { ...signer, keyId: 'ep:key:shared#2' };
  const doc = kit.receipt(2, (digest) => [
    kit.signA(signer, digest),
    kit.signA(alias, digest),
  ]);
  const r = evaluateReceiptAssurance(doc, 'quorum', {
    approverKeys: kit.keys,
    quorumPolicy: policyFor('ep:approver:alice', 'ep:approver:bob'),
    ...ASSURANCE_SCOPE,
  });
  assert.equal(r.ok, false);
  assert.equal(r.have, 'class_a');
});

test('Class-A attribution comes from the pinned directory, not the receipt claim', () => {
  const kit = assuranceKit();
  const signer = kit.addKeyA('ep:key:alice#1', 'ep:approver:alice');
  const doc = kit.receipt(1, (digest) => [kit.signA(signer, digest)], 'ep:approver:mallory');
  const r = evaluateReceiptAssurance(doc, 'class_a', {
    approverKeys: kit.keys,
    ...ASSURANCE_SCOPE,
  });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'assurance_claimed_approver_mismatch');
  assert.deepEqual(r.approvers, ['ep:approver:alice']);
});

test('quorum: presenter threshold cannot weaken the relying-party policy', () => {
  const kit = assuranceKit();
  const a = kit.addKeyA('ep:key:cfo#1');
  const doc = kit.receipt(1, (digest) => [kit.signA(a, digest)]);
  const r = evaluateReceiptAssurance(doc, 'quorum', {
    approverKeys: kit.keys,
    quorumPolicy: policyFor(a.keyId, 'ep:key:controller#1'),
    ...ASSURANCE_SCOPE,
  });
  assert.equal(r.ok, false);
  assert.equal(r.have, 'class_a');
  assert.equal(r.reason, 'assurance_too_low');
});

test('Class-A proof refuses signed clientDataJSON with duplicate members', () => {
  const kit = assuranceKit();
  const signer = kit.addKeyA('ep:key:cfo#duplicate');
  const doc = kit.receipt(1, (digest) => [kit.signA(signer, digest, undefined, {
    duplicateChallenge: true,
  })]);
  const r = evaluateReceiptAssurance(doc, 'class_a', {
    approverKeys: kit.keys,
    ...ASSURANCE_SCOPE,
  });
  assert.equal(r.ok, false);
  assert.equal(r.have, 'software');
});

test('assurance class comes from the pinned key entry, never the signoff label', () => {
  const kit = assuranceKit();
  const softwareP256 = kit.addKeyA('ep:key:software-p256#1');
  kit.keys[softwareP256.keyId].key_class = 'B';
  const doc = kit.receipt(1, (digest) => [kit.signA(softwareP256, digest)]);
  const r = evaluateReceiptAssurance(doc, 'class_a', {
    approverKeys: kit.keys,
    rpId: 'www.emiliaprotocol.ai',
    allowedOrigins: ['https://www.emiliaprotocol.ai'],
  });
  assert.equal(r.ok, false, 'a presenter must not relabel a pinned Class-B key as Class-A');
  assert.equal(r.have, 'software');
});

test('Class-A proof is not credited for an unpinned WebAuthn RP or origin', () => {
  const kit = assuranceKit();
  const signer = kit.addKeyA('ep:key:cfo#wrong-rp');
  const doc = kit.receipt(1, (digest) => [kit.signA(signer, digest, undefined, {
    rpId: 'attacker.example',
    origin: 'https://attacker.example',
  })]);
  const r = evaluateReceiptAssurance(doc, 'class_a', {
    approverKeys: kit.keys,
    rpId: 'www.emiliaprotocol.ai',
    allowedOrigins: ['https://www.emiliaprotocol.ai'],
  });
  assert.equal(r.ok, false);
  assert.equal(r.have, 'software');
});

test('quorum requires distinct Class-A humans, not two software keys', () => {
  const kit = assuranceKit();
  const a = kit.addKeyB('ep:key:automation-a');
  const b = kit.addKeyB('ep:key:automation-b');
  const doc = kit.receipt(2, (digest) => [kit.signB(a, digest), kit.signB(b, digest)]);
  const r = evaluateReceiptAssurance(doc, 'quorum', {
    approverKeys: kit.keys,
    quorumPolicy: policyFor(a.keyId, b.keyId),
    rpId: 'www.emiliaprotocol.ai',
    allowedOrigins: ['https://www.emiliaprotocol.ai'],
  });
  assert.equal(r.ok, false, 'two machine signatures are not a human quorum');
  assert.equal(r.have, 'software');
});
