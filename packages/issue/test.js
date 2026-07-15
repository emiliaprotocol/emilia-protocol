/**
 * @emilia-protocol/issue — issuer → published verifier round-trip.
 * @license Apache-2.0
 *
 * The other half of I-D §6.3: a receipt this package emits MUST pass all seven
 * steps of @emilia-protocol/verify's verifyTrustReceipt(). These tests issue
 * receipts (single-approver Class B; dual-approval Class A + Class B; a real
 * Merkle log with prior leaves) and prove the published verifier accepts them —
 * and rejects tampered actions, wrong keys, and forged checkpoints.
 *
 * Same runner as packages/verify (node --test). The verifier is imported from
 * the sibling package source, so the round-trip is checked against the exact
 * bytes that ship on npm.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

import {
  generateIssuerKeyBundle,
  issueFromKeyBundle,
  issueAuthorizationReceipt,
  assembleAuthorizationReceipt,
  buildContexts,
  collectSignoffs,
  softwareSignerFromPrivateKey,
  generateEd25519KeyPair,
  formatLogKeyId,
  publicKeyToSpkiB64u,
  validateInitiatorAttestation,
  validateAgentBinding,
  canonicalize,
  buildReceiptAnchorV2,
  ESCALATION_TRIGGERS,
  ATTESTATION_STATEMENT_MAX,
} from './index.js';
import { verifyTrustReceipt, verifyReceipt } from '../verify/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RP_ID = 'www.emiliaprotocol.ai';
const ORIGIN = 'https://www.emiliaprotocol.ai';

const action = {
  ep_version: '1.0',
  action_type: 'wire.release',
  target: { system: 'treasury.example', resource: 'wire/8841' },
  parameters: { amount: '2400000.00', currency: 'USD' },
  initiator: 'ep:entity:agent-recon-7',
  policy_id: 'ep:policy:wires-over-100k@v12',
  requested_at: '2026-06-09T17:21:04Z',
};

// A trusted log keypair shared across the multi-signer tests below.
const log = (() => {
  const k = generateEd25519KeyPair();
  return { privateKey: k.privateKey, pub: k.publicKeyB64u, logKeyId: formatLogKeyId('test') };
})();

// Class B software signer (Ed25519 over the raw context digest).
function classBSigner(approverKeyId, approverId, signedAt) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    keyEntry: {
      approver_id: approverId,
      public_key: publicKeyToSpkiB64u(publicKey),
      key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z',
    },
    signer: softwareSignerFromPrivateKey({ privateKey, approverKeyId, signedAt, keyClass: 'B' }),
  };
}

// Class A WebAuthn signer (challenge = b64u(context digest)). The hosted
// ceremony produces this in production; here we synthesize it to prove the
// issuer's assembly accepts a Class-A signoff that the verifier validates.
function classASigner(approverKeyId, approverId, signedAt) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    keyEntry: {
      approver_id: approverId,
      public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z',
    },
    signer: {
      approverKeyId, keyClass: 'A', signedAt,
      signWebAuthn: (digest) => {
        const challenge = digest.toString('base64url');
        const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: ORIGIN }), 'utf8');
        const authData = Buffer.concat([crypto.createHash('sha256').update(RP_ID).digest(), Buffer.from([0x05]), Buffer.from([0, 0, 0, 0])]);
        const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
        return {
          authenticator_data: authData.toString('base64url'),
          client_data_json: clientDataJSON.toString('base64url'),
          signature: crypto.sign('sha256', signedData, privateKey).toString('base64url'),
        };
      },
    },
  };
}

async function issueDual() {
  const a = classASigner('ep:key:cfo#1', 'ep:approver:mrios-cfo', '2026-06-09T17:24:40Z');
  const b = classBSigner('ep:key:controller#1', 'ep:approver:jchen-controller', '2026-06-09T17:24:55Z');
  const receipt = await issueAuthorizationReceipt({
    receiptId: 'ep:receipt:01JISSUE',
    action,
    policyHash: 'sha256:77ab1234',
    approvers: ['ep:approver:mrios-cfo', 'ep:approver:jchen-controller'],
    issuedAt: '2026-06-09T17:21:05Z',
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    committedAt: new Date().toISOString(),
    signers: [a.signer, b.signer],
    log,
  });
  const approverKeys = { 'ep:key:cfo#1': a.keyEntry, 'ep:key:controller#1': b.keyEntry };
  return { receipt, approverKeys };
}

// ── Positive: full round-trip against the published verifier ─────────────────

test('issueFromKeyBundle → verifyTrustReceipt passes all seven §6.3 checks', async () => {
  const keys = generateIssuerKeyBundle({ approverId: 'ep:approver:finance-lead' });
  const { receipt, verification } = await issueFromKeyBundle({ keys, action, issuedAt: new Date().toISOString() });

  const r = verifyTrustReceipt(receipt, {
    approverKeys: verification.approver_keys,
    logPublicKey: verification.log_public_key,
  });

  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
  assert.equal(Object.keys(r.checks).length, 7);
  assert.ok(Object.values(r.checks).every(Boolean), 'every check must pass');
});

test('a dual-approval (Class A + Class B) receipt passes all seven §6.3 checks', async () => {
  const { receipt, approverKeys } = await issueDual();
  const r = verifyTrustReceipt(receipt, { approverKeys, logPublicKey: log.pub });
  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
  assert.ok(Object.values(r.checks).every(Boolean));
});

test('a receipt anchored in a log with prior leaves verifies (real inclusion proof)', async () => {
  const a = classBSigner('ep:key:k1', 'ep:approver:solo', '2026-06-09T17:24:40Z');
  const contexts = buildContexts({
    action, policyHash: 'sha256:aa', approvers: ['ep:approver:solo'], requiredApprovals: 1,
    issuedAt: '2026-06-09T17:21:05Z', expiresAt: new Date(Date.now() + 3600_000).toISOString(),
  });
  const signoffs = await collectSignoffs(contexts, [a.signer]);
  const priorLeaves = Array.from({ length: 6 }, (_, i) => crypto.createHash('sha256').update(`leaf-${i}`).digest('hex'));
  const receipt = assembleAuthorizationReceipt({
    receiptId: 'ep:receipt:withlog', action, contexts, signoffs,
    committedAt: new Date().toISOString(), log: { ...log, priorLeaves },
  });
  const r = verifyTrustReceipt(receipt, { approverKeys: { 'ep:key:k1': a.keyEntry }, logPublicKey: log.pub });
  assert.equal(r.valid, true);
  assert.equal(receipt.log_proof.checkpoint.tree_size, 7);
  assert.ok(receipt.log_proof.inclusion_path.length > 0);
});

// ── Negative: tamper, wrong key, forged checkpoint ───────────────────────────

test('a tampered action hash fails verification', async () => {
  const { receipt, approverKeys } = await issueDual();
  receipt.action.parameters.amount = '24000000.00'; // 10x after the log-signed checkpoint
  const r = verifyTrustReceipt(receipt, { approverKeys, logPublicKey: log.pub });
  assert.equal(r.valid, false);
  assert.equal(r.checks.action_hash, false);   // recomputed hash no longer matches
  assert.equal(r.checks.inclusion, false);     // leaf bytes changed → root won't reconstruct
});

test('a wrong approver key fails the signoff signature check', async () => {
  const { receipt, approverKeys } = await issueDual();
  // Swap in an unrelated public key for the CFO's pinned entry.
  const wrong = generateEd25519KeyPair();
  const tampered = {
    ...approverKeys,
    'ep:key:cfo#1': { ...approverKeys['ep:key:cfo#1'], public_key: wrong.publicKeyB64u, key_class: 'B' },
  };
  const r = verifyTrustReceipt(receipt, { approverKeys: tampered, logPublicKey: log.pub });
  assert.equal(r.valid, false);
  assert.equal(r.checks.signoff_signatures, false);
});

test('a forged checkpoint fails the checkpoint signature check', async () => {
  const { receipt, approverKeys } = await issueDual();
  // Re-sign the checkpoint with an attacker's log key, leaving the root intact.
  const attacker = generateEd25519KeyPair();
  const cp = { ...receipt.log_proof.checkpoint };
  delete cp.log_signature;
  const canon = (v) => v === null || v === undefined ? JSON.stringify(v)
    : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
      : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
        : JSON.stringify(v);
  const digest = crypto.createHash('sha256').update(canon(cp), 'utf8').digest();
  receipt.log_proof.checkpoint.log_signature = crypto.sign(null, digest, attacker.privateKey).toString('base64url');

  // Verifier still pins the genuine log key, so the forged signature is rejected.
  const r = verifyTrustReceipt(receipt, { approverKeys, logPublicKey: log.pub });
  assert.equal(r.valid, false);
  assert.equal(r.checks.checkpoint_signature, false);
  // Inclusion (root unchanged) still holds — only the signature is forged.
  assert.equal(r.checks.inclusion, true);
});

test('a verifier given no log public key fails closed on the checkpoint', async () => {
  const { receipt, approverKeys } = await issueDual();
  const r = verifyTrustReceipt(receipt, { approverKeys });
  assert.equal(r.valid, false);
  assert.equal(r.checks.checkpoint_signature, false);
});

// ── Guard: Class A cannot be minted from a local software key ─────────────────

test('softwareSignerFromPrivateKey refuses Class A (device-bound) keys', () => {
  const { privateKey } = generateEd25519KeyPair();
  assert.throws(
    () => softwareSignerFromPrivateKey({ privateKey, approverKeyId: 'ep:key:x#1', signedAt: '2026-06-09T17:24:40Z', keyClass: 'A' }),
    /Class A .* hosted ceremony/,
  );
});

// ── CLI: keygen + issue round-trip, and the demo subcommand ──────────────────

test('CLI keygen + issue round-trips through verifyTrustReceipt', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-issue-cli-'));
  const keysPath = path.join(dir, 'issuer-keys.json');
  const actionPath = path.join(dir, 'action.json');
  const receiptPath = path.join(dir, 'receipt.json');
  const verificationPath = path.join(dir, 'verification.json');

  fs.writeFileSync(actionPath, `${JSON.stringify(action, null, 2)}\n`);
  execFileSync(process.execPath, ['./cli.js', 'keygen', '--out', keysPath, '--log-name', 'acme'], { cwd: HERE });
  execFileSync(process.execPath, ['./cli.js', 'issue', '--keys', keysPath, '--action', actionPath, '--out', receiptPath, '--verification', verificationPath], { cwd: HERE });

  const receipt = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
  const verification = JSON.parse(fs.readFileSync(verificationPath, 'utf8'));
  // keygen --log-name acme must yield the canonical ep:log:acme#1 id.
  const keys = JSON.parse(fs.readFileSync(keysPath, 'utf8'));
  assert.equal(keys.log.key_id, 'ep:log:acme#1');

  const r = verifyTrustReceipt(receipt, {
    approverKeys: verification.approver_keys,
    logPublicKey: verification.log_public_key,
  });
  assert.equal(r.valid, true);
});

test('CLI refuses duplicate-member action JSON instead of signing parser-dependent semantics', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ep-issue-cli-duplicate-'));
  const keysPath = path.join(dir, 'issuer-keys.json');
  const actionPath = path.join(dir, 'action.json');
  const receiptPath = path.join(dir, 'receipt.json');
  fs.writeFileSync(actionPath, '{"action_type":"payment.release","action_type":"payment.redirect"}');
  execFileSync(process.execPath, ['./cli.js', 'keygen', '--out', keysPath], { cwd: HERE });
  assert.throws(
    () => execFileSync(process.execPath, ['./cli.js', 'issue', '--keys', keysPath, '--action', actionPath, '--out', receiptPath], { cwd: HERE, stdio: 'pipe' }),
    /Command failed/,
  );
  assert.equal(fs.existsSync(receiptPath), false);
});

test('CLI demo subcommand issues and verifies end-to-end (smoke)', () => {
  const out = execFileSync(process.execPath, ['./cli.js', 'demo'], { cwd: HERE, encoding: 'utf8' });
  assert.match(out, /VERIFIED/);
  assert.match(out, /ep:log:demo#1/);
  // The 7 verifier checks must all be present and ticked.
  for (const check of ['action_hash', 'context_commitments', 'signoff_signatures', 'sod', 'inclusion', 'checkpoint_signature', 'windows']) {
    assert.match(out, new RegExp(`✓ ${check}`), `demo output should show ✓ ${check}`);
  }
});

// ── PIP-007: initiator escalation attestation ────────────────────────────────

test('PIP-007 — issue WITH attestation round-trips; verifier reports it present + consistent', async () => {
  const keys = generateIssuerKeyBundle({ approverId: 'ep:approver:finance-lead' });
  const initiatorAttestation = {
    escalation_trigger: 'irreversibility',
    policy_basis: action.policy_id,
    statement: 'Wire is irreversible; policy requires a named human approval.',
  };
  const { receipt, verification } = await issueFromKeyBundle({ keys, action, initiatorAttestation });

  // The IDENTICAL object is in the (single) context.
  assert.deepEqual(receipt.contexts[0].initiator_attestation, initiatorAttestation);

  const r = verifyTrustReceipt(receipt, {
    approverKeys: verification.approver_keys,
    logPublicKey: verification.log_public_key,
  });
  // All original checks still pass.
  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
  assert.ok(Object.values(r.checks).every(Boolean));
  // And the advisory reports the attestation.
  assert.equal(r.attestation.present, true);
  assert.equal(r.attestation.consistent, true);
  assert.deepEqual(r.attestation.issues, []);
});

test('PIP-007 — a dual-approval receipt carries the IDENTICAL attestation in every context (canonical-identical)', async () => {
  const a = classBSigner('ep:key:k1', 'ep:approver:cfo', '2026-06-09T17:24:40Z');
  const b = classBSigner('ep:key:k2', 'ep:approver:controller', '2026-06-09T17:24:55Z');
  const initiatorAttestation = { escalation_trigger: 'magnitude', policy_basis: 'ep:policy:wires-over-100k@v12/rule:dual-auth' };
  const contexts = buildContexts({
    action, policyHash: 'sha256:aa', approvers: ['ep:approver:cfo', 'ep:approver:controller'], requiredApprovals: 2,
    issuedAt: '2026-06-09T17:21:05Z', expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    initiatorAttestation,
  });
  assert.equal(contexts.length, 2);
  const c0 = canonicalize(contexts[0].initiator_attestation);
  const c1 = canonicalize(contexts[1].initiator_attestation);
  assert.equal(c0, c1, 'canonicalize(initiator_attestation) must be identical across contexts');

  const signoffs = await collectSignoffs(contexts, [a.signer, b.signer]);
  const receipt = assembleAuthorizationReceipt({
    receiptId: 'ep:receipt:dual-att', action, contexts, signoffs,
    committedAt: new Date().toISOString(), log,
  });
  const r = verifyTrustReceipt(receipt, {
    approverKeys: { 'ep:key:k1': a.keyEntry, 'ep:key:k2': b.keyEntry }, logPublicKey: log.pub,
  });
  assert.equal(r.valid, true);
  assert.equal(r.attestation.present, true);
  assert.equal(r.attestation.consistent, true);
});

test('PIP-007 — receipts WITHOUT attestation behave exactly as before (no member added; advisory absent)', async () => {
  const keys = generateIssuerKeyBundle({ approverId: 'ep:approver:finance-lead' });
  const { receipt, verification } = await issueFromKeyBundle({ keys, action });
  assert.equal('initiator_attestation' in receipt.contexts[0], false);
  const r = verifyTrustReceipt(receipt, {
    approverKeys: verification.approver_keys, logPublicKey: verification.log_public_key,
  });
  assert.equal(r.valid, true);
  assert.equal(r.attestation.present, false);
  assert.equal(r.attestation.consistent, true);
  assert.deepEqual(r.attestation.issues, []);
});

test('PIP-007 — validateInitiatorAttestation enforces §1 (enum, cap, members, policy_rule basis)', () => {
  // Valid: all six enum members accepted.
  for (const trigger of ESCALATION_TRIGGERS) {
    const att = trigger === 'policy_rule'
      ? { escalation_trigger: trigger, policy_basis: 'ep:policy:x/rule:y' }
      : { escalation_trigger: trigger };
    assert.deepEqual(validateInitiatorAttestation(att), att);
  }
  // Missing/bad enum.
  assert.throws(() => validateInitiatorAttestation({ escalation_trigger: 'because' }), /escalation_trigger/);
  assert.throws(() => validateInitiatorAttestation({}), /escalation_trigger/);
  // Unknown member rejected.
  assert.throws(() => validateInitiatorAttestation({ escalation_trigger: 'magnitude', confidence: 0.9 }), /unknown member/);
  // Over-cap statement rejected.
  assert.throws(
    () => validateInitiatorAttestation({ escalation_trigger: 'magnitude', statement: 'x'.repeat(ATTESTATION_STATEMENT_MAX + 1) }),
    /character cap/,
  );
  // A statement exactly at the cap is allowed.
  assert.ok(validateInitiatorAttestation({ escalation_trigger: 'magnitude', statement: 'x'.repeat(ATTESTATION_STATEMENT_MAX) }));
  // policy_rule REQUIRES policy_basis.
  assert.throws(() => validateInitiatorAttestation({ escalation_trigger: 'policy_rule' }), /policy_basis is required/);
});

test('PIP-007 — buildContexts rejects a malformed attestation (fail closed)', () => {
  assert.throws(() => buildContexts({
    action, policyHash: 'sha256:aa', approvers: ['ep:approver:solo'], requiredApprovals: 1,
    issuedAt: '2026-06-09T17:21:05Z', expiresAt: '2026-06-09T17:36:05Z',
    initiatorAttestation: { escalation_trigger: 'magnitude', extra: 'nope' },
  }), /unknown member/);
});

test('PIP-007 — an over-cap statement passed via issueFromKeyBundle throws (issuer fails closed)', async () => {
  const keys = generateIssuerKeyBundle({ approverId: 'ep:approver:finance-lead' });
  await assert.rejects(
    () => issueFromKeyBundle({
      keys, action,
      initiatorAttestation: { escalation_trigger: 'magnitude', statement: 'x'.repeat(ATTESTATION_STATEMENT_MAX + 1) },
    }),
    /character cap/,
  );
});

// ── PIP-008: agent binding (identity + delegation reference) ─────────────────

test('PIP-008 — issue WITH agent_binding round-trips; receipt still fully verifies (signature covers it)', async () => {
  const keys = generateIssuerKeyBundle({ approverId: 'ep:approver:finance-lead' });
  const agentBinding = {
    agent_id: 'did:web:agents.acme.example:treasury-bot',
    delegation: { scheme: 'DRP', ref: 'drp:rcpt:abc123', hash: 'sha256:' + 'a'.repeat(64) },
    statement: 'Acting under the treasury delegation issued to this agent.',
  };
  const { receipt, verification } = await issueFromKeyBundle({ keys, action, agentBinding });

  // The IDENTICAL validated object is in the (single) context.
  assert.deepEqual(receipt.contexts[0].agent_binding, agentBinding);

  const r = verifyTrustReceipt(receipt, {
    approverKeys: verification.approver_keys,
    logPublicKey: verification.log_public_key,
  });
  // Additive: existing verifier passes unmodified, signature covers the binding.
  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
  assert.ok(Object.values(r.checks).every(Boolean));
});

test('PIP-008 — a dual-approval receipt carries the IDENTICAL agent_binding in every context', () => {
  const a = classBSigner('ep:key:k1', 'ep:approver:cfo', '2026-06-09T17:24:40Z');
  const b = classBSigner('ep:key:k2', 'ep:approver:controller', '2026-06-09T17:24:55Z');
  void a; void b;
  const agentBinding = { agent_id: 'urn:agent:recon-7', delegation: { scheme: 'WIMSE', ref: 'wimse:cred:9' } };
  const contexts = buildContexts({
    action, policyHash: 'sha256:aa', approvers: ['ep:approver:cfo', 'ep:approver:controller'], requiredApprovals: 2,
    issuedAt: '2026-06-09T17:21:05Z', expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    agentBinding,
  });
  assert.equal(contexts.length, 2);
  assert.equal(canonicalize(contexts[0].agent_binding), canonicalize(contexts[1].agent_binding));
  assert.deepEqual(contexts[0].agent_binding, agentBinding);
});

test('PIP-008 — validateAgentBinding fails closed on bad input', () => {
  assert.throws(() => validateAgentBinding({}), /agent_id is required/);
  assert.throws(() => validateAgentBinding({ agent_id: '' }), /agent_id is required/);
  assert.throws(() => validateAgentBinding({ agent_id: 'a', extra: 'x' }), /unknown member/);
  assert.throws(() => validateAgentBinding({ agent_id: 'a', delegation: { scheme: 'DRP' } }), /delegation\.ref/);
  assert.throws(() => validateAgentBinding({ agent_id: 'a', delegation: { scheme: 'DRP', ref: 'r', hash: 'sha256:zz' } }), /hash must be/);
  assert.throws(() => validateAgentBinding({ agent_id: 'a', statement: 'x'.repeat(ATTESTATION_STATEMENT_MAX + 1) }), /character cap/);
  // Valid: agent_id only, and full delegation.
  assert.deepEqual(validateAgentBinding({ agent_id: 'urn:agent:1' }), { agent_id: 'urn:agent:1' });
});

test('PIP-008 §1.1 — delegation.observed_at (freshness) accepted and round-trips', () => {
  const b = validateAgentBinding({ agent_id: 'a', delegation: { scheme: 'DRP', ref: 'r', observed_at: '2026-06-24T18:00:00Z' } });
  assert.equal(b.delegation.observed_at, '2026-06-24T18:00:00Z');
  // rejects a non-timestamp
  assert.throws(() => validateAgentBinding({ agent_id: 'a', delegation: { scheme: 'DRP', ref: 'r', observed_at: 'not-a-date' } }), /observed_at must be an RFC 3339/);
});

// ── CAT-2: EP-MERKLE-v2 anchor issuance → published-verifier round-trip ──────
test('buildReceiptAnchorV2: a v2-anchored document verifies under verifyReceipt and binds to its payload', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  const payload = {
    receipt_id: 'r_v2_issue',
    subject: 'ep:entity:agent-7',
    claim: { action_type: 'wire.release', outcome: 'allow' },
  };
  const sign = (p) => crypto.sign(null, Buffer.from(canonicalize(p), 'utf8'), privateKey).toString('base64url');

  // Real 2-leaf tree (one prior v2 leaf) so the inclusion proof is non-trivial.
  const anchor = buildReceiptAnchorV2(payload, ['ab'.repeat(32)]);
  assert.equal(anchor.alg, 'EP-MERKLE-v2');
  assert.ok(anchor.merkle_proof.length >= 1, 'expected a non-empty inclusion proof');

  const doc = {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value: sign(payload) },
    anchor,
  };
  const res = verifyReceipt(doc, pub);
  assert.equal(res.checks.anchor, true, 'v2 anchor must verify');
  assert.equal(res.valid, true);

  // Binding: the same anchor cannot be lifted onto a different payload, even with
  // a freshly valid signature — verifyReceipt recomputes the v2 leaf from payload.
  const lifted = {
    ...doc,
    payload: { ...payload, receipt_id: 'r_other' },
  };
  lifted.signature = { algorithm: 'Ed25519', value: sign(lifted.payload) };
  assert.equal(verifyReceipt(lifted, pub).checks.anchor, false, 'anchor must not bind to a different payload');
});

test('issuer refuses non-I-JSON signed material before minting Trust Receipts or anchors', async () => {
  const a = classBSigner('ep:key:k1', 'ep:approver:cfo', new Date().toISOString());
  const badAction = { ...action, parameters: { amount: 2400000.25, currency: 'USD' } };
  const contexts = buildContexts({
    action: badAction,
    policyHash: 'sha256:aa',
    approvers: ['ep:approver:cfo'],
    requiredApprovals: 1,
    issuedAt: '2026-06-09T17:21:05Z',
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
  });
  const signoffs = await collectSignoffs(contexts, [a.signer]);
  assert.throws(() => assembleAuthorizationReceipt({
    receiptId: 'ep:receipt:bad-float',
    action: badAction,
    contexts,
    signoffs,
    committedAt: new Date().toISOString(),
    log,
  }), /canonicalization profile/);
  assert.throws(() => buildReceiptAnchorV2({ amount: 1.25 }), /canonicalization profile/);
});
