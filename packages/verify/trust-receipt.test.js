/**
 * verifyTrustReceipt — I-D Section 6.3 offline verification algorithm.
 *
 * Synthesizes a complete Section 6.2 Trust Receipt: a real Action Object, two
 * Authorization Contexts (dual approval), a Class-B Ed25519 signoff and a
 * Class-A WebAuthn signoff over the context digests, a 4-leaf Merkle tree with
 * a positioned inclusion path, and an Ed25519 log-signed checkpoint. Then
 * proves all six steps pass — and that each step independently fails closed:
 * tampered action, mismatched context commitment, forged signature, SoD
 * violations (initiator-as-approver, duplicate approver, missing approval),
 * key-validity-window miss, broken inclusion proof, wrong log key, and
 * out-of-window signed_at / committed_at.
 *
 * Run: node --test trust-receipt.test.js
 *
 * @license Apache-2.0
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { verifyTrustReceipt } from './index.js';

// ── canonicalize + sha256: must match index.js ───────────────────────────────
function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',')}}`;
  }
  return JSON.stringify(value);
}
const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const hashPair = (a, b) => { const s = [a, b].sort(); return sha256hex(s[0] + s[1]); };

// ── fixture actors ───────────────────────────────────────────────────────────
function ed25519() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}
function p256() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { privateKey, pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url') };
}

const logKey = ed25519();          // the trusted transparency-log key
const approverB = ed25519();       // Class B software key (controller)
const approverA = p256();          // Class A device key (CFO, WebAuthn)

const KEYS = {
  'ep:key:controller#1': { public_key: approverB.pub, key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
  'ep:key:cfo#1': { public_key: approverA.pub, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
};

// Class B signs the raw context digest with Ed25519.
function signB(digestHex) {
  return crypto.sign(null, Buffer.from(digestHex, 'hex'), approverB.privateKey).toString('base64url');
}
// Class A: WebAuthn assertion whose challenge is b64u(digest).
function signA(digestHex) {
  const challenge = Buffer.from(digestHex, 'hex').toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
  const rpIdHash = crypto.createHash('sha256').update('www.emiliaprotocol.ai').digest();
  const authData = Buffer.concat([rpIdHash, Buffer.from([0x05]), Buffer.from([0, 0, 0, 0])]);
  const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]);
  const signature = crypto.sign('sha256', signedData, approverA.privateKey);
  return {
    authenticator_data: authData.toString('base64url'),
    client_data_json: clientDataJSON.toString('base64url'),
    signature: signature.toString('base64url'),
  };
}

// ── receipt fixture builder ──────────────────────────────────────────────────
function buildReceipt(mutate = {}) {
  const action = {
    ep_version: '1.0',
    action_type: 'wire.release',
    target: { system: 'treasury.example', resource: 'wire/8841' },
    parameters: { amount: '2400000.00', currency: 'USD' },
    initiator: 'ep:entity:agent-recon-7',
    policy_id: 'ep:policy:wires-over-100k@v12',
    requested_at: '2026-06-09T17:21:04Z',
    ...(mutate.action || {}),
  };
  const action_hash = `sha256:${sha256hex(canonicalize(action))}`;

  const baseCtx = {
    ep_version: '1.0',
    context_type: 'ep.signoff.v1',
    action_hash,
    policy_id: 'ep:policy:wires-over-100k@v12',
    policy_hash: 'sha256:77ab1234',
    initiator: action.initiator,
    required_approvals: 2,
    issued_at: '2026-06-09T17:21:05Z',
    expires_at: '2026-06-09T17:36:05Z',
  };
  const ctx1 = { ...baseCtx, approver: 'ep:approver:jchen-controller', approver_index: 1, nonce: 'n-1', ...(mutate.ctx1 || {}) };
  const ctx2 = { ...baseCtx, approver: 'ep:approver:mrios-cfo', approver_index: 2, nonce: 'n-2', ...(mutate.ctx2 || {}) };
  const d1 = sha256hex(canonicalize(ctx1));
  const d2 = sha256hex(canonicalize(ctx2));

  const signoffs = mutate.signoffs || [
    { context_hash: `sha256:${d1}`, signature: signB(d1), key_class: 'B', approver_key_id: 'ep:key:controller#1', signed_at: '2026-06-09T17:24:40Z' },
    { context_hash: `sha256:${d2}`, signature: 'unused-for-class-a', key_class: 'A', approver_key_id: 'ep:key:cfo#1', signed_at: '2026-06-09T17:25:01Z', webauthn: signA(d2) },
  ];

  const receipt = {
    receipt_id: 'ep:receipt:01JTEST',
    action,
    action_hash,
    contexts: [ctx1, ctx2],
    signoffs,
    consumption: { nonce: 'n-consume', state: 'COMMITTED', committed_at: mutate.committed_at || '2026-06-09T17:25:02Z' },
  };

  // Build the log: leaf = hash of canonical receipt without log_proof.
  const leaf = sha256hex(canonicalize(receipt));
  const sibling1 = sha256hex('other-leaf-1');
  const sibling2 = sha256hex('other-subtree');
  const level1 = hashPair(leaf, sibling1);
  const root = hashPair(level1, sibling2);
  const checkpoint = { tree_size: 4, root_hash: `sha256:${root}`, log_key_id: 'ep:log:test#1' };
  const log_signature = crypto.sign(
    null,
    crypto.createHash('sha256').update(canonicalize(checkpoint), 'utf8').digest(),
    logKey.privateKey,
  ).toString('base64url');

  receipt.log_proof = {
    leaf_index: 0,
    inclusion_path: [
      { hash: sibling1, position: 'right' },
      { hash: sibling2, position: 'right' },
    ],
    checkpoint: { ...checkpoint, log_signature },
  };
  return receipt;
}

const OPTS = { approverKeys: KEYS, logPublicKey: logKey.pub };

// ── happy path ───────────────────────────────────────────────────────────────

test('a complete Trust Receipt passes all six Section 6.3 steps', () => {
  const r = verifyTrustReceipt(buildReceipt(), OPTS);
  assert.deepEqual(r.checks, {
    action_hash: true,
    context_commitments: true,
    signoff_signatures: true,
    sod: true,
    inclusion: true,
    checkpoint_signature: true,
    windows: true,
  }, JSON.stringify(r.errors));
  assert.equal(r.valid, true);
});

// ── step 1: action binding ───────────────────────────────────────────────────

test('step 1 — a tampered action parameter fails the action hash', () => {
  const receipt = buildReceipt();
  receipt.action.parameters.amount = '24000000.00'; // 10x after signing
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.action_hash, false);
  assert.equal(r.valid, false);
});

// ── step 2: context commitments ──────────────────────────────────────────────

test('step 2 — a context committing to a different action hash fails', () => {
  const receipt = buildReceipt({ ctx1: { action_hash: 'sha256:deadbeef' } });
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.context_commitments, false);
  assert.equal(r.valid, false);
});

test('step 2 — contexts with differing policy hashes fail', () => {
  const receipt = buildReceipt({ ctx2: { policy_hash: 'sha256:00ff' } });
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.context_commitments, false);
});

// ── step 3: signoff signatures + key windows ─────────────────────────────────

test('step 3 — a forged Class-B signature fails', () => {
  const other = ed25519();
  const receipt = buildReceipt();
  const d1 = receipt.signoffs[0].context_hash.replace('sha256:', '');
  receipt.signoffs[0].signature = crypto.sign(null, Buffer.from(d1, 'hex'), other.privateKey).toString('base64url');
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.signoff_signatures, false);
  assert.equal(r.valid, false);
});

test('step 3 — a Class-A assertion bound to a different context fails', () => {
  const receipt = buildReceipt();
  receipt.signoffs[1].webauthn = signA(sha256hex('a different context')); // wrong challenge
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.signoff_signatures, false);
});

test('step 3 — an approver key outside its validity window fails', () => {
  const keys = { ...KEYS, 'ep:key:controller#1': { ...KEYS['ep:key:controller#1'], valid_to: '2026-06-01T00:00:00Z' } }; // expired before issued_at
  const r = verifyTrustReceipt(buildReceipt(), { approverKeys: keys, logPublicKey: logKey.pub });
  assert.equal(r.checks.signoff_signatures, false);
});

test('step 3 — an unknown approver_key_id fails (no pinned key)', () => {
  const receipt = buildReceipt();
  receipt.signoffs[0].approver_key_id = 'ep:key:nobody#9';
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.signoff_signatures, false);
});

// ── step 4: separation of duties ─────────────────────────────────────────────

test('step 4 — the initiator appearing as an approver fails SoD', () => {
  const receipt = buildReceipt({ ctx1: { approver: 'ep:entity:agent-recon-7' } }); // initiator
  // Re-sign ctx1 under its new content so the signature itself is valid —
  // SoD must fail on its own, not via a broken signature.
  const ctx1 = receipt.contexts[0];
  const d1 = sha256hex(canonicalize(ctx1));
  receipt.signoffs[0] = { context_hash: `sha256:${d1}`, signature: signB(d1), key_class: 'B', approver_key_id: 'ep:key:controller#1', signed_at: '2026-06-09T17:24:40Z' };
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.sod, false);
  assert.match(r.errors.join(' '), /initiator appears in an approver slot/);
});

test('step 4 — duplicate approvers fail SoD', () => {
  const receipt = buildReceipt({ ctx2: { approver: 'ep:approver:jchen-controller' } }); // same as ctx1
  const ctx2 = receipt.contexts[1];
  const d2 = sha256hex(canonicalize(ctx2));
  receipt.signoffs[1] = { context_hash: `sha256:${d2}`, signature: 'x', key_class: 'A', approver_key_id: 'ep:key:cfo#1', signed_at: '2026-06-09T17:25:01Z', webauthn: signA(d2) };
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.sod, false);
  assert.match(r.errors.join(' '), /pairwise distinct/);
});

test('step 4 — fewer valid approvals than required_approvals fails', () => {
  const receipt = buildReceipt();
  receipt.signoffs = [receipt.signoffs[0]]; // only 1 of required 2
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.sod, false);
  assert.match(r.errors.join(' '), /approval count 1 < required_approvals 2/);
});

// ── step 5: log inclusion + checkpoint ───────────────────────────────────────

test('step 5 — a broken inclusion path fails', () => {
  const receipt = buildReceipt();
  receipt.log_proof.inclusion_path[0].hash = sha256hex('not-the-sibling');
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.inclusion, false);
  assert.equal(r.valid, false);
});

test('step 5 — a checkpoint signed by a different log key fails', () => {
  const r = verifyTrustReceipt(buildReceipt(), { approverKeys: KEYS, logPublicKey: ed25519().pub });
  assert.equal(r.checks.checkpoint_signature, false);
  assert.equal(r.valid, false);
});

// ── step 6: temporal windows ─────────────────────────────────────────────────

test('step 6 — signed_at after expires_at fails', () => {
  const receipt = buildReceipt();
  receipt.signoffs[0].signed_at = '2026-06-09T18:00:00Z'; // past 17:36:05Z expiry
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.windows, false);
});

test('step 6 — committed_at outside the context window fails', () => {
  const receipt = buildReceipt({ committed_at: '2026-06-10T00:00:00Z' });
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.windows, false);
});

// ── fail-closed on missing inputs ────────────────────────────────────────────

test('fails closed on a receipt with no contexts/signoffs', () => {
  const r = verifyTrustReceipt({ action: {}, action_hash: 'sha256:00' }, OPTS);
  assert.equal(r.valid, false);
});
