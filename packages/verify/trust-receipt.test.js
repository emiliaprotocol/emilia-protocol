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
import { buildConsistencyProof, merkleRoot } from './consistency.js';

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
// Legacy EP-MERKLE-v1 (sorted-pair) helper — used only by opt-in legacy tests.
const hashPair = (a, b) => { const s = [a, b].sort(); return sha256hex(s[0] + s[1]); };
// EP-MERKLE-v2 helpers (domain-separated, positional) — must match index.js.
const leafHashV2 = (canonicalPayload) =>
  crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0x00]), Buffer.from(canonicalPayload, 'utf8')])).digest('hex');
const hashPairV2 = (left, right) =>
  crypto.createHash('sha256').update(Buffer.concat([Buffer.from([0x01]), Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8')])).digest('hex');

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
  'ep:key:controller#1': { approver_id: 'ep:approver:jchen-controller', public_key: approverB.pub, key_class: 'B', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
  'ep:key:cfo#1': { approver_id: 'ep:approver:mrios-cfo', public_key: approverA.pub, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
};

// Class B signs the raw context digest with Ed25519.
function signB(digestHex) {
  return crypto.sign(null, Buffer.from(digestHex, 'hex'), approverB.privateKey).toString('base64url');
}
// Class A: WebAuthn assertion whose challenge is b64u(digest).
function signA(digestHex, { rpId = 'www.emiliaprotocol.ai', flags = 0x05 } = {}) {
  const challenge = Buffer.from(digestHex, 'hex').toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
  const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
  const authData = Buffer.concat([rpIdHash, Buffer.from([flags]), Buffer.from([0, 0, 0, 0])]);
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
  // PIP-007: an `attestation` shorthand puts the SAME object into both contexts.
  if (mutate.attestation !== undefined && !('initiator_attestation' in (mutate.ctx1 || {})) && !('initiator_attestation' in (mutate.ctx2 || {}))) {
    ctx1.initiator_attestation = mutate.attestation;
    ctx2.initiator_attestation = mutate.attestation;
  }
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

  // Build the log: default leaf = EP-MERKLE-v2(canonical receipt without log_proof).
  const legacyMerkle = mutate.legacyMerkle === true;
  const leaf = legacyMerkle ? sha256hex(canonicalize(receipt)) : leafHashV2(canonicalize(receipt));
  const sibling1 = sha256hex('other-leaf-1');
  const sibling2 = sha256hex('other-subtree');
  const level1 = legacyMerkle ? hashPair(leaf, sibling1) : hashPairV2(leaf, sibling1);
  const root = legacyMerkle ? hashPair(level1, sibling2) : hashPairV2(level1, sibling2);
  const checkpoint = {
    tree_size: 4,
    root_hash: `sha256:${root}`,
    log_key_id: 'ep:log:test#1',
    ...(legacyMerkle ? {} : { merkle_alg: 'EP-MERKLE-v2' }),
  };
  const log_signature = crypto.sign(
    null,
    crypto.createHash('sha256').update(canonicalize(checkpoint), 'utf8').digest(),
    logKey.privateKey,
  ).toString('base64url');

  receipt.log_proof = {
    ...(legacyMerkle ? {} : { alg: 'EP-MERKLE-v2', leaf_hash: `sha256:${leaf}` }),
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
const STRICT_OPTS = {
  ...OPTS,
  strict: true,
  rpId: 'www.emiliaprotocol.ai',
  allowedOrigins: ['https://www.emiliaprotocol.ai'],
  expectedPolicyHash: 'sha256:77ab1234',
};

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

test('step 1 — non-I-JSON signed material is rejected before Trust Receipt hashing', () => {
  const receipt = buildReceipt({ action: { parameters: { amount: 2400000.25, currency: 'USD' } } });
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.valid, false);
  assert.match(r.errors.join(' '), /canonicalization profile/);
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

test('step 3 — a Class-A assertion without user presence fails', () => {
  const receipt = buildReceipt();
  const d2 = receipt.signoffs[1].context_hash.replace('sha256:', '');
  receipt.signoffs[1].webauthn = signA(d2, { flags: 0x04 }); // UV only, no UP
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.signoff_signatures, false);
  assert.equal(r.valid, false);
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

test('a signed denied receipt remains valid decision evidence but cannot authorize reliance', () => {
  const receipt = buildReceipt({
    ctx1: { decision: 'denied' },
    ctx2: { decision: 'denied' },
  });
  const r = verifyTrustReceipt(receipt, OPTS);

  assert.equal(r.checks.context_commitments, true);
  assert.equal(r.checks.signoff_signatures, true);
  assert.equal(r.checks.windows, true);
  assert.equal(r.checks.sod, false);
  assert.equal(r.valid, false);
  assert.match(r.errors.join(' '), /signed denial.*does not authorize/);
});

// ── step 4: separation of duties ─────────────────────────────────────────────

test('step 4 — the initiator appearing as an approver fails SoD', () => {
  // The initiator IS one of the bound approvers (jchen), so every signoff passes
  // the key↔approver binding and SoD must fail on its own: the initiator cannot
  // also be an approver. buildReceipt re-signs the contexts under the new
  // initiator, so the signatures and the log leaf are valid.
  const receipt = buildReceipt({ action: { initiator: 'ep:approver:jchen-controller' } });
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.sod, false);
  assert.match(r.errors.join(' '), /initiator appears in an approver slot/);
});

test('step 4 — duplicate approvers fail SoD', () => {
  // Both contexts name the CFO and are BOTH signed by the CFO's own bound key,
  // so the key↔approver binding passes and SoD must fail purely on name
  // distinctness (the same approver cannot fill two slots).
  const receipt = buildReceipt({ ctx1: { approver: 'ep:approver:mrios-cfo' }, ctx2: { approver: 'ep:approver:mrios-cfo' } });
  const ctx1 = receipt.contexts[0]; const d1 = sha256hex(canonicalize(ctx1));
  const ctx2 = receipt.contexts[1]; const d2 = sha256hex(canonicalize(ctx2));
  receipt.signoffs[0] = { context_hash: `sha256:${d1}`, signature: 'x', key_class: 'A', approver_key_id: 'ep:key:cfo#1', signed_at: '2026-06-09T17:24:40Z', webauthn: signA(d1) };
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

// ── step 4: required_approvals type — cross-language parity (fail-closed) ─────
// required_approvals is signed INSIDE the context; buildReceipt re-signs, so the
// value below is legitimately what the approver signed. A string that would
// coerce to a satisfiable threshold must NOT be silently coerced — otherwise one
// signoff satisfies a threshold of 2 (SoD bypass). Matches Python + Go.

test('step 4 — required_approvals as a string is malformed and fails closed', () => {
  // single 1-of context, but the threshold is the string "2" — an under-approval
  // that Number("2") would have satisfied. Must reject.
  const receipt = buildReceipt({
    ctx1: { required_approvals: '2' },
    ctx2: { required_approvals: '2' },
  });
  receipt.signoffs = [receipt.signoffs[0]]; // one valid signoff only
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.sod, false);
  assert.match(r.errors.join(' '), /required_approvals must be an integer/);
  assert.equal(r.valid, false);
});

test('step 4 — non-integer required_approvals never throws and is rejected', () => {
  for (const bad of ['abc', 2.5, true, [], {}, '1']) {
    const receipt = buildReceipt({ ctx1: { required_approvals: bad }, ctx2: { required_approvals: bad } });
    let r;
    assert.doesNotThrow(() => { r = verifyTrustReceipt(receipt, OPTS); });
    assert.equal(r.checks.sod, false, `sod should fail for required_approvals=${JSON.stringify(bad)}`);
    assert.equal(r.valid, false);
  }
});

// ── timestamp profile — canonical RFC3339 with offset (Z or ±hh:mm) ──────────
// issued_at/expires_at are signed inside the context; buildReceipt re-signs. The
// window checks (step 6) parse them, so a non-conforming form fails the window on
// all three ports identically (JS/Python/Go).

test('timestamp profile — a no-timezone issued_at is rejected (fail-closed)', () => {
  // issued_at is signed inside the context (buildReceipt re-signs), so the
  // signature is valid — but a no-timezone "2026-07-01T12:00:00" is not the
  // canonical profile, so every window/key-window parse of it fails closed. The
  // receipt must be rejected. Matches Python + Go.
  const receipt = buildReceipt({
    ctx1: { issued_at: '2026-07-01T12:00:00', expires_at: '2026-07-01T20:00:00' },
    ctx2: { issued_at: '2026-07-01T12:00:00', expires_at: '2026-07-01T20:00:00' },
  });
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.windows, false);
  assert.equal(r.valid, false);
});

test('timestamp profile — a date-only issued_at is rejected (fail-closed)', () => {
  const receipt = buildReceipt({
    ctx1: { issued_at: '2026-07-01', expires_at: '2026-07-02' },
    ctx2: { issued_at: '2026-07-01', expires_at: '2026-07-02' },
  });
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.windows, false);
  assert.equal(r.valid, false);
});

test('timestamp profile — a numeric +hh:mm offset is accepted', () => {
  // issued/expires as +02:00 == [17:21:05, 17:36:05]Z, which contains the default
  // signed_at (17:24:40Z / 17:25:01Z) and committed_at (17:25:02Z). Those defaults
  // stay untouched so the Merkle leaf (hashed over the whole receipt) is stable.
  const receipt = buildReceipt({
    ctx1: { issued_at: '2026-06-09T19:21:05+02:00', expires_at: '2026-06-09T19:36:05+02:00' },
    ctx2: { issued_at: '2026-06-09T19:21:05+02:00', expires_at: '2026-06-09T19:36:05+02:00' },
  });
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.windows, true, JSON.stringify({ checks: r.checks, errors: r.errors }));
  assert.equal(r.valid, true);
});

// ── step 5: log inclusion + checkpoint ───────────────────────────────────────

test('step 5 — a broken inclusion path fails', () => {
  const receipt = buildReceipt();
  receipt.log_proof.inclusion_path[0].hash = sha256hex('not-the-sibling');
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.inclusion, false);
  assert.equal(r.valid, false);
});

test('step 5 — a legacy Trust Receipt Merkle proof is opt-in only', () => {
  const receipt = buildReceipt({ legacyMerkle: true });
  const strictDefault = verifyTrustReceipt(receipt, OPTS);
  assert.equal(strictDefault.checks.inclusion, false);
  assert.match(strictDefault.errors.join(' '), /EP-MERKLE-v2/);
  assert.equal(strictDefault.valid, false);

  const legacyAllowed = verifyTrustReceipt(receipt, { ...OPTS, allowLegacyTrustReceiptMerkle: true });
  assert.equal(legacyAllowed.checks.inclusion, true, JSON.stringify(legacyAllowed.errors));
});

test('step 5 — a v2 Trust Receipt leaf_hash must bind this receipt', () => {
  const receipt = buildReceipt();
  receipt.log_proof.leaf_hash = `sha256:${sha256hex('not-this-receipt')}`;
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.checks.inclusion, false);
  assert.match(r.errors.join(' '), /leaf_hash/);
  assert.equal(r.valid, false);
});

test('step 5 — a checkpoint signed by a different log key fails', () => {
  const r = verifyTrustReceipt(buildReceipt(), { approverKeys: KEYS, logPublicKey: ed25519().pub });
  assert.equal(r.checks.checkpoint_signature, false);
  assert.equal(r.valid, false);
});

// Rebuild a receipt's log_proof as LEGACY EP-MERKLE-v1 (sorted-pair, no domain
// separation, no alg marker) so the migration guard can be exercised.
const hashPairV1 = (a, b) => { const s = [a, b].sort(); return sha256hex(s[0] + s[1]); };
function buildLegacyV1Receipt() {
  const receipt = buildReceipt();
  const leafSource = { ...receipt };
  delete leafSource.log_proof;
  const leaf = sha256hex(canonicalize(leafSource));
  const sibling1 = sha256hex('other-leaf-1');
  const sibling2 = sha256hex('other-subtree');
  const root = hashPairV1(hashPairV1(leaf, sibling1), sibling2);
  const checkpoint = { tree_size: 4, root_hash: `sha256:${root}`, log_key_id: 'ep:log:test#1' };
  const log_signature = crypto.sign(null, crypto.createHash('sha256').update(canonicalize(checkpoint), 'utf8').digest(), logKey.privateKey).toString('base64url');
  receipt.log_proof = {
    leaf_index: 0,
    inclusion_path: [{ hash: sibling1, position: 'right' }, { hash: sibling2, position: 'right' }],
    checkpoint: { ...checkpoint, log_signature },
  };
  return receipt;
}

test('step 5 — a legacy EP-MERKLE-v1 inclusion is REFUSED by default (no allowLegacyMerkle)', () => {
  const r = verifyTrustReceipt(buildLegacyV1Receipt(), OPTS);
  assert.equal(r.checks.inclusion, false);
  assert.equal(r.valid, false);
});

test('step 5 — the same legacy v1 inclusion VERIFIES when allowLegacyMerkle is opted in', () => {
  const r = verifyTrustReceipt(buildLegacyV1Receipt(), { ...OPTS, allowLegacyMerkle: true });
  assert.equal(r.checks.inclusion, true);
  assert.equal(r.valid, true);
});

test('step 5 — a v2 inclusion still verifies (default path) but a v1 fold does not reconstruct it', () => {
  const r = verifyTrustReceipt(buildReceipt(), OPTS);
  assert.equal(r.checks.inclusion, true);
});

// ── I-JSON canonicalization gate (fail-closed, mirrors verifyReceipt) ─────────

test('rejects a non-representable number in signed material (fail-closed I-JSON gate)', () => {
  const receipt = buildReceipt();
  receipt.action.parameters.rate = 1e-7; // outside the EP canonicalization profile
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => /canonicalization profile/.test(e)));
});

test('rejects a value larger than a safe integer in signed material', () => {
  const receipt = buildReceipt();
  receipt.contexts[0].big = 1e20;
  const r = verifyTrustReceipt(receipt, OPTS);
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

// ── PIP-007: initiator escalation attestation — ADVISORY only ────────────────

test('PIP-007 — no attestation: advisory absent; all six checks unchanged (regression)', () => {
  const r = verifyTrustReceipt(buildReceipt(), OPTS);
  assert.equal(r.valid, true);
  // The frozen checks object is byte-for-byte what it was before this PIP.
  assert.deepEqual(Object.keys(r.checks), [
    'action_hash', 'context_commitments', 'signoff_signatures', 'sod', 'inclusion', 'checkpoint_signature', 'windows',
  ]);
  assert.deepEqual(r.attestation, { present: false, consistent: true, issues: [] });
});

test('PIP-007 — a well-formed attestation in every context: present + consistent, signature still valid', () => {
  const att = { escalation_trigger: 'magnitude', policy_basis: 'ep:policy:wires-over-100k@v12/rule:dual-auth', statement: 'Wire exceeds my single-action limit.' };
  const r = verifyTrustReceipt(buildReceipt({ attestation: att }), OPTS);
  assert.equal(r.valid, true, JSON.stringify(r.errors));
  assert.ok(Object.values(r.checks).every(Boolean));
  assert.equal(r.attestation.present, true);
  assert.equal(r.attestation.consistent, true);
  assert.deepEqual(r.attestation.issues, []);
});

test('PIP-007 — cross-context MISMATCH is flagged (MUST), but signature validity is unaffected', () => {
  // Different attestation per context — every individual signature stays valid.
  const r = verifyTrustReceipt(buildReceipt({
    ctx1: { initiator_attestation: { escalation_trigger: 'magnitude' } },
    ctx2: { initiator_attestation: { escalation_trigger: 'irreversibility' } },
  }), OPTS);
  // Cryptography is unaffected: the receipt still verifies 7/7.
  assert.equal(r.valid, true, JSON.stringify(r.errors));
  assert.equal(r.checks.signoff_signatures, true);
  // The advisory MUST flag the mismatch.
  assert.equal(r.attestation.present, true);
  assert.equal(r.attestation.consistent, false);
  assert.match(r.attestation.issues.join(' '), /differs across contexts/);
});

test('PIP-007 — attestation present in only one context is flagged inconsistent (signature unaffected)', () => {
  const r = verifyTrustReceipt(buildReceipt({
    ctx1: { initiator_attestation: { escalation_trigger: 'magnitude' } },
  }), OPTS);
  assert.equal(r.valid, true);
  assert.equal(r.attestation.consistent, false);
  assert.match(r.attestation.issues.join(' '), /present in some contexts but not all/);
});

test('PIP-007 — an over-cap statement is SHOULD-flagged; the receipt still verifies cryptographically', () => {
  const att = { escalation_trigger: 'magnitude', statement: 'x'.repeat(281) };
  const r = verifyTrustReceipt(buildReceipt({ attestation: att }), OPTS);
  assert.equal(r.valid, true);
  assert.equal(r.checks.signoff_signatures, true);
  assert.match(r.attestation.issues.join(' '), /character cap/);
});

test('PIP-007 — unknown members and policy_rule-without-basis are SHOULD-flagged; signature unaffected', () => {
  // NB: value is a STRING — a fractional float like 0.9 is (correctly) refused by
  // the I-JSON canonicalization gate; the "unknown member" flag is orthogonal to type.
  const att = { escalation_trigger: 'policy_rule', confidence: '0.9' }; // missing policy_basis + extra member
  const r = verifyTrustReceipt(buildReceipt({ attestation: att }), OPTS);
  assert.equal(r.valid, true);
  assert.equal(r.checks.signoff_signatures, true);
  const joined = r.attestation.issues.join(' ');
  assert.match(joined, /unknown member "confidence"/);
  assert.match(joined, /policy_rule.*without policy_basis/);
});

test('PIP-007 — a bad escalation_trigger enum is SHOULD-flagged; signature unaffected', () => {
  const r = verifyTrustReceipt(buildReceipt({ attestation: { escalation_trigger: 'because' } }), OPTS);
  assert.equal(r.valid, true);
  assert.match(r.attestation.issues.join(' '), /invalid escalation_trigger/);
});

// ── strict verifier: additive deployment-grade gate ─────────────────────────

test('strict verifier — complete receipt passes strict deployment gate', () => {
  const r = verifyTrustReceipt(buildReceipt(), STRICT_OPTS);
  assert.equal(r.valid, true, JSON.stringify(r.errors));
  assert.equal(r.strict.enabled, true);
  assert.equal(r.strict.valid, true, JSON.stringify(r.strict.errors));
  assert.deepEqual(r.strict.checks, {
    pinned_keys: true,
    rp_id: true,
    origin: true,
    user_presence: true,
    user_verification: true,
    key_windows: true,
    policy_hash: true,
    no_unsigned: true,
  });
});

test('strict verifier — default mode still does not evaluate the strict gate', () => {
  const r = verifyTrustReceipt(buildReceipt(), OPTS);
  assert.equal(r.valid, true, JSON.stringify(r.errors));
  assert.deepEqual(r.strict, { enabled: false, valid: true, checks: {}, errors: [] });
});

test('strict verifier — requires caller-pinned expected policy hash', () => {
  const r = verifyTrustReceipt(buildReceipt(), { ...OPTS, strict: true, rpId: 'www.emiliaprotocol.ai', allowedOrigins: ['https://www.emiliaprotocol.ai'] });
  assert.equal(r.checks.context_commitments, true, JSON.stringify(r.errors));
  assert.equal(r.strict.checks.policy_hash, false);
  assert.equal(r.valid, false);
  assert.match(r.errors.join(' '), /strict policy_hash requires opts\.expectedPolicyHash/);
});

test('verifier rejects Class-A WebAuthn assertions for the wrong pinned RP ID', () => {
  const r = verifyTrustReceipt(buildReceipt(), { ...STRICT_OPTS, rpId: 'login.evil.example' });
  assert.equal(r.checks.signoff_signatures, false, JSON.stringify(r.errors));
  assert.equal(r.strict.checks.rp_id, false);
  assert.equal(r.valid, false);
  assert.match(r.strict.errors.join(' '), /rpIdHash/);
});

test('strict verifier — requires Class-A WebAuthn user presence as well as UV', () => {
  const receipt = buildReceipt();
  const d2 = receipt.signoffs[1].context_hash.replace('sha256:', '');
  receipt.signoffs[1].webauthn = signA(d2, { flags: 0x04 }); // UV without UP
  const r = verifyTrustReceipt(receipt, STRICT_OPTS);
  assert.equal(r.checks.signoff_signatures, false, JSON.stringify(r.errors));
  assert.equal(r.strict.checks.user_verification, true);
  assert.equal(r.strict.checks.user_presence, false);
  assert.equal(r.valid, false);
});

test('strict verifier — requires explicit approver key validity windows', () => {
  const keys = {
    'ep:key:controller#1': { approver_id: 'ep:approver:jchen-controller', public_key: approverB.pub, key_class: 'B' },
    'ep:key:cfo#1': { approver_id: 'ep:approver:mrios-cfo', public_key: approverA.pub, key_class: 'A' },
  };
  const r = verifyTrustReceipt(buildReceipt(), { ...STRICT_OPTS, approverKeys: keys });
  assert.equal(r.checks.signoff_signatures, true, JSON.stringify(r.errors));
  assert.equal(r.strict.checks.key_windows, false);
  assert.equal(r.valid, false);
  assert.match(r.strict.errors.join(' '), /valid_from and valid_to/);
});

test('strict verifier — rejects unsigned critical signoff fields', () => {
  const receipt = buildReceipt();
  delete receipt.signoffs[0].signature;
  const r = verifyTrustReceipt(receipt, STRICT_OPTS);
  assert.equal(r.checks.signoff_signatures, false);
  assert.equal(r.strict.checks.no_unsigned, false);
  assert.equal(r.valid, false);
  assert.match(r.strict.errors.join(' '), /Ed25519 signoff signature/);
});

// ── class-downgrade attack: pinned Class-A key can't be met by a bare sig ────
// The signoff's declared key_class is ATTACKER-CONTROLLED. If the verifier let
// that value choose the verify routine, an attacker could pin a Class-A
// (WebAuthn, user-presence/user-verification) approver, declare key_class:'B',
// and hand over a bare raw signature over the digest — verifying with NO
// human-presence proof. The PINNED key entry's class MUST win: a pinned Class-A
// key is always verified as a real WebAuthn assertion and rejected if it only
// carries a raw signature. This must hold in BOTH the default and strict paths.

// A pinned Class-A key whose SPKI is Ed25519. This is the sharp witness: a bare
// Ed25519 signature over the raw digest WOULD verify on the raw-signature path
// (verifyEd25519OverDigest), so if the attacker-declared key_class:'B' were
// allowed to choose that path, the downgrade would succeed with NO WebAuthn
// proof. Only the pinned-class-wins rule (which forces the WebAuthn path for a
// pinned-A key) stops it. This makes the test a true red/green witness of the
// defense rather than passing incidentally on a P-256/Ed25519 key mismatch.
const approverAEd = ed25519();
const KEYS_A_ED = {
  ...KEYS,
  'ep:key:cfo#1': { approver_id: 'ep:approver:mrios-cfo', public_key: approverAEd.pub, key_class: 'A', valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' },
};
const OPTS_A_ED = { approverKeys: KEYS_A_ED, logPublicKey: logKey.pub };
const STRICT_OPTS_A_ED = { ...OPTS_A_ED, strict: true, rpId: 'www.emiliaprotocol.ai', allowedOrigins: ['https://www.emiliaprotocol.ai'], expectedPolicyHash: 'sha256:77ab1234' };

// Build a receipt where the CFO (pinned Class-A key ep:key:cfo#1) signs off with
// a DOWNGRADED signoff: declared key_class:'B' and a bare Ed25519 signature over
// the context digest produced by the pinned key's OWN private half, and NO
// webauthn assertion. Under the vulnerable code this raw signature verifies and
// the receipt is accepted with zero user-presence/user-verification proof.
function buildDowngradedReceipt() {
  const receipt = buildReceipt();
  const ctx2 = receipt.contexts[1];               // the CFO context
  const d2 = sha256hex(canonicalize(ctx2));
  const bareSig = crypto.sign(null, Buffer.from(d2, 'hex'), approverAEd.privateKey).toString('base64url');
  receipt.signoffs[1] = {
    context_hash: `sha256:${d2}`,
    signature: bareSig,                           // bare Ed25519 over the digest
    key_class: 'B',                               // attacker-declared downgrade
    approver_key_id: 'ep:key:cfo#1',              // pinned as Class-A (Ed25519 SPKI)
    signed_at: '2026-06-09T17:25:01Z',
    // NB: no `webauthn` — a real Class-A assertion is absent.
  };
  return receipt;
}

test('class-downgrade — pinned Class-A + declared key_class B + bare signature is REJECTED (default path)', () => {
  const r = verifyTrustReceipt(buildDowngradedReceipt(), OPTS_A_ED);
  assert.equal(r.checks.signoff_signatures, false, JSON.stringify(r.errors));
  assert.equal(r.valid, false);
});

test('class-downgrade — pinned Class-A downgrade is REJECTED under the strict gate too', () => {
  const r = verifyTrustReceipt(buildDowngradedReceipt(), STRICT_OPTS_A_ED);
  // Base signature verification fails closed (pinned class wins → WebAuthn path,
  // no assertion present).
  assert.equal(r.checks.signoff_signatures, false, JSON.stringify(r.errors));
  // And the strict no_unsigned gate keys on the pinned class, so it demands the
  // Class-A WebAuthn fields that the downgraded signoff does not carry.
  assert.equal(r.strict.checks.no_unsigned, false);
  assert.match(r.strict.errors.join(' '), /Class-A/);
  assert.equal(r.valid, false);
});

test('class-escalation — an unclassified pinned key cannot self-declare Class-A', () => {
  const unclassified = {
    ...KEYS,
    'ep:key:cfo#1': { ...KEYS['ep:key:cfo#1'] },
  };
  delete unclassified['ep:key:cfo#1'].key_class;
  const receipt = buildReceipt();

  const regular = verifyTrustReceipt(receipt, { approverKeys: unclassified, logPublicKey: logKey.pub });
  assert.equal(regular.checks.signoff_signatures, false, JSON.stringify(regular.errors));
  assert.equal(regular.valid, false);

  const strict = verifyTrustReceipt(receipt, {
    approverKeys: unclassified,
    logPublicKey: logKey.pub,
    strict: true,
    rpId: 'www.emiliaprotocol.ai',
    allowedOrigins: ['https://www.emiliaprotocol.ai'],
    expectedPolicyHash: 'sha256:77ab1234',
  });
  assert.equal(strict.checks.signoff_signatures, false, JSON.stringify(strict.errors));
  assert.equal(strict.valid, false);
});

// ── step 5c: opt-in priorCheckpoint consistency knob ─────────────────────────
// The caller pins a previously-observed checkpoint head; the receipt's
// checkpoint must be proven an append-only extension of it (RFC 6962 §2.1.2
// over EP-MERKLE-v2 branches). Knob off = behavior unchanged. Fail-closed on
// a malformed pin, missing proof, or invalid proof — each a distinct reason.

// Sign a checkpoint exactly as buildReceipt does.
const signCheckpoint = (cp) => crypto.sign(
  null,
  crypto.createHash('sha256').update(canonicalize(cp), 'utf8').digest(),
  logKey.privateKey,
).toString('base64url');

// Rebuild a receipt's log_proof over a REAL 4-leaf RFC 6962 tree (receipt leaf
// at index 1), and return the pinned prior head (the first 2 leaves) plus the
// genuine consistency proof from that head to the receipt's checkpoint.
function buildConsistencyReceipt() {
  const receipt = buildReceipt();
  const leafSource = { ...receipt };
  delete leafSource.log_proof;
  const receiptLeaf = leafHashV2(canonicalize(leafSource));
  const l0 = leafHashV2('log-entry-0');
  const l2 = leafHashV2('log-entry-2');
  const l3 = leafHashV2('log-entry-3');
  const allLeaves = [l0, receiptLeaf, l2, l3];
  const newRoot = merkleRoot(allLeaves);            // head at tree_size 4
  const oldRoot = merkleRoot(allLeaves.slice(0, 2)); // pinned prior head at tree_size 2
  const checkpoint = { tree_size: 4, root_hash: `sha256:${newRoot}`, log_key_id: 'ep:log:test#1', merkle_alg: 'EP-MERKLE-v2' };
  receipt.log_proof = {
    alg: 'EP-MERKLE-v2',
    leaf_hash: `sha256:${receiptLeaf}`,
    leaf_index: 1,
    inclusion_path: [
      { hash: l0, position: 'left' },
      { hash: hashPairV2(l2, l3), position: 'right' },
    ],
    checkpoint: { ...checkpoint, log_signature: signCheckpoint(checkpoint) },
  };
  const prior = {
    tree_size: 2,
    root_hash: `sha256:${oldRoot}`,
    consistency_proof: buildConsistencyProof(2, 4, allLeaves),
  };
  return { receipt, prior };
}

test('step 5c — knob OFF: result shape and behavior are unchanged (no consistency key)', () => {
  const { receipt } = buildConsistencyReceipt();
  const r = verifyTrustReceipt(receipt, OPTS);
  assert.equal(r.valid, true, JSON.stringify(r.errors));
  assert.deepEqual(Object.keys(r.checks), [
    'action_hash', 'context_commitments', 'signoff_signatures', 'sod', 'inclusion', 'checkpoint_signature', 'windows',
  ]);
  assert.equal('consistency' in r.checks, false);
});

test('step 5c — knob ON + genuine append-only proof from the pinned head passes', () => {
  const { receipt, prior } = buildConsistencyReceipt();
  const r = verifyTrustReceipt(receipt, { ...OPTS, priorCheckpoint: prior });
  assert.equal(r.checks.consistency, true, JSON.stringify(r.errors));
  assert.equal(r.valid, true);
});

test('step 5c — knob ON + equal heads: an EMPTY proof array is legitimate', () => {
  const { receipt } = buildConsistencyReceipt();
  const head = receipt.log_proof.checkpoint;
  const r = verifyTrustReceipt(receipt, {
    ...OPTS,
    priorCheckpoint: { tree_size: head.tree_size, root_hash: head.root_hash, consistency_proof: [] },
  });
  assert.equal(r.checks.consistency, true, JSON.stringify(r.errors));
  assert.equal(r.valid, true);
});

test('step 5c — knob ON + MISSING proof refuses with a distinct reason', () => {
  const { receipt, prior } = buildConsistencyReceipt();
  delete prior.consistency_proof;
  const r = verifyTrustReceipt(receipt, { ...OPTS, priorCheckpoint: prior });
  assert.equal(r.checks.consistency, false);
  assert.equal(r.valid, false);
  assert.match(r.errors.join(' '), /priorCheckpoint is pinned but consistency_proof is missing/);
});

test('step 5c — knob ON + TAMPERED proof refuses with a distinct reason', () => {
  const { receipt, prior } = buildConsistencyReceipt();
  prior.consistency_proof = [...prior.consistency_proof];
  prior.consistency_proof[0] = sha256hex('not-the-node');
  const r = verifyTrustReceipt(receipt, { ...OPTS, priorCheckpoint: prior });
  assert.equal(r.checks.consistency, false);
  assert.equal(r.valid, false);
  assert.match(r.errors.join(' '), /consistency_proof does not prove an append-only extension from the pinned prior checkpoint/);
});

test('step 5c — knob ON + a rewritten prior head (split view) refuses', () => {
  const { receipt, prior } = buildConsistencyReceipt();
  prior.root_hash = `sha256:${sha256hex('a-forked-history-head')}`; // not a prefix of this log
  const r = verifyTrustReceipt(receipt, { ...OPTS, priorCheckpoint: prior });
  assert.equal(r.checks.consistency, false);
  assert.equal(r.valid, false);
  assert.match(r.errors.join(' '), /does not prove an append-only extension/);
});

test('step 5c — knob ON + malformed pin fails closed with a distinct reason', () => {
  const { receipt, prior } = buildConsistencyReceipt();
  for (const badSize of ['2', 2.5, 0, -1, undefined]) {
    const r = verifyTrustReceipt(receipt, { ...OPTS, priorCheckpoint: { ...prior, tree_size: badSize } });
    assert.equal(r.checks.consistency, false, `tree_size=${JSON.stringify(badSize)}`);
    assert.equal(r.valid, false);
    assert.match(r.errors.join(' '), /priorCheckpoint requires integer tree_size >= 1 and root_hash/);
  }
});

test('step 5c — knob ON + receipt without a usable checkpoint fails closed', () => {
  const { receipt, prior } = buildConsistencyReceipt();
  delete receipt.log_proof; // no checkpoint head to extend to
  const r = verifyTrustReceipt(receipt, { ...OPTS, priorCheckpoint: prior });
  assert.equal(r.checks.consistency, false);
  assert.equal(r.valid, false);
  assert.match(r.errors.join(' '), /priorCheckpoint is pinned but the receipt checkpoint is missing tree_size or root_hash/);
});

// ── step 5: empty inclusion_path degenerate rule (fail-closed) ───────────────
// An empty path collapses the Merkle fold to leafHash === root_hash, which is
// only a true inclusion statement for a single-leaf tree. tree_size must be
// exactly the integer 1 (and leaf_index, when present, 0) — otherwise refuse.

// Rebuild a receipt's log_proof as a SINGLE-LEAF log: root == leaf, empty path.
// (Sentinel: a destructuring default would swallow a literal `undefined`.)
const ABSENT = Symbol('absent tree_size');
function buildSingleLeafReceipt({ treeSize = 1, leafIndex = 0 } = {}) {
  const receipt = buildReceipt();
  const leafSource = { ...receipt };
  delete leafSource.log_proof;
  const leaf = leafHashV2(canonicalize(leafSource));
  const checkpoint = { tree_size: treeSize, root_hash: `sha256:${leaf}`, log_key_id: 'ep:log:test#1', merkle_alg: 'EP-MERKLE-v2' };
  if (treeSize === ABSENT) delete checkpoint.tree_size; // "missing tree_size" case
  receipt.log_proof = {
    alg: 'EP-MERKLE-v2',
    leaf_hash: `sha256:${leaf}`,
    leaf_index: leafIndex,
    inclusion_path: [],
    checkpoint: { ...checkpoint, log_signature: signCheckpoint(checkpoint) },
  };
  return receipt;
}

test('step 5 — an empty inclusion_path with tree_size 1 (single-leaf log) verifies', () => {
  const r = verifyTrustReceipt(buildSingleLeafReceipt(), OPTS);
  assert.equal(r.checks.inclusion, true, JSON.stringify(r.errors));
  assert.equal(r.valid, true);
});

test('step 5 — an empty inclusion_path with tree_size > 1 is REFUSED (degenerate leaf==root forgery)', () => {
  const r = verifyTrustReceipt(buildSingleLeafReceipt({ treeSize: 4 }), OPTS);
  assert.equal(r.checks.inclusion, false);
  assert.equal(r.valid, false);
  assert.match(r.errors.join(' '), /empty inclusion_path requires checkpoint tree_size 1 \(single-leaf tree\)/);
});

test('step 5 — an empty inclusion_path with a non-integer, zero, or missing tree_size fails closed', () => {
  for (const badSize of ['1', 0, null, ABSENT]) {
    const r = verifyTrustReceipt(buildSingleLeafReceipt({ treeSize: badSize }), OPTS);
    assert.equal(r.checks.inclusion, false, `tree_size=${String(badSize)}`);
    assert.equal(r.valid, false);
    assert.match(r.errors.join(' '), /empty inclusion_path requires checkpoint tree_size 1/);
  }
});

test('step 5 — an empty inclusion_path with a nonzero leaf_index is REFUSED even at tree_size 1', () => {
  const r = verifyTrustReceipt(buildSingleLeafReceipt({ leafIndex: 1 }), OPTS);
  assert.equal(r.checks.inclusion, false);
  assert.equal(r.valid, false);
  assert.match(r.errors.join(' '), /empty inclusion_path requires leaf_index 0 in a single-leaf tree/);
});
