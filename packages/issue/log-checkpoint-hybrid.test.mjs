// SPDX-License-Identifier: Apache-2.0
//
// EP-LOG-CHECKPOINT-HYBRID-v1 issuance tests, plus the regression that matters
// most in this partition: EP-AUTHORIZATION-RECEIPT-v1 issuance must stay
// BYTE-IDENTICAL now that a hybrid path exists beside it.
//
// The byte-identity half does not trust the module's own helpers. It
// independently recomputes the canonical JSON, the EP-MERKLE-v2 leaf, the
// checkpoint signing input, and the Ed25519 log signature with code written
// here, then asserts the issued receipt matches. A refactor that quietly
// changed what the issuer signs would pass a test that reused the issuer's own
// canonicalize(); it cannot pass this one.
//
// The PQ leg runs for real. This suite FAILS LOUDLY if @noble/post-quantum is
// missing rather than silently skipping.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  actionHash,
  assembleAuthorizationReceipt,
  assembleAuthorizationReceiptHybrid,
  buildContexts,
  collectSignoffs,
  createLogCheckpointHybridProof,
  generateEd25519KeyPair,
  logCheckpointHybridSignedBytes,
  logCheckpointSignedFields,
  softwareSignerFromPrivateKey,
  LOG_CHECKPOINT_HYBRID_PROFILE,
  LOG_CHECKPOINT_HYBRID_REQUIRED_ALGORITHMS,
} from './index.js';
import { signAgileSet } from '../verify/pq-signature-agility.js';
import {
  logCheckpointHybridSignedBytes as verifierCheckpointBytes,
  verifyLogCheckpointHybridProof,
} from '../verify/receipt-hybrid.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

// ---------------------------------------------------------------------------
// An INDEPENDENT canonicalizer. Deliberately not the issuer's: this is the
// second opinion the byte-identity regression rests on.
// ---------------------------------------------------------------------------
function independentCanonicalize(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return `[${value.map(independentCanonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort()
      .map((k) => `${JSON.stringify(k)}:${independentCanonicalize(value[k])}`)
      .join(',')}}`;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('outside the EP canonicalization profile');
    return String(value);
  }
  return JSON.stringify(value);
}

const independentLeafV2 = (canonical) => crypto.createHash('sha256')
  .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(canonical, 'utf8')]))
  .digest('hex');

const log = generateEd25519KeyPair();
const approver = generateEd25519KeyPair();
const pq = ml_dsa65.keygen(crypto.randomBytes(32));

const ACTION = { policy_id: 'pol_wire', initiator: 'ep:agent:bot', action_type: 'payment.send' };
const ISSUED_AT = '2026-08-17T12:00:00.000Z';

/** Build the exact argument object both assemblers are handed. */
async function issuanceArgs() {
  const contexts = buildContexts({
    action: ACTION,
    policyHash: `sha256:${'1'.repeat(64)}`,
    approvers: ['ep:approver:cfo'],
    requiredApprovals: 1,
    issuedAt: ISSUED_AT,
    expiresAt: '2026-08-17T13:00:00.000Z',
  });
  const signoffs = await collectSignoffs(contexts, [softwareSignerFromPrivateKey({
    privateKey: approver.privateKey,
    approverKeyId: 'ep:key:cfo#1',
    signedAt: ISSUED_AT,
  })]);
  return {
    receiptId: 'ep:receipt:checkpoint-hybrid-test',
    action: ACTION,
    contexts,
    signoffs,
    committedAt: ISSUED_AT,
    log: { privateKey: log.privateKey, logKeyId: 'ep:log:acme#1' },
  };
}

/** The dual-signer seam, shaped exactly like HybridCustodySigner.signSet. */
async function hybridSignSet(bytes) {
  return signAgileSet(new Uint8Array(bytes), [
    { alg: 'Ed25519', private_key: log.privateKey, key_id: 'ep:log:acme#1' },
    { alg: 'ML-DSA-65', private_key: pq.secretKey, key_id: 'ep:log:acme-pq#1' },
  ]);
}

const KEYS = {
  ed25519PublicKey: log.publicKeyB64u,
  ed25519KeyId: 'ep:log:acme#1',
  mldsaPublicKey: Buffer.from(pq.publicKey).toString('base64url'),
  mldsaKeyId: 'ep:log:acme-pq#1',
};

// ===========================================================================
// REGRESSION: EP-AUTHORIZATION-RECEIPT-v1 issuance is byte-identical
// ===========================================================================

test('REGRESSION: the hybrid path emits a receipt BYTE-IDENTICAL to the classical assembler', async () => {
  const args = await issuanceArgs();

  // assembleAuthorizationReceipt mints one random consumption nonce per call.
  // Pin it so "byte-identical" means exactly that rather than "identical apart
  // from the parts that always differ".
  const realRandomBytes = crypto.randomBytes;
  const fixed = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');
  crypto.randomBytes = (n) => (n === 16 ? fixed : realRandomBytes(n));
  try {
    const classical = assembleAuthorizationReceipt(args);
    const { receipt: hybridPath, hybrid_proof } = await assembleAuthorizationReceiptHybrid({
      ...args, hybridSignSet,
    });
    assert.equal(
      independentCanonicalize(hybridPath),
      independentCanonicalize(classical),
      'configuring a hybrid signer must not change one byte of the v1 receipt',
    );
    assert.ok(hybrid_proof, 'the hybrid proof is returned SEPARATELY, never folded into the receipt');
  } finally {
    crypto.randomBytes = realRandomBytes;
  }
});

test('REGRESSION: the receipt carries exactly the v1 member set, with nothing hybrid leaked in', async () => {
  const { receipt } = await assembleAuthorizationReceiptHybrid({ ...(await issuanceArgs()), hybridSignSet });
  assert.deepEqual(Object.keys(receipt).sort(),
    ['action', 'action_hash', 'consumption', 'contexts', 'log_proof', 'receipt_id', 'signoffs']);
  assert.deepEqual(Object.keys(receipt.log_proof).sort(),
    ['alg', 'checkpoint', 'inclusion_path', 'leaf_hash', 'leaf_index']);
  assert.deepEqual(Object.keys(receipt.log_proof.checkpoint).sort(),
    ['log_key_id', 'log_signature', 'merkle_alg', 'root_hash', 'tree_size']);
  assert.equal(receipt.log_proof.checkpoint.log_signature.length > 0, true);
});

test('REGRESSION: the v1 log signature verifies over INDEPENDENTLY recomputed bytes', async () => {
  const { receipt } = await assembleAuthorizationReceiptHybrid({ ...(await issuanceArgs()), hybridSignSet });
  const { log_signature, ...signedCheckpoint } = receipt.log_proof.checkpoint;

  // The v1 signing input, rebuilt here: Ed25519 over SHA-256 of the canonical
  // checkpoint WITHOUT log_signature.
  const digest = crypto.createHash('sha256')
    .update(independentCanonicalize(signedCheckpoint), 'utf8').digest();
  assert.equal(
    crypto.verify(null, digest, log.publicKey, Buffer.from(log_signature, 'base64url')),
    true,
    'the v1 checkpoint signing input must be unchanged',
  );
});

test('REGRESSION: the EP-MERKLE-v2 leaf is INDEPENDENTLY recomputable from the receipt', async () => {
  const { receipt } = await assembleAuthorizationReceiptHybrid({ ...(await issuanceArgs()), hybridSignSet });
  const { log_proof, ...withoutLogProof } = receipt;
  assert.equal(
    `sha256:${independentLeafV2(independentCanonicalize(withoutLogProof))}`,
    log_proof.leaf_hash,
    'the v1 leaf definition must be unchanged',
  );
  assert.equal(log_proof.alg, 'EP-MERKLE-v2');
  assert.equal(receipt.action_hash, actionHash(ACTION));
});

// ===========================================================================
// EP-LOG-CHECKPOINT-HYBRID-v1
// ===========================================================================

test('the issuer and the verifier build byte-identical checkpoint signed material', async () => {
  const { receipt } = await assembleAuthorizationReceiptHybrid({ ...(await issuanceArgs()), hybridSignSet });
  const mine = logCheckpointHybridSignedBytes(receipt.log_proof.checkpoint);
  const theirs = verifierCheckpointBytes(receipt.log_proof.checkpoint);
  assert.ok(mine.equals(theirs));
  // And the SHAPE, so a change that breaks both together still trips a test.
  const { log_signature, ...signedCheckpoint } = receipt.log_proof.checkpoint;
  assert.equal(mine.toString('utf8'), independentCanonicalize({
    '@version': LOG_CHECKPOINT_HYBRID_PROFILE,
    checkpoint: signedCheckpoint,
    required_algorithms: ['Ed25519', 'ML-DSA-65'],
  }));
});

test('the issued proof verifies against the receipt the issuer emitted', async () => {
  const { receipt, hybrid_proof } = await assembleAuthorizationReceiptHybrid({
    ...(await issuanceArgs()), hybridSignSet,
  });
  assert.equal(hybrid_proof['@version'], LOG_CHECKPOINT_HYBRID_PROFILE);
  assert.deepEqual(hybrid_proof.profile.required_algorithms, ['Ed25519', 'ML-DSA-65']);
  assert.deepEqual(hybrid_proof.signatures.map((s) => s.alg), ['Ed25519', 'ML-DSA-65']);
  assert.equal(hybrid_proof.checkpoint.log_signature, undefined,
    'the classical signature is never inside the material it signs');

  const result = await verifyLogCheckpointHybridProof(receipt.log_proof.checkpoint, hybrid_proof, KEYS);
  assert.equal(result.verified, true, `expected verified, got ${result.reason}`);
});

test('the proof does NOT speak for a different receipt from the same log', async () => {
  const a = await assembleAuthorizationReceiptHybrid({ ...(await issuanceArgs()), hybridSignSet });
  const b = await assembleAuthorizationReceiptHybrid({
    ...(await issuanceArgs()),
    receiptId: 'ep:receipt:other',
    hybridSignSet,
  });
  const result = await verifyLogCheckpointHybridProof(b.receipt.log_proof.checkpoint, a.hybrid_proof, KEYS);
  assert.equal(result.verified, false);
  assert.equal(result.reason, 'checkpoint_mismatch');
});

test('ISSUANCE REFUSES rather than emit a half-hybrid proof', async () => {
  const args = await issuanceArgs();
  const cases = [
    // No PQ leg returned at all.
    async () => [{ alg: 'Ed25519', sig: 'AAAA' }],
    // A backend that throws, exactly as signAgile does with no ML-DSA present.
    async () => { throw new Error('pq_backend_unavailable'); },
    // A signer that returns something that is not a set.
    async () => null,
  ];
  for (const badSignSet of cases) {
    await assert.rejects(() => assembleAuthorizationReceiptHybrid({ ...args, hybridSignSet: badSignSet }));
  }
  await assert.rejects(() => assembleAuthorizationReceiptHybrid({ ...args }),
    /hybridSignSet is required/);
});

test('ISSUANCE REFUSES a checkpoint outside the profile', async () => {
  // A legacy EP-MERKLE-v1 checkpoint has no merkle_alg and must not enter here.
  await assert.rejects(
    () => createLogCheckpointHybridProof({
      checkpoint: { tree_size: 1, root_hash: `sha256:${'a'.repeat(64)}`, log_key_id: 'ep:log:x#1' },
      signSet: hybridSignSet,
    }),
    /missing "merkle_alg"/,
  );
  // A smuggled extra member must not be silently dropped from signed material.
  await assert.rejects(
    () => createLogCheckpointHybridProof({
      checkpoint: {
        tree_size: 1,
        root_hash: `sha256:${'a'.repeat(64)}`,
        log_key_id: 'ep:log:x#1',
        merkle_alg: 'EP-MERKLE-v2',
        note: 'trust me',
      },
      signSet: hybridSignSet,
    }),
    /unexpected checkpoint member "note"/,
  );
});

test('logCheckpointSignedFields drops only log_signature, and requires every other member', () => {
  const fields = logCheckpointSignedFields({
    tree_size: 3,
    root_hash: `sha256:${'b'.repeat(64)}`,
    log_key_id: 'ep:log:x#1',
    merkle_alg: 'EP-MERKLE-v2',
    log_signature: 'AAAA',
  });
  assert.deepEqual(Object.keys(fields).sort(), ['log_key_id', 'merkle_alg', 'root_hash', 'tree_size']);
  assert.throws(() => logCheckpointSignedFields({ tree_size: 3, merkle_alg: 'EP-MERKLE-v2' }));
});

test('the registered algorithm set is fixed and ordered', () => {
  assert.deepEqual([...LOG_CHECKPOINT_HYBRID_REQUIRED_ALGORITHMS], ['Ed25519', 'ML-DSA-65']);
  assert.throws(() => logCheckpointHybridSignedBytes({
    tree_size: 1, root_hash: `sha256:${'a'.repeat(64)}`, log_key_id: 'x', merkle_alg: 'EP-MERKLE-v2',
  }, ['Ed25519']));
});
