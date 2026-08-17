// SPDX-License-Identifier: Apache-2.0
//
// EP-EVIDENCE-RECORD-v1 BASE-record algorithm agility.
//
// The re-attestation chain has been agile since it landed; the base record's
// protection (a chain of EP-TIME-ATTESTATION-v1 renewals) was Ed25519-only.
// verifyEvidenceRecordAgile is the opt-in sibling. This suite proves three
// things and nothing looser:
//
//   1. v1 REGRESSION. A record whose attestations are Ed25519-signed gets the
//      same verdict from verifyEvidenceRecord and verifyEvidenceRecordAgile,
//      accept and refuse alike.
//   2. ML-DSA-65 base records verify under a pinned, algorithm-tagged key, over
//      the SAME recomputed bytes the Ed25519 path checks.
//   3. NO ONE-LEG ACCEPTANCE of a set-shaped proof. A proof carrying a
//      signature ARRAY is checked under hybrid_all against the full registry by
//      default: one valid Ed25519 leg inside a set is a refusal, not a pass.
//
// Real ML-DSA-65 throughout (@noble/post-quantum); the suite fails loudly if
// that backend is missing rather than skipping, because an agility test that
// never ran an ML-DSA verification proves nothing about agility.
//
// Run: node --test packages/verify/evidence-record-base-agility.test.js
//  or: npx tsx --test packages/verify/evidence-record-base-agility.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

import { canonicalize } from './index.js';
import { verifyEvidenceRecord, verifyEvidenceRecordAgile, EVIDENCE_RECORD_VERSION } from './dist/evidence-record.js';
import { TIME_ATTESTATION_VERSION } from './dist/time-attestation.js';
import { signAgile } from './dist/pq-signature-agility.js';

const TSA = 'ep:tsa:roughtime-1';
const TIME = '2026-06-20T12:00:00.000Z';
const PROTECTED = Buffer.from('{"@version":"EP-RECEIPT-v1","payload":{"action":"pay"}}', 'utf8');
const PROTECTED_HASH = `sha256:${crypto.createHash('sha256').update(PROTECTED).digest('hex')}`;

assert.equal(typeof ml_dsa65?.keygen, 'function', 'the real ML-DSA-65 backend must be present; a skipped agility suite proves nothing');

const ed = crypto.generateKeyPairSync('ed25519');
const edPublicB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
const pq = ml_dsa65.keygen(new Uint8Array(32).fill(3));

/** The bytes a TSA proof is bound to, rebuilt here independently. */
function signedBytes({ hashed, time }: { hashed: string; time: string }) {
  return Buffer.from(
    canonicalize({ '@version': TIME_ATTESTATION_VERSION, hashed, time, ts_authority_id: TSA }),
    'utf8',
  );
}

function ed25519Attestation({ hashed, time = TIME }: { hashed: string; time?: string }) {
  return {
    '@version': TIME_ATTESTATION_VERSION,
    ts_authority_id: TSA,
    hashed,
    time,
    proof: {
      algorithm: 'Ed25519',
      ts_key_id: 'tk1',
      public_key: edPublicB64u,
      signature_b64u: crypto.sign(null, signedBytes({ hashed, time }), ed.privateKey).toString('base64url'),
    },
  };
}

async function mldsaAttestation({ hashed, time = TIME }: { hashed: string; time?: string }) {
  const sig = await signAgile(new Uint8Array(signedBytes({ hashed, time })), {
    alg: 'ML-DSA-65', private_key: pq.secretKey, key_id: 'tk-pq1',
  });
  return {
    '@version': TIME_ATTESTATION_VERSION,
    ts_authority_id: TSA,
    hashed,
    time,
    proof: { algorithm: 'ML-DSA-65', ts_key_id: 'tk-pq1', signature_b64u: sig.sig },
  };
}

/** A proof carrying a signature SET rather than one signature. */
async function setShapedAttestation({ hashed, time = TIME, algs }: { hashed: string; time?: string; algs: string[] }) {
  const bytes = new Uint8Array(signedBytes({ hashed, time }));
  const signatures = [];
  for (const alg of algs) {
    signatures.push(alg === 'Ed25519'
      ? { alg: 'Ed25519', sig: crypto.sign(null, Buffer.from(bytes), ed.privateKey).toString('base64url'), key_id: 'tk1' }
      : await signAgile(bytes, { alg: 'ML-DSA-65', private_key: pq.secretKey, key_id: 'tk-pq1' }));
  }
  return {
    '@version': TIME_ATTESTATION_VERSION,
    ts_authority_id: TSA,
    hashed,
    time,
    proof: { algorithm: 'EP-SIG-AGILITY-v1', signatures },
  };
}

const record = (attestations: any[]) => ({
  '@version': EVIDENCE_RECORD_VERSION,
  protected_hash: PROTECTED_HASH,
  archive_timestamps: attestations.map((time_attestation) => ({ time_attestation })),
});

const V1_PIN = { tsaKeys: { [TSA]: { public_key: edPublicB64u } } };
const PQ_PIN = { tsaKeys: { [TSA]: { alg: 'ML-DSA-65', public_key: Buffer.from(pq.publicKey).toString('base64url') } } };
const SET_PIN = {
  tsaKeys: {
    [TSA]: {
      keys: [
        { alg: 'Ed25519', public_key: edPublicB64u },
        { alg: 'ML-DSA-65', public_key: Buffer.from(pq.publicKey).toString('base64url') },
      ],
    },
  },
};

// --- 1. v1 regression -------------------------------------------------------

test('an Ed25519 v1 record gets the same verdict from both entry points', async () => {
  const rec = record([ed25519Attestation({ hashed: PROTECTED_HASH })]);
  const opts = { ...V1_PIN, protectedHash: PROTECTED_HASH };

  const v1 = verifyEvidenceRecord(rec, opts);
  const agile = await verifyEvidenceRecordAgile(rec, opts);
  assert.equal(v1.valid, true, JSON.stringify(v1.errors));
  assert.equal(agile.valid, true, JSON.stringify(agile.errors));
  assert.deepEqual(agile.checks, v1.checks);
  assert.deepEqual(agile.errors, v1.errors);
  assert.equal(agile.protected_since, v1.protected_since);
  assert.equal(agile.last_renewed, v1.last_renewed);
});

test('v1 refusals are preserved verbatim by the agile entry point', async () => {
  const good = record([ed25519Attestation({ hashed: PROTECTED_HASH })]);
  const cases: Array<[string, any, any]> = [
    ['unpinned TSA', good, { protectedHash: PROTECTED_HASH }],
    ['wrong protected artifact', good, { ...V1_PIN, protectedHash: `sha256:${'9'.repeat(64)}` }],
    ['chain does not cover the protected hash', record([ed25519Attestation({ hashed: `sha256:${'8'.repeat(64)}` })]), V1_PIN],
    ['no archive timestamps', record([]), V1_PIN],
    ['wrong version', { ...good, '@version': 'EP-EVIDENCE-RECORD-v2' }, V1_PIN],
  ];
  for (const [label, rec, opts] of cases) {
    const v1 = verifyEvidenceRecord(rec as any, opts);
    const agile = await verifyEvidenceRecordAgile(rec as any, opts);
    assert.equal(v1.valid, false, label);
    assert.equal(agile.valid, false, label);
    assert.deepEqual(agile.checks, v1.checks, label);
    assert.deepEqual(agile.errors, v1.errors, label);
  }
});

test('a tampered v1 attestation still fails the signature check under the agile path', async () => {
  const att = ed25519Attestation({ hashed: PROTECTED_HASH });
  att.time = '2030-01-01T00:00:00.000Z';
  const rec = record([att]);
  assert.equal(verifyEvidenceRecord(rec, V1_PIN).valid, false);
  const agile = await verifyEvidenceRecordAgile(rec, V1_PIN);
  assert.equal(agile.valid, false);
  assert.equal(agile.checks.all_timestamps_valid, false);
});

// --- 2. ML-DSA-65 base records ---------------------------------------------

test('an ML-DSA-65 base record verifies under a pinned, algorithm-tagged key', async () => {
  const rec = record([await mldsaAttestation({ hashed: PROTECTED_HASH })]);

  // The v1 entry point does not pretend to understand it.
  assert.equal(verifyEvidenceRecord(rec, V1_PIN).valid, false);

  const agile = await verifyEvidenceRecordAgile(rec, { ...PQ_PIN, protectedHash: PROTECTED_HASH });
  assert.equal(agile.valid, true, JSON.stringify(agile.errors));
  assert.equal(agile.checks.all_timestamps_valid, true);
  assert.equal(agile.protected_since, TIME);
});

test('a mixed chain renews an Ed25519 anchor under ML-DSA-65', async () => {
  // This is the case the whole extension exists for: evidence anchored under
  // the old algorithm, renewed under the new one before the old one weakens.
  const first = ed25519Attestation({ hashed: PROTECTED_HASH });
  const renewalHash = `sha256:${crypto.createHash('sha256').update(Buffer.from(canonicalize(first), 'utf8')).digest('hex')}`;
  const second = await mldsaAttestation({ hashed: renewalHash, time: '2027-06-20T12:00:00.000Z' });
  const rec = record([first, second]);

  // One authority, both keys pinned: `public_key` serves the v1 leg,
  // `keys` names the algorithm-tagged key for the agile leg.
  const mixedPin = {
    tsaKeys: {
      [TSA]: {
        public_key: edPublicB64u,
        keys: [{ alg: 'ML-DSA-65', public_key: Buffer.from(pq.publicKey).toString('base64url') }],
      },
    },
    protectedHash: PROTECTED_HASH,
  };
  const agile = await verifyEvidenceRecordAgile(rec, mixedPin);
  assert.equal(agile.valid, true, JSON.stringify(agile.errors));
  assert.equal(agile.protected_since, TIME);
  assert.equal(agile.last_renewed, '2027-06-20T12:00:00.000Z');

  // The v1 entry point refuses the same chain: it cannot check the ML-DSA leg
  // and does not pretend the Ed25519 one was enough.
  assert.equal(verifyEvidenceRecord(rec, mixedPin).valid, false);

  // Pinning an Ed25519 SPKI key AS the ML-DSA key refuses: a 1952-byte pin is
  // required, and a key of the wrong shape is never verified under it.
  const wrongShape = await verifyEvidenceRecordAgile(rec, {
    tsaKeys: { [TSA]: { public_key: edPublicB64u, keys: [{ alg: 'ML-DSA-65', public_key: edPublicB64u }] } },
    protectedHash: PROTECTED_HASH,
  });
  assert.equal(wrongShape.valid, false);
});

test('the ML-DSA leg fails closed on a wrong key, a tampered time, and a missing backend', async () => {
  const rec = record([await mldsaAttestation({ hashed: PROTECTED_HASH })]);

  const other = ml_dsa65.keygen(new Uint8Array(32).fill(4));
  const wrongKey = await verifyEvidenceRecordAgile(rec, {
    tsaKeys: { [TSA]: { alg: 'ML-DSA-65', public_key: Buffer.from(other.publicKey).toString('base64url') } },
  });
  assert.equal(wrongKey.valid, false);
  assert.equal(wrongKey.checks.all_timestamps_valid, false);

  const unpinned = await verifyEvidenceRecordAgile(rec, {});
  assert.equal(unpinned.valid, false);

  // A pin tagged for the wrong algorithm never verifies the presented one.
  const wrongAlgTag = await verifyEvidenceRecordAgile(rec, {
    tsaKeys: { [TSA]: { alg: 'Ed25519', public_key: Buffer.from(pq.publicKey).toString('base64url') } },
  });
  assert.equal(wrongAlgTag.valid, false);

  const tampered = record([await mldsaAttestation({ hashed: PROTECTED_HASH })]);
  (tampered.archive_timestamps[0].time_attestation as any).time = '2030-01-01T00:00:00.000Z';
  assert.equal((await verifyEvidenceRecordAgile(tampered, PQ_PIN)).valid, false);

  // No ML-DSA backend is a refusal, never a skipped check.
  const noBackend = await verifyEvidenceRecordAgile(rec, { ...PQ_PIN, mldsaBackendLoader: () => null });
  assert.equal(noBackend.valid, false);
  assert.equal(noBackend.checks.all_timestamps_valid, false);
});

// --- 3. never one-leg acceptance of anything set-shaped ---------------------

test('a set-shaped proof carrying BOTH legs verifies', async () => {
  const rec = record([await setShapedAttestation({ hashed: PROTECTED_HASH, algs: ['Ed25519', 'ML-DSA-65'] })]);
  const agile = await verifyEvidenceRecordAgile(rec, { ...SET_PIN, protectedHash: PROTECTED_HASH });
  assert.equal(agile.valid, true, JSON.stringify(agile.errors));
});

test('a set-shaped proof is NEVER accepted on one leg', async () => {
  for (const algs of [['Ed25519'], ['ML-DSA-65']]) {
    const rec = record([await setShapedAttestation({ hashed: PROTECTED_HASH, algs })]);
    const agile = await verifyEvidenceRecordAgile(rec, { ...SET_PIN, protectedHash: PROTECTED_HASH });
    assert.equal(agile.valid, false, `a set-shaped proof with only ${algs.join(',')} must refuse`);
    assert.equal(agile.checks.all_timestamps_valid, false);
  }
});

test('one broken leg inside a valid-looking set refuses the whole attestation', async () => {
  const rec = record([await setShapedAttestation({ hashed: PROTECTED_HASH, algs: ['Ed25519', 'ML-DSA-65'] })]);
  const sigs = (rec.archive_timestamps[0].time_attestation as any).proof.signatures;
  const pqLeg = sigs.find((s: any) => s.alg === 'ML-DSA-65');
  pqLeg.sig = `${pqLeg.sig.slice(0, -1)}${pqLeg.sig.endsWith('A') ? 'B' : 'A'}`;
  const agile = await verifyEvidenceRecordAgile(rec, { ...SET_PIN, protectedHash: PROTECTED_HASH });
  assert.equal(agile.valid, false);
});

test('a relying party may narrow the required set, and narrowing is its explicit decision', async () => {
  const rec = record([await setShapedAttestation({ hashed: PROTECTED_HASH, algs: ['ML-DSA-65'] })]);

  // Default: the FULL registry is required, so this refuses.
  assert.equal((await verifyEvidenceRecordAgile(rec, SET_PIN)).valid, false);

  // Narrowed deliberately by the relying party: accepted, and the narrowing is
  // written down at the call site rather than inferred from what was presented.
  const narrowed = await verifyEvidenceRecordAgile(rec, {
    ...SET_PIN, protectedHash: PROTECTED_HASH, requiredAlgorithms: ['ML-DSA-65'],
  });
  assert.equal(narrowed.valid, true, JSON.stringify(narrowed.errors));
});

test('a set-shaped proof with no pinned key set refuses', async () => {
  const rec = record([await setShapedAttestation({ hashed: PROTECTED_HASH, algs: ['Ed25519', 'ML-DSA-65'] })]);
  assert.equal((await verifyEvidenceRecordAgile(rec, PQ_PIN)).valid, false);
  assert.equal((await verifyEvidenceRecordAgile(rec, V1_PIN)).valid, false);
  assert.equal((await verifyEvidenceRecordAgile(rec, {})).valid, false);
});
