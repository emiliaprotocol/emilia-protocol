/**
 * Tests for the EXPERIMENTAL third-party CONSUMPTION proof verifier
 * (sparse-Merkle-over-nonce, EP-SMT-CONSUME-v1).
 *
 * These build a real sparse consumption tree, produce a genuine ABSENT -> PRESENT
 * transition of a nonce between two append-only-linked heads, and assert ACCEPT;
 * plus reject vectors: present-at-h1, absent-at-h2, non-append-only h1->h2, and
 * fail-closed input validation. The consistency (h1->h2) leg reuses the dense
 * RFC 6962 prover from consistency.js so h1/h2 are a real append-only pair.
 *
 * Run:  node --test consumption-proof.test.js
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import {
  verifyConsumptionProof,
  ReferenceConsumptionTree,
  CONSUMPTION_PROFILE,
  CONSUMPTION_LEAF_DOMAIN,
  SMT_DEPTH,
} from './consumption-proof.js';
import { buildConsistencyProof, merkleRoot } from './consistency.js';

// Dense-log leaf hashes (0x00 || content) — matches leafHashV2/consistency.js.
function denseLeaf(content) {
  return crypto
    .createHash('sha256')
    .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(content, 'utf8')]))
    .digest('hex');
}
function denseLeaves(n) {
  return Array.from({ length: n }, (_, i) => denseLeaf(`log-entry-${i}`));
}

// Build a full bundle for a real absent->present transition of `nonce`.
// h1 witnesses the SMT root BEFORE the nonce is consumed (nonce absent);
// h2 witnesses the SMT root AFTER (nonce present). The dense checkpoints h1/h2
// are a genuine append-only pair (m < n) so the consistency leg verifies.
function makeBundle({ nonce = 'nonce-A', otherNonces = ['nonce-B', 'nonce-C'], m = 3, n = 6 } = {}) {
  // SMT before: contains only the OTHER nonces, not `nonce`.
  const treeBefore = new ReferenceConsumptionTree();
  for (const o of otherNonces) treeBefore.insert(o);
  const niProof = treeBefore.prove(nonce); // absent

  // SMT after: same tree plus `nonce` consumed.
  const treeAfter = new ReferenceConsumptionTree();
  for (const o of otherNonces) treeAfter.insert(o);
  treeAfter.insert(nonce);
  const incProof = treeAfter.prove(nonce); // present

  // Dense append-only log: h1 at size m, h2 at size n (m < n), real consistency.
  const logLeaves = denseLeaves(n);
  const h1Root = merkleRoot(logLeaves.slice(0, m));
  const h2Root = merkleRoot(logLeaves);
  const consistency = buildConsistencyProof(m, n, logLeaves);

  return {
    nonce,
    non_inclusion_proof: niProof,
    inclusion_proof: incProof,
    consistency_proof: consistency,
    checkpoints: {
      h1: { tree_size: m, root_hash: h1Root },
      h2: { tree_size: n, root_hash: h2Root },
    },
    // stash for reject-vector reuse
    _treeBefore: treeBefore,
    _treeAfter: treeAfter,
    _logLeaves: logLeaves,
    _m: m,
    _n: n,
  };
}

test('exports and constants', () => {
  assert.equal(typeof verifyConsumptionProof, 'function');
  assert.equal(typeof ReferenceConsumptionTree, 'function');
  assert.equal(CONSUMPTION_PROFILE, 'EP-SMT-CONSUME-v1');
  assert.equal(CONSUMPTION_LEAF_DOMAIN, 'EP-SMT-CONSUME-v1');
  assert.equal(SMT_DEPTH, 32);
});

test('reference emitter is reachable via the declared package subpath export', async () => {
  // package.json exports "./consumption-proof.js", so a third party can import
  // the reference issuer-side emitter (not only the verifier) by package name.
  const viaSubpath = await import('@emilia-protocol/verify/consumption-proof.js');
  assert.equal(typeof viaSubpath.ReferenceConsumptionTree, 'function');
  assert.equal(viaSubpath.ReferenceConsumptionTree, ReferenceConsumptionTree);
  assert.equal(typeof viaSubpath.verifyConsumptionProof, 'function');
  // The emitter really produces a bundle the verifier accepts: emit, then verify.
  const before = new viaSubpath.ReferenceConsumptionTree();
  before.insert('other');
  const ni = before.prove('subpath-nonce'); // absent
  const after = new viaSubpath.ReferenceConsumptionTree();
  after.insert('other');
  after.insert('subpath-nonce');
  const inc = after.prove('subpath-nonce'); // present
  const leaves = denseLeaves(6);
  const bundle = {
    nonce: 'subpath-nonce',
    non_inclusion_proof: ni,
    inclusion_proof: inc,
    consistency_proof: buildConsistencyProof(3, 6, leaves),
    checkpoints: {
      h1: { tree_size: 3, root_hash: merkleRoot(leaves.slice(0, 3)) },
      h2: { tree_size: 6, root_hash: merkleRoot(leaves) },
    },
  };
  assert.equal(viaSubpath.verifyConsumptionProof(bundle).valid, true);
});

test('ACCEPT: genuine absent->present transition between append-only heads', () => {
  const b = makeBundle();
  const res = verifyConsumptionProof(b);
  assert.equal(res.valid, true, JSON.stringify(res));
  assert.deepEqual(res.checks, { non_inclusion: true, inclusion: true, consistency: true });
  assert.equal(res.reason, null);
});

test('ACCEPT: accepts sha256: prefixes on roots and sibling/value hashes', () => {
  const b = makeBundle();
  const pfx = (h) => `sha256:${h}`;
  b.non_inclusion_proof.root = pfx(b.non_inclusion_proof.root);
  b.non_inclusion_proof.siblings = b.non_inclusion_proof.siblings.map(pfx);
  b.inclusion_proof.root = pfx(b.inclusion_proof.root);
  b.inclusion_proof.siblings = b.inclusion_proof.siblings.map(pfx);
  b.inclusion_proof.value = pfx(b.inclusion_proof.value);
  b.checkpoints.h1.root_hash = pfx(b.checkpoints.h1.root_hash);
  b.checkpoints.h2.root_hash = pfx(b.checkpoints.h2.root_hash);
  b.consistency_proof = b.consistency_proof.map(pfx);
  assert.equal(verifyConsumptionProof(b).valid, true);
});

test('ACCEPT: works across a range of other-nonce populations and head sizes', () => {
  for (const [m, n] of [[1, 2], [2, 5], [4, 9], [5, 8], [7, 16]]) {
    const others = Array.from({ length: 5 }, (_, i) => `other-${m}-${n}-${i}`);
    const res = verifyConsumptionProof(makeBundle({ otherNonces: others, m, n }));
    assert.equal(res.valid, true, `m=${m} n=${n}: ${JSON.stringify(res)}`);
  }
});

// ── REJECT: present-at-h1 (nonce was ALREADY consumed at the earlier head) ──
test('REJECT: present-at-h1 (double-spend attempt)', () => {
  const b = makeBundle();
  // Replace the non-inclusion proof with an INCLUSION proof at h1 — the operator
  // trying to claim absence while the nonce was actually already present.
  const treeAlreadyHas = new ReferenceConsumptionTree();
  treeAlreadyHas.insert(b.nonce);
  const presentAtH1 = treeAlreadyHas.prove(b.nonce);
  b.non_inclusion_proof = presentAtH1; // present:true where absent is required
  const res = verifyConsumptionProof(b);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'non_inclusion_proof_must_assert_absent');
  assert.equal(res.checks.non_inclusion, false);
});

test('REJECT: absent-claim at h1 that does not reconstruct its root', () => {
  const b = makeBundle();
  // Keep present:false but corrupt a sibling so the fold misses the h1 root.
  b.non_inclusion_proof.siblings[SMT_DEPTH - 1] = 'ff'.repeat(32);
  const res = verifyConsumptionProof(b);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'non_inclusion_does_not_reconstruct_root');
});

// ── REJECT: absent-at-h2 (the nonce was never actually consumed) ────────────
test('REJECT: absent-at-h2 (inclusion proof asserts absence)', () => {
  const b = makeBundle();
  // Swap the inclusion proof for a NON-inclusion proof at h2.
  const treeAfterButAbsent = new ReferenceConsumptionTree();
  treeAfterButAbsent.insert('nonce-B');
  treeAfterButAbsent.insert('nonce-C');
  const absentAtH2 = treeAfterButAbsent.prove(b.nonce); // present:false
  b.inclusion_proof = absentAtH2;
  const res = verifyConsumptionProof(b);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'inclusion_proof_must_assert_present');
  assert.equal(res.checks.inclusion, false);
});

test('REJECT: present-claim at h2 that does not reconstruct its root', () => {
  const b = makeBundle();
  b.inclusion_proof.siblings[0] = 'ab'.repeat(32);
  const res = verifyConsumptionProof(b);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'inclusion_does_not_reconstruct_root');
});

test('REJECT: present-claim at h2 with a tampered value', () => {
  const b = makeBundle();
  // Value no longer matches the leaf that was folded into h2's root.
  b.inclusion_proof.value = crypto.createHash('sha256').update('forged').digest('hex');
  const res = verifyConsumptionProof(b);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'inclusion_does_not_reconstruct_root');
});

// ── REJECT: non-append-only h1 -> h2 ────────────────────────────────────────
test('REJECT: non-append-only h1->h2 (rewritten prefix)', () => {
  const b = makeBundle();
  // Fork the dense log's prefix so h1 is NOT a prefix of h2.
  const forked = [...b._logLeaves];
  forked[0] = denseLeaf('rewritten-log-entry-0');
  const forkedH1 = merkleRoot(forked.slice(0, b._m));
  b.checkpoints.h1.root_hash = forkedH1; // consistency proof no longer bridges
  const res = verifyConsumptionProof(b);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'consistency_proof_not_append_only');
  assert.equal(res.checks.consistency, false);
});

test('REJECT: tampered consistency proof node', () => {
  const b = makeBundle();
  b.consistency_proof[0] = denseLeaf('not-the-node');
  const res = verifyConsumptionProof(b);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'consistency_proof_not_append_only');
});

test('REJECT: h1 not strictly before h2 (equal heads cannot witness a transition)', () => {
  const b = makeBundle({ m: 4, n: 4 }); // equal sizes -> empty consistency proof
  // makeBundle with m===n produces equal roots too; force distinct-but-equal-size.
  b.checkpoints.h1 = { tree_size: 5, root_hash: b.checkpoints.h2.root_hash };
  b.checkpoints.h2 = { tree_size: 5, root_hash: b.checkpoints.h2.root_hash };
  b.consistency_proof = [];
  const res = verifyConsumptionProof(b);
  assert.equal(res.valid, false);
  assert.equal(res.reason, 'checkpoint_h1_not_before_h2');
});

test('REJECT: identical SMT roots (no transition occurred)', () => {
  const b = makeBundle();
  // Force both SMT sub-proofs to carry the same root; the flags still say
  // absent@h1 / present@h2 but the roots did not change.
  b.inclusion_proof.root = b.non_inclusion_proof.root;
  const res = verifyConsumptionProof(b);
  assert.equal(res.valid, false);
  // Either the inclusion no longer reconstructs OR the root-unchanged guard trips;
  // both are fail-closed. Assert it did not pass.
  assert.ok(
    res.reason === 'smt_root_unchanged_no_transition' || res.reason === 'inclusion_does_not_reconstruct_root',
    res.reason,
  );
});

// ── Fail-closed input validation ────────────────────────────────────────────
test('fail-closed: bundle / nonce / sub-proof shape', () => {
  assert.equal(verifyConsumptionProof(undefined).reason, 'bundle_missing');
  assert.equal(verifyConsumptionProof(null).reason, 'bundle_missing');
  assert.equal(verifyConsumptionProof('x').reason, 'bundle_missing');
  assert.equal(verifyConsumptionProof({}).reason, 'nonce_missing');
  assert.equal(verifyConsumptionProof({ nonce: '' }).reason, 'nonce_missing');
  assert.equal(verifyConsumptionProof({ nonce: 'n' }).reason, 'non_inclusion_proof_missing');

  const b = makeBundle();

  // present flag must be an explicit boolean, never inferred.
  const b1 = makeBundle();
  delete b1.non_inclusion_proof.present;
  assert.equal(verifyConsumptionProof(b1).reason, 'non_inclusion_proof_must_assert_absent');

  // wrong siblings length is refused.
  const b2 = makeBundle();
  b2.non_inclusion_proof.siblings = b2.non_inclusion_proof.siblings.slice(0, 5);
  assert.equal(verifyConsumptionProof(b2).reason, 'non_inclusion_siblings_wrong_length');

  // malformed SMT root.
  const b3 = makeBundle();
  b3.non_inclusion_proof.root = 'not-hex';
  assert.equal(verifyConsumptionProof(b3).reason, 'non_inclusion_root_malformed');

  // present inclusion missing value.
  const b4 = makeBundle();
  delete b4.inclusion_proof.value;
  assert.equal(verifyConsumptionProof(b4).reason, 'inclusion_present_value_malformed');

  // missing checkpoints.
  const b5 = makeBundle();
  delete b5.checkpoints;
  assert.equal(verifyConsumptionProof(b5).reason, 'checkpoints_missing');

  // malformed checkpoint h1.
  const b6 = makeBundle();
  b6.checkpoints.h1.tree_size = 0;
  assert.equal(verifyConsumptionProof(b6).reason, 'checkpoint_h1_malformed');

  // missing consistency proof array.
  const b7 = makeBundle();
  b7.consistency_proof = 'nope';
  assert.equal(verifyConsumptionProof(b7).reason, 'consistency_proof_missing');

  // sanity: the untouched base bundle still verifies.
  assert.equal(verifyConsumptionProof(b).valid, true);
});

// ── Reference tree self-consistency ─────────────────────────────────────────
test('reference tree: inclusion and non-inclusion proofs reconstruct the root', () => {
  const t = new ReferenceConsumptionTree();
  t.insert('alpha');
  t.insert('beta');
  const root = t.root();
  const incl = t.prove('alpha');
  const nonIncl = t.prove('gamma');
  assert.equal(incl.root, root);
  assert.equal(nonIncl.root, root);
  assert.equal(incl.present, true);
  assert.equal(nonIncl.present, false);
  assert.equal(incl.siblings.length, SMT_DEPTH);
});
