// Generated from witness.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Tests for the EP-WITNESS-v1 cosignature verifier (witness.js).
 *
 * A witness re-signs the SAME committed checkpoint bytes the log signed, under a
 * distinct domain tag, so that when multiple independent witnesses cosign
 * divergent heads a split view becomes detectable. These tests prove:
 *   - a genuine cosign verifies;
 *   - a wrong (unpinned) key refuses;
 *   - a tampered checkpoint refuses (signature is over different bytes);
 *   - a cosignature echoed for a DIFFERENT head refuses;
 *   - the domain tag keeps a witness cosignature and a log signature disjoint;
 *   - the k-of-n quorum helper accepts k DISTINCT pinned witnesses and refuses
 *     k-1, duplicate witness_ids, or unpinned witnesses.
 *
 * Run:  node --test witness.test.js
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { canonicalize } from './index.js';
import { verifyWitnessCosignature, requireWitnessQuorum, witnessSigningDigest, WITNESS_DOMAIN_TAG, WITNESS_VERSION, } from './witness.js';
// ── helpers ──────────────────────────────────────────────────────────────────
function newEd25519() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    return {
        privateKey,
        pub: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    };
}
// A representative log checkpoint (same shape verifyTrustReceipt signs/checks).
function makeCheckpoint(overrides = {}) {
    return {
        tree_size: 42,
        root_hash: `sha256:${'a1'.repeat(32)}`,
        log_key_id: 'ep:log:test#1',
        merkle_alg: 'EP-MERKLE-v2',
        ...overrides,
    };
}
// Produce a witness cosignature exactly as witness/server.mjs does.
function cosign(checkpoint, witnessId, keys, extra = {}) {
    const digest = witnessSigningDigest(checkpoint);
    const signature = crypto.sign(null, digest, keys.privateKey).toString('base64url');
    return {
        alg: WITNESS_VERSION,
        witness_id: witnessId,
        tree_size: checkpoint.tree_size,
        root_hash: checkpoint.root_hash,
        log_key_id: checkpoint.log_key_id,
        signature,
        ...extra,
    };
}
// ── single-cosignature verification ──────────────────────────────────────────
test('a genuine witness cosignature verifies', () => {
    const w = newEd25519();
    const cp = makeCheckpoint();
    const cosig = cosign(cp, 'witness-a', w);
    const r = verifyWitnessCosignature(cp, cosig, { witness_id: 'witness-a', public_key: w.pub });
    assert.equal(r.verified, true);
    assert.equal(r.witness_id, 'witness-a');
    assert.equal(r.reason, undefined);
});
test('a cosignature over the checkpoint WITH log_signature still verifies (bytes are the committed bytes)', () => {
    const w = newEd25519();
    const cp = makeCheckpoint();
    const cosig = cosign(cp, 'witness-a', w); // signed over committed bytes (no log_signature)
    // Present the checkpoint as it travels in a receipt: still carrying log_signature.
    const withLogSig = { ...cp, log_signature: 'b64u:deadbeef' };
    const r = verifyWitnessCosignature(withLogSig, cosig, { witness_id: 'witness-a', public_key: w.pub });
    assert.equal(r.verified, true, 'log_signature must be stripped before hashing');
});
test('wrong key refuses (cosignature made by a different key than pinned)', () => {
    const signer = newEd25519();
    const other = newEd25519();
    const cp = makeCheckpoint();
    const cosig = cosign(cp, 'witness-a', signer);
    const r = verifyWitnessCosignature(cp, cosig, { witness_id: 'witness-a', public_key: other.pub });
    assert.equal(r.verified, false);
    assert.match(r.reason, /does not verify/);
});
test('unpinned witness_id refuses (cosignature names a witness we do not trust)', () => {
    const w = newEd25519();
    const cp = makeCheckpoint();
    const cosig = cosign(cp, 'witness-stranger', w);
    const r = verifyWitnessCosignature(cp, cosig, { witness_id: 'witness-a', public_key: w.pub });
    assert.equal(r.verified, false);
    assert.match(r.reason, /unpinned witness refused/);
});
test('tampered checkpoint refuses (root_hash flipped after cosigning)', () => {
    const w = newEd25519();
    const cp = makeCheckpoint();
    const cosig = cosign(cp, 'witness-a', w);
    // Change the committed bytes: the digest now differs, so the signature fails.
    // Also drop the echoed root_hash so we exercise the crypto path, not the echo guard.
    const tampered = makeCheckpoint({ root_hash: `sha256:${'ff'.repeat(32)}` });
    const bareCosig = { ...cosig };
    delete bareCosig.root_hash;
    const r = verifyWitnessCosignature(tampered, bareCosig, { witness_id: 'witness-a', public_key: w.pub });
    assert.equal(r.verified, false);
    assert.match(r.reason, /does not verify over the checkpoint committed bytes/);
});
test('tampered tree_size refuses', () => {
    const w = newEd25519();
    const cp = makeCheckpoint();
    const cosig = cosign(cp, 'witness-a', w);
    const bareCosig = { ...cosig };
    delete bareCosig.tree_size; // avoid the echo guard so the crypto path runs
    const tampered = makeCheckpoint({ tree_size: 43 });
    const r = verifyWitnessCosignature(tampered, bareCosig, { witness_id: 'witness-a', public_key: w.pub });
    assert.equal(r.verified, false);
});
test('cosignature echoed for a DIFFERENT head refuses before crypto (tree_size mismatch)', () => {
    const w = newEd25519();
    const cp = makeCheckpoint({ tree_size: 42 });
    const cosig = cosign(cp, 'witness-a', w); // echoes tree_size 42
    const otherHead = makeCheckpoint({ tree_size: 100 });
    const r = verifyWitnessCosignature(otherHead, cosig, { witness_id: 'witness-a', public_key: w.pub });
    assert.equal(r.verified, false);
    assert.match(r.reason, /different head/);
});
test('cosignature echoed for a different log_key_id refuses', () => {
    const w = newEd25519();
    const cp = makeCheckpoint({ log_key_id: 'ep:log:test#1' });
    const cosig = cosign(cp, 'witness-a', w);
    const otherLog = makeCheckpoint({ log_key_id: 'ep:log:evil#9' });
    const r = verifyWitnessCosignature(otherLog, cosig, { witness_id: 'witness-a', public_key: w.pub });
    assert.equal(r.verified, false);
    assert.match(r.reason, /different log/);
});
test('domain separation: a LOG signature (no witness tag) does NOT verify as a witness cosignature', () => {
    const w = newEd25519();
    const cp = makeCheckpoint();
    // Sign exactly as the LOG does: SHA-256(canonicalize(checkpoint)) with NO domain tag.
    const signed = { ...cp };
    delete signed.log_signature;
    const logDigest = crypto.createHash('sha256').update(canonicalize(signed), 'utf8').digest();
    const logSig = crypto.sign(null, logDigest, w.privateKey).toString('base64url');
    const forged = {
        alg: WITNESS_VERSION,
        witness_id: 'witness-a',
        tree_size: cp.tree_size,
        root_hash: cp.root_hash,
        log_key_id: cp.log_key_id,
        signature: logSig,
    };
    const r = verifyWitnessCosignature(cp, forged, { witness_id: 'witness-a', public_key: w.pub });
    assert.equal(r.verified, false, 'a log signature must not be replayable as a witness cosignature');
});
test('the witness pre-image includes the domain tag', () => {
    const cp = makeCheckpoint();
    const signed = { ...cp };
    const witnessPre = Buffer.concat([
        Buffer.from(WITNESS_DOMAIN_TAG, 'utf8'),
        Buffer.from(canonicalize(signed), 'utf8'),
    ]);
    const expected = crypto.createHash('sha256').update(witnessPre).digest();
    assert.ok(witnessSigningDigest(cp).equals(expected));
    // And it differs from the log's tag-less digest.
    const logDigest = crypto.createHash('sha256').update(canonicalize(signed), 'utf8').digest();
    assert.ok(!witnessSigningDigest(cp).equals(logDigest));
});
test('malformed inputs refuse (fail-closed)', () => {
    const w = newEd25519();
    const cp = makeCheckpoint();
    const good = cosign(cp, 'witness-a', w);
    const pin = { witness_id: 'witness-a', public_key: w.pub };
    assert.equal(verifyWitnessCosignature(null, good, pin).verified, false);
    assert.equal(verifyWitnessCosignature(cp, null, pin).verified, false);
    assert.equal(verifyWitnessCosignature(cp, good, null).verified, false);
    assert.equal(verifyWitnessCosignature(cp, good, { witness_id: 'witness-a' }).verified, false);
    assert.equal(verifyWitnessCosignature(cp, good, { public_key: w.pub }).verified, false);
    assert.equal(verifyWitnessCosignature(cp, { ...good, signature: undefined }, pin).verified, false);
    assert.equal(verifyWitnessCosignature(cp, { ...good, witness_id: undefined }, pin).verified, false);
    assert.equal(verifyWitnessCosignature(cp, { ...good, alg: 'WRONG' }, pin).verified, false);
});
// ── k-of-n quorum helper ─────────────────────────────────────────────────────
test('requireWitnessQuorum accepts k distinct pinned witnesses over one head', () => {
    const wA = newEd25519();
    const wB = newEd25519();
    const wC = newEd25519();
    const cp = makeCheckpoint();
    const pinned = [
        { witness_id: 'a', public_key: wA.pub },
        { witness_id: 'b', public_key: wB.pub },
        { witness_id: 'c', public_key: wC.pub },
    ];
    const cosigs = [cosign(cp, 'a', wA), cosign(cp, 'b', wB), cosign(cp, 'c', wC)];
    const r = requireWitnessQuorum(cp, cosigs, pinned, 2);
    assert.equal(r.ok, true);
    assert.equal(r.met, 3);
    assert.equal(r.required, 2);
    assert.deepEqual(r.witness_ids, ['a', 'b', 'c']);
});
test('requireWitnessQuorum refuses k-1 (not enough distinct witnesses)', () => {
    const wA = newEd25519();
    const wB = newEd25519();
    const wC = newEd25519();
    const cp = makeCheckpoint();
    const pinned = [
        { witness_id: 'a', public_key: wA.pub },
        { witness_id: 'b', public_key: wB.pub },
        { witness_id: 'c', public_key: wC.pub },
    ];
    // Only two valid cosignatures, but k = 3.
    const cosigs = [cosign(cp, 'a', wA), cosign(cp, 'b', wB)];
    const r = requireWitnessQuorum(cp, cosigs, pinned, 3);
    assert.equal(r.ok, false);
    assert.equal(r.met, 2);
    assert.equal(r.required, 3);
});
test('requireWitnessQuorum counts a duplicate witness_id only once', () => {
    const wA = newEd25519();
    const wB = newEd25519();
    const cp = makeCheckpoint();
    const pinned = [
        { witness_id: 'a', public_key: wA.pub },
        { witness_id: 'b', public_key: wB.pub },
    ];
    // Witness "a" cosigns twice; that must NOT satisfy a 2-of-n threshold alone.
    const cosigs = [cosign(cp, 'a', wA), cosign(cp, 'a', wA)];
    const r = requireWitnessQuorum(cp, cosigs, pinned, 2);
    assert.equal(r.ok, false);
    assert.equal(r.met, 1);
    assert.deepEqual(r.witness_ids, ['a']);
    assert.match(r.reasons.join(' '), /duplicate cosignature from witness "a"/);
});
test('requireWitnessQuorum ignores cosignatures from unpinned witnesses', () => {
    const wA = newEd25519();
    const wB = newEd25519();
    const wStranger = newEd25519();
    const cp = makeCheckpoint();
    const pinned = [
        { witness_id: 'a', public_key: wA.pub },
        { witness_id: 'b', public_key: wB.pub },
    ];
    const cosigs = [cosign(cp, 'a', wA), cosign(cp, 'stranger', wStranger)];
    const r = requireWitnessQuorum(cp, cosigs, pinned, 2);
    assert.equal(r.ok, false);
    assert.equal(r.met, 1);
    assert.match(r.reasons.join(' '), /unpinned witness "stranger"/);
});
test('requireWitnessQuorum ignores a cosignature for a DIFFERENT head', () => {
    const wA = newEd25519();
    const wB = newEd25519();
    const cp = makeCheckpoint({ tree_size: 42 });
    const otherHead = makeCheckpoint({ tree_size: 99 });
    const pinned = [
        { witness_id: 'a', public_key: wA.pub },
        { witness_id: 'b', public_key: wB.pub },
    ];
    // wB cosigned a DIFFERENT head — it must not count toward quorum on cp.
    const cosigs = [cosign(cp, 'a', wA), cosign(otherHead, 'b', wB)];
    const r = requireWitnessQuorum(cp, cosigs, pinned, 2);
    assert.equal(r.ok, false);
    assert.equal(r.met, 1);
    assert.deepEqual(r.witness_ids, ['a']);
});
test('requireWitnessQuorum drops an ambiguous duplicate PINNED witness_id', () => {
    const wA1 = newEd25519();
    const wA2 = newEd25519();
    const wB = newEd25519();
    const cp = makeCheckpoint();
    // Two pinned entries claim id "a" with different keys — ambiguous, so "a" is dropped.
    const pinned = [
        { witness_id: 'a', public_key: wA1.pub },
        { witness_id: 'a', public_key: wA2.pub },
        { witness_id: 'b', public_key: wB.pub },
    ];
    const cosigs = [cosign(cp, 'a', wA1), cosign(cp, 'b', wB)];
    const r = requireWitnessQuorum(cp, cosigs, pinned, 2);
    assert.equal(r.ok, false);
    assert.equal(r.met, 1); // only "b" counts; "a" is unpinned after the drop
    assert.match(r.reasons.join(' '), /appears more than once/);
});
test('requireWitnessQuorum fails closed on bad k and bad inputs', () => {
    const cp = makeCheckpoint();
    assert.equal(requireWitnessQuorum(cp, [], [], 0).ok, false);
    assert.equal(requireWitnessQuorum(cp, [], [], 2.5).ok, false);
    assert.equal(requireWitnessQuorum(cp, [], [], '2').ok, false);
    assert.equal(requireWitnessQuorum(null, [], [], 1).ok, false);
    assert.equal(requireWitnessQuorum(cp, 'nope', [], 1).ok, false);
    assert.equal(requireWitnessQuorum(cp, [], 'nope', 1).ok, false);
});
