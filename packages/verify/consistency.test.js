// Generated from consistency.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Tests for the EXPERIMENTAL checkpoint consistency verifier (RFC 6962 §2.1.2).
 *
 * These prove the verifier accepts genuine append-only extensions and REJECTS
 * the equivocation / history-rewrite attacks described in
 * docs/security/TRANSPARENCY-LAYER-DESIGN.md. Run:  node --test consistency.test.js
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { verifyCheckpointConsistency, buildConsistencyProof, merkleRoot, } from './consistency.js';
// Deterministic v2 leaf hashes (0x00 || content) — matches leafHashV2 in index.js.
function leaf(content) {
    return crypto
        .createHash('sha256')
        .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(content, 'utf8')]))
        .digest('hex');
}
function leaves(n) {
    return Array.from({ length: n }, (_, i) => leaf(`receipt-${i}`));
}
// Exhaustive round-trip: for every 1 <= m <= n <= 16, a genuine extension verifies.
test('genuine append-only extensions verify for all 1<=m<=n<=16', () => {
    for (let n = 1; n <= 16; n++) {
        const all = leaves(n);
        const newRoot = merkleRoot(all);
        for (let m = 1; m <= n; m++) {
            const oldRoot = merkleRoot(all.slice(0, m));
            const proof = buildConsistencyProof(m, n, all);
            assert.equal(verifyCheckpointConsistency(oldRoot, m, newRoot, n, proof), true, `expected consistent proof to verify for m=${m}, n=${n}`);
        }
    }
});
test('equal sizes: empty proof + equal roots verifies; mismatched roots fail', () => {
    const all = leaves(5);
    const root = merkleRoot(all);
    assert.equal(verifyCheckpointConsistency(root, 5, root, 5, []), true);
    assert.equal(verifyCheckpointConsistency(root, 5, merkleRoot(leaves(6)), 5, []), false);
    // Equal size but a non-empty proof is illegal.
    assert.equal(verifyCheckpointConsistency(root, 5, root, 5, [leaf('x')]), false);
});
test('accepts sha256: hash prefixes on roots and proof nodes', () => {
    const all = leaves(7);
    const oldRoot = merkleRoot(all.slice(0, 3));
    const newRoot = merkleRoot(all);
    const proof = buildConsistencyProof(3, 7, all).map((h) => `sha256:${h}`);
    assert.equal(verifyCheckpointConsistency(`sha256:${oldRoot}`, 3, `SHA256:${newRoot}`, 7, proof), true);
});
// ── ATTACK: history rewrite / split view ────────────────────────────────────
// The core threat. Operator shows verifier A a size-3 log, then to verifier B a
// size-6 log whose first 3 leaves DIFFER. No consistency proof can bridge them.
test('rejects a rewritten prefix (split-view / equivocation)', () => {
    const honest = leaves(6);
    const oldRoot = merkleRoot(honest.slice(0, 3));
    // Fork: same length, but leaf 1 was swapped out — a different history.
    const forked = [...honest];
    forked[1] = leaf('rewritten-receipt-1');
    const forkedNewRoot = merkleRoot(forked);
    // Try every proof the honest prover could produce; none should validate the fork.
    const honestProof = buildConsistencyProof(3, 6, honest);
    assert.equal(verifyCheckpointConsistency(oldRoot, 3, forkedNewRoot, 6, honestProof), false);
    // And the honest new root cannot be reached from the forked old prefix root.
    const forkedOldRoot = merkleRoot(forked.slice(0, 3));
    const honestNewRoot = merkleRoot(honest);
    assert.equal(verifyCheckpointConsistency(forkedOldRoot, 3, honestNewRoot, 6, honestProof), false);
});
test('rejects a tampered proof node', () => {
    const all = leaves(9);
    const oldRoot = merkleRoot(all.slice(0, 4));
    const newRoot = merkleRoot(all);
    const proof = buildConsistencyProof(4, 9, all);
    const tampered = [...proof];
    tampered[0] = leaf('not-the-node');
    assert.equal(verifyCheckpointConsistency(oldRoot, 4, newRoot, 9, tampered), false);
});
test('rejects a proof for the wrong old root', () => {
    const all = leaves(8);
    const newRoot = merkleRoot(all);
    const proof = buildConsistencyProof(5, 8, all);
    const wrongOld = merkleRoot(leaves(5).map((h, i) => (i === 0 ? leaf('different') : h)));
    assert.equal(verifyCheckpointConsistency(wrongOld, 5, newRoot, 8, proof), false);
});
// ── Fail-closed input validation ────────────────────────────────────────────
test('fail-closed on malformed inputs', () => {
    const all = leaves(4);
    const root = merkleRoot(all);
    assert.equal(verifyCheckpointConsistency(root, 5, root, 4, []), false, 'oldSize > newSize');
    assert.equal(verifyCheckpointConsistency(root, 1.5, root, 4, []), false, 'non-integer size');
    assert.equal(verifyCheckpointConsistency(root, 0, root, 4, []), false, 'oldSize 0 rejected');
    assert.equal(verifyCheckpointConsistency('', 1, root, 4, []), false, 'empty old root');
    assert.equal(verifyCheckpointConsistency(root, 2, root, 4, 'nope'), false, 'proof not array');
    assert.equal(verifyCheckpointConsistency(root, 2, root, 4, []), false, 'growth with empty proof');
});
