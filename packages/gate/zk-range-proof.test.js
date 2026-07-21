// SPDX-License-Identifier: Apache-2.0
// Generated from zk-range-proof.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import { ristretto255 } from '@noble/curves/ed25519.js';
import { ZK_RANGE_RECEIPT_VERSION, deriveZkRangeBases, loadBulletproofBackend, mintZkRangeReceipt, verifyZkRangeReceipt, } from './zk-range-proof.js';
function scalarLE(value) {
    const bytes = new Uint8Array(32);
    let current = BigInt(value) % ristretto255.Point.Fn.ORDER;
    for (let i = 0; i < bytes.length; i += 1) {
        bytes[i] = Number(current & 0xffn);
        current >>= 8n;
    }
    return bytes;
}
function commitment(value, blinding, valBase, randBase) {
    let scalar = 0n;
    for (let i = blinding.length - 1; i >= 0; i -= 1)
        scalar = (scalar << 8n) | BigInt(blinding[i]);
    return ristretto255.Point.fromBytes(valBase)
        .multiply(BigInt(value))
        .add(ristretto255.Point.fromBytes(randBase).multiply(scalar))
        .toBytes();
}
function fakeBulletproofBackend() {
    return {
        async batchRangeProof({ v, rs, valBase, randBase }) {
            return {
                proof: Uint8Array.from([1, 2, 3]),
                comms: v.map((value, index) => commitment(value, rs[index], valBase, randBase)),
            };
        },
        async batchVerifyProof() { return true; },
    };
}
test('ZK range receipt binds a hidden value to a public upper bound', async () => {
    const backend = fakeBulletproofBackend();
    const proof = await mintZkRangeReceipt({
        value: 42,
        max: 100,
        blindingFactor: scalarLE(19),
        policyHash: `sha256:${'11'.repeat(32)}`,
        actionPredicate: 'amount <= 100 USD minor units',
        baseReceiptDigest: `sha256:${'22'.repeat(32)}`,
        issuerPublicKey: 'issuer-key-1',
        nonce: 'nonce-1',
        backend,
    });
    assert.equal(proof['@version'], ZK_RANGE_RECEIPT_VERSION);
    assert.equal(proof.statement.max, 100);
    assert.equal(Object.hasOwn(proof.statement, 'value'), false);
    assert.equal(Object.hasOwn(proof.statement, 'blinding_factor'), false);
    assert.equal((await verifyZkRangeReceipt(proof, { backend })).ok, true);
    const tampered = structuredClone(proof);
    tampered.statement.max = 10_000;
    assert.equal((await verifyZkRangeReceipt(tampered, { backend })).ok, false);
});
test('ZK range receipt refuses out-of-range values before invoking the backend', async () => {
    let invoked = false;
    await assert.rejects(mintZkRangeReceipt({
        value: 101,
        max: 100,
        policyHash: `sha256:${'11'.repeat(32)}`,
        actionPredicate: 'amount <= 100',
        baseReceiptDigest: `sha256:${'22'.repeat(32)}`,
        issuerPublicKey: 'issuer-key-1',
        backend: { batchRangeProof: async () => { invoked = true; }, batchVerifyProof: async () => false },
    }), /exceeds the public range bound/);
    assert.equal(invoked, false);
});
test('ZK bases are deterministic and missing optional backend fails closed', async () => {
    const first = deriveZkRangeBases();
    const second = deriveZkRangeBases();
    assert.deepEqual(first.valBase, second.valBase);
    assert.deepEqual(first.randBase, second.randBase);
    await assert.rejects(loadBulletproofBackend(), /backend unavailable/);
});
