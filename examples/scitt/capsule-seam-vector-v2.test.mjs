// SPDX-License-Identifier: Apache-2.0
// Generated from capsule-seam-vector-v2.test.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { COSE_HEADER_CWT_CLAIMS, CWT_CLAIM_ISS, CWT_CLAIM_SUB, EP_STATEMENT_PAYLOAD_CONTENT_TYPE, decodeDeterministicCbor8949, verifyEpScittSignedStatement, } from '../../packages/verify/index.js';
import { approved, denied, vectorJson, } from './capsule-seam-vector-v2.mjs';
const HERE = dirname(fileURLToPath(import.meta.url));
const V1_PATH = resolve(HERE, 'capsule-seam-vector.json');
const V2_PATH = resolve(HERE, 'capsule-seam-vector-v2.json');
const V1_SHA256 = 'c03fa6eb3a899bae1c63e7d25bc5fce1e10bdb9ac8dfdfc8e25fb7dafaae635a';
function decodeProtected(statement) {
    const body = decodeDeterministicCbor8949(statement.subarray(1), { textKeysOnly: false });
    assert.equal(body.ok, true, body.ok ? undefined : body.reason);
    if (!body.ok)
        throw new Error(body.reason);
    assert.equal(Array.isArray(body.value), true);
    const protectedBytes = body.value[0];
    assert.equal(protectedBytes instanceof Uint8Array, true);
    const protectedHeader = decodeDeterministicCbor8949(protectedBytes, {
        textKeysOnly: false,
    });
    assert.equal(protectedHeader.ok, true, protectedHeader.ok ? undefined : protectedHeader.reason);
    if (!protectedHeader.ok || !(protectedHeader.value instanceof Map)) {
        throw new Error('protected header is not a map');
    }
    return protectedHeader.value;
}
test('the immutable v1 Capsule seam fixture remains byte-for-byte frozen', () => {
    const actual = crypto.createHash('sha256').update(readFileSync(V1_PATH)).digest('hex');
    assert.equal(actual, V1_SHA256);
});
test('v2 approved and denied statements pass the shipped fail-closed profile verifier', () => {
    for (const fixture of [approved, denied]) {
        const verified = verifyEpScittSignedStatement(fixture.statement, fixture.pins);
        assert.equal(verified.valid, true, verified.reason);
        assert.equal(verified.registered, false);
        assert.equal(verified.identity?.statement_entry_digest, fixture.statement_entry_digest);
        assert.equal(verified.identity?.signing_input_digest, fixture.signing_input_digest);
        assert.equal(verified.identity?.authorization_payload_digest, fixture.authorization_payload_digest);
    }
});
test('v2 statements carry the exact EP profile headers and versioned action grammar', () => {
    for (const fixture of [approved, denied]) {
        const protectedHeader = decodeProtected(fixture.statement);
        assert.equal(protectedHeader.get(3), EP_STATEMENT_PAYLOAD_CONTENT_TYPE);
        const claims = protectedHeader.get(COSE_HEADER_CWT_CLAIMS);
        assert.equal(claims instanceof Map, true);
        assert.equal(claims.get(CWT_CLAIM_ISS), fixture.iss);
        assert.equal(claims.get(CWT_CLAIM_SUB), fixture.sub);
        assert.equal(fixture.receipt.payload.action.action_type, 'payment.release.1');
    }
});
test('v2 keeps all three prefixed digest identities separate and pins its JSON', () => {
    const vector = vectorJson();
    assert.equal(vector.vector, 'EP<->Capsule seam vector v2');
    for (const fixture of [vector.approved, vector.denied]) {
        assert.match(fixture.authorization_payload_digest, /^sha256:[0-9a-f]{64}$/);
        assert.match(fixture.signing_input_digest, /^sha256:[0-9a-f]{64}$/);
        assert.match(fixture.statement_entry_digest, /^sha256:[0-9a-f]{64}$/);
        assert.notEqual(fixture.authorization_payload_digest, fixture.signing_input_digest);
        assert.notEqual(fixture.authorization_payload_digest, fixture.statement_entry_digest);
        assert.notEqual(fixture.signing_input_digest, fixture.statement_entry_digest);
    }
    assert.deepEqual(vector, JSON.parse(readFileSync(V2_PATH, 'utf8')));
});
