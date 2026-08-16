// SPDX-License-Identifier: Apache-2.0
// Generated from evidence-record-reattestation.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * Tests for the EP-EVIDENCE-REATTESTATION-v1 extension in
 * src/evidence-record.ts, plus a regression check that the pre-existing
 * EP-EVIDENCE-RECORD-v1 verifier is unchanged by the additive extension.
 *
 * Run: npx tsx --test packages/verify/evidence-record-reattestation.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { EVIDENCE_RECORD_VERSION, REATTESTATION_VERSION, createReattestation, verifyEvidenceRecord, verifyReattestationChain, } from './dist/evidence-record.js';
import { canonicalize } from './dist/index.js';
import { TIME_ATTESTATION_VERSION } from './dist/time-attestation.js';
import { AGILITY_REASONS } from './dist/pq-signature-agility.js';
// --- fixtures ---------------------------------------------------------------
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const edPair = crypto.generateKeyPairSync('ed25519');
const edPubB64u = edPair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
const pqPair = ml_dsa65.keygen(crypto.randomBytes(32));
const pqPubB64u = Buffer.from(pqPair.publicKey).toString('base64url');
const ed2Pair = crypto.generateKeyPairSync('ed25519');
const ed2PubB64u = ed2Pair.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
// The protected evidence: canonical bytes of a receipt-shaped artifact.
const RECORD_BYTES = Buffer.from(canonicalize({
    '@version': 'EP-RECEIPT-v1',
    payload: { action: { type: 'wire.transfer.1' }, issued_at: '2026-08-16T00:00:00Z' },
    signature: { algorithm: 'Ed25519', value: 'stub' },
}), 'utf8');
const KEYS = {
    'era-ed-1': { alg: 'Ed25519', public_key: edPubB64u },
    'era-pq-1': { alg: 'ML-DSA-65', public_key: pqPubB64u },
    'era-ed-2': { alg: 'Ed25519', public_key: ed2PubB64u },
};
// A three-link chain crossing an algorithm transition and back:
// Ed25519 -> ML-DSA-65 -> Ed25519 (fresh key), times strictly increasing.
async function makeChain() {
    const e0 = await createReattestation(RECORD_BYTES, {
        key: { alg: 'Ed25519', private_key: edPair.privateKey, key_id: 'era-ed-1' },
        reattestedAt: '2026-08-16T00:00:00Z',
    });
    const e1 = await createReattestation(e0, {
        key: { alg: 'ML-DSA-65', private_key: pqPair.secretKey, key_id: 'era-pq-1' },
        digestAlg: 'sha384',
        reattestedAt: '2030-01-01T00:00:00Z',
    });
    const e2 = await createReattestation(e1, {
        key: { alg: 'Ed25519', private_key: ed2Pair.privateKey, key_id: 'era-ed-2' },
        digestAlg: 'sha512',
        reattestedAt: '2034-01-01T00:00:00Z',
    });
    return [e0, e1, e2];
}
// --- happy path --------------------------------------------------------------
test('a chain crossing an algorithm transition verifies, reporting per-link algorithms', async () => {
    const chain = await makeChain();
    assert.ok(chain.every((e) => e['@version'] === REATTESTATION_VERSION));
    const r = await verifyReattestationChain(RECORD_BYTES, chain, KEYS);
    assert.equal(r.verified, true, JSON.stringify(r, null, 2));
    assert.equal(r.reason, null);
    assert.equal(r.first_reattested_at, '2026-08-16T00:00:00Z');
    assert.equal(r.last_reattested_at, '2034-01-01T00:00:00Z');
    // Newest-to-oldest walk; every link reports its algorithm and validity.
    assert.deepEqual(r.links.map((l) => l.index), [2, 1, 0]);
    assert.deepEqual([...r.links].sort((a, b) => a.index - b.index).map((l) => l.alg), ['Ed25519', 'ML-DSA-65', 'Ed25519']);
    assert.ok(r.links.every((l) => l.digest_valid === true && l.signature_valid === true));
});
test('a single-link chain over the record bytes verifies', async () => {
    const e0 = await createReattestation(RECORD_BYTES, {
        key: { alg: 'ML-DSA-65', private_key: pqPair.secretKey, key_id: 'era-pq-1' },
        reattestedAt: '2026-08-16T00:00:00Z',
    });
    const r = await verifyReattestationChain(RECORD_BYTES, [e0], KEYS);
    assert.equal(r.verified, true);
    assert.equal(r.links[0].alg, 'ML-DSA-65');
});
// --- broken links: refusal names the link index and reason -------------------
test('tampered protected record bytes break link 0 by name', async () => {
    const chain = await makeChain();
    const tampered = Buffer.from(RECORD_BYTES);
    tampered[0] ^= 0x01;
    const r = await verifyReattestationChain(tampered, chain, KEYS);
    assert.equal(r.verified, false);
    assert.match(String(r.reason), /^link 0: /);
    assert.equal(r.links.find((l) => l.index === 0)?.digest_valid, false);
});
test('a tampered middle entry breaks the chain, naming the link', async () => {
    const chain = await makeChain();
    chain[1] = { ...chain[1], reattested_at: '2030-01-01T00:00:01Z' }; // re-signed content changed
    const r = await verifyReattestationChain(RECORD_BYTES, chain, KEYS);
    assert.equal(r.verified, false);
    // Walking newest-to-oldest, link 2 no longer commits to the altered link 1.
    assert.match(String(r.reason), /^link 2: does not commit to the full prior record bytes/);
    const link1 = r.links.find((l) => l.index === 1);
    assert.equal(link1.signature_valid, false); // and link 1's own signature fails over the altered bytes
});
test('a tampered signature on the newest link is a broken link 2', async () => {
    const chain = await makeChain();
    const sigBuf = Buffer.from(chain[2].new_signature.sig, 'base64url');
    sigBuf[0] ^= 0x01;
    chain[2] = { ...chain[2], new_signature: { ...chain[2].new_signature, sig: sigBuf.toString('base64url') } };
    const r = await verifyReattestationChain(RECORD_BYTES, chain, KEYS);
    assert.equal(r.verified, false);
    assert.equal(r.reason, `link 2: ${AGILITY_REASONS.SIGNATURE_INVALID}`);
});
test('wrong-order chain refuses (digest linkage breaks)', async () => {
    const chain = await makeChain();
    const swapped = [chain[1], chain[0], chain[2]];
    const r = await verifyReattestationChain(RECORD_BYTES, swapped, KEYS);
    assert.equal(r.verified, false);
    assert.match(String(r.reason), /^link \d+: /);
    assert.ok(r.links.some((l) => l.digest_valid === false));
});
test('non-monotonic reattested_at refuses even when signatures verify', async () => {
    const e0 = await createReattestation(RECORD_BYTES, {
        key: { alg: 'Ed25519', private_key: edPair.privateKey, key_id: 'era-ed-1' },
        reattestedAt: '2030-01-01T00:00:00Z',
    });
    const e1 = await createReattestation(e0, {
        key: { alg: 'ML-DSA-65', private_key: pqPair.secretKey, key_id: 'era-pq-1' },
        reattestedAt: '2026-01-01T00:00:00Z', // earlier than its predecessor
    });
    const r = await verifyReattestationChain(RECORD_BYTES, [e0, e1], KEYS);
    assert.equal(r.verified, false);
    assert.match(String(r.reason), /link 1: reattested_at is not after the previous link/);
});
test('unpinned key_id refuses fail-closed', async () => {
    const chain = await makeChain();
    const r = await verifyReattestationChain(RECORD_BYTES, chain, { 'era-ed-1': KEYS['era-ed-1'] });
    assert.equal(r.verified, false);
    assert.match(String(r.reason), /no pinned key for key_id/);
});
test('an unknown signature algorithm in a link refuses with unknown_algorithm', async () => {
    const chain = await makeChain();
    chain[0] = {
        ...chain[0],
        new_signature: { ...chain[0].new_signature, alg: 'Ed448' },
    };
    const r = await verifyReattestationChain(RECORD_BYTES, [chain[0]], { 'era-ed-1': { alg: 'Ed448', public_key: edPubB64u } });
    assert.equal(r.verified, false);
    assert.equal(r.reason, `link 0: ${AGILITY_REASONS.UNKNOWN_ALGORITHM}`);
});
test('malformed inputs refuse with reasons, never throw', async () => {
    const chain = await makeChain();
    assert.equal((await verifyReattestationChain(null, chain, KEYS)).verified, false);
    assert.equal((await verifyReattestationChain(RECORD_BYTES, null, KEYS)).verified, false);
    assert.equal((await verifyReattestationChain(RECORD_BYTES, [], KEYS)).verified, false);
    const r = await verifyReattestationChain(RECORD_BYTES, [{ bogus: true }], KEYS);
    assert.equal(r.verified, false);
    assert.match(String(r.reason), /link 0: unsupported or missing @version/);
});
test('missing ML-DSA backend refuses the PQ link, never skips it', async () => {
    const chain = await makeChain();
    const r = await verifyReattestationChain(RECORD_BYTES, chain, KEYS, { mldsaBackendLoader: async () => null });
    assert.equal(r.verified, false);
    assert.equal(r.reason, `link 1: ${AGILITY_REASONS.PQ_BACKEND_UNAVAILABLE}`);
});
// --- regression: the pre-existing EP-EVIDENCE-RECORD-v1 path is unchanged ----
function tsaAttestation(hashed, time, authorityId, key) {
    const body = { '@version': TIME_ATTESTATION_VERSION, hashed, time, ts_authority_id: authorityId };
    const signed = Buffer.from(canonicalize({
        '@version': TIME_ATTESTATION_VERSION, hashed, time, ts_authority_id: authorityId,
    }), 'utf8');
    return {
        ...body,
        proof: {
            algorithm: 'Ed25519',
            ts_key_id: `${authorityId}#1`,
            public_key: key.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
            signature_b64u: crypto.sign(null, signed, key.privateKey).toString('base64url'),
        },
    };
}
test('regression: verifyEvidenceRecord still verifies a valid renewal chain', async () => {
    const tsa = crypto.generateKeyPairSync('ed25519');
    const tsaKeys = {
        'ep:tsa:test': { public_key: tsa.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url') },
    };
    const protectedHash = `sha256:${crypto.createHash('sha256').update(RECORD_BYTES).digest('hex')}`;
    const at0 = { time_attestation: tsaAttestation(protectedHash, '2026-08-16T00:00:00Z', 'ep:tsa:test', tsa) };
    const renewalHash = `sha384:${crypto.createHash('sha384')
        .update(Buffer.from(canonicalize(at0.time_attestation), 'utf8')).digest('hex')}`;
    const at1 = { time_attestation: tsaAttestation(renewalHash, '2030-01-01T00:00:00Z', 'ep:tsa:test', tsa) };
    const record = { '@version': EVIDENCE_RECORD_VERSION, protected_hash: protectedHash, archive_timestamps: [at0, at1] };
    const ok = verifyEvidenceRecord(record, { tsaKeys, protectedHash });
    assert.equal(ok.valid, true, JSON.stringify(ok, null, 2));
    // and it still fails closed on a broken chain
    const broken = { ...record, archive_timestamps: [at1, at0] };
    assert.equal(verifyEvidenceRecord(broken, { tsaKeys, protectedHash }).valid, false);
    assert.equal(verifyEvidenceRecord(null, { tsaKeys }).valid, false);
});
