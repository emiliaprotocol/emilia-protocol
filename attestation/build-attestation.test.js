// SPDX-License-Identifier: Apache-2.0
// Generated from build-attestation.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import { describe, it, expect } from 'vitest';
import { verifyBuildAttestation, verifyTpmQuote, attestationSubject, attestationLeafHash, BUILD_ATTESTATION_VERSION, TPM_QUOTE_FORMAT, } from './build-attestation.js';
import { assembleRecord, buildLogEntry } from './merkle-log.js';
const COMMIT_A = 'a'.repeat(40);
const COMMIT_B = 'b'.repeat(40);
const HASH_H = '11'.repeat(32); // 64 hex
const HASH_G = '22'.repeat(32);
function baseRecord(overrides = {}) {
    return assembleRecord({ commit: COMMIT_A, package_path: 'packages/verify' }, { filename: 'pkg-1.0.0.tgz', sha256: HASH_H, bytes: 1024, ...overrides });
}
// A rebuild stub that returns a fixed hash — no npm/git, so tests are fast and
// deterministic. The real reproducible build is exercised separately (CLI/demo).
function rebuildReturning(sha256) {
    return () => ({ source_commit: COMMIT_A, sha256, filename: 'pkg-1.0.0.tgz', bytes: 1024 });
}
describe('attestation subject + leaf binding', () => {
    it('binds the leaf to the exact {source, artifact}', () => {
        const record = baseRecord();
        const leaf = attestationLeafHash(attestationSubject(record));
        expect(record.log_entry.leaf_hash).toBe(leaf);
    });
    it('a different binary hash yields a different leaf', () => {
        const a = attestationLeafHash(attestationSubject(baseRecord({ sha256: HASH_H })));
        const b = attestationLeafHash(attestationSubject(baseRecord({ sha256: HASH_G })));
        expect(a).not.toBe(b);
    });
    it('a different source commit yields a different leaf', () => {
        const r1 = assembleRecord({ commit: COMMIT_A, package_path: 'p' }, { filename: 'f', sha256: HASH_H, bytes: 1 });
        const r2 = assembleRecord({ commit: COMMIT_B, package_path: 'p' }, { filename: 'f', sha256: HASH_H, bytes: 1 });
        expect(r1.log_entry.leaf_hash).not.toBe(r2.log_entry.leaf_hash);
    });
});
describe('verifyBuildAttestation — software chain (no rebuild)', () => {
    it('verifies leaf binding + single-leaf log inclusion, but is not complete', () => {
        const result = verifyBuildAttestation(baseRecord());
        expect(result.valid).toBe(true);
        expect(result.complete).toBe(false); // no rebuild link run
        expect(result.links.leaf_binding).toBe(true);
        expect(result.links.log_inclusion).toBe(true);
        expect(result.links.rebuild).toEqual({ status: 'not_checked' });
    });
    it('verifies a genuine multi-leaf inclusion proof', () => {
        // Three real builds in one log; prove the middle one.
        const subjects = [
            attestationSubject(assembleRecord({ commit: COMMIT_A, package_path: 'p0' }, { filename: 'f0', sha256: '00'.repeat(32), bytes: 1 })),
            attestationSubject(assembleRecord({ commit: COMMIT_A, package_path: 'p1' }, { filename: 'f1', sha256: '01'.repeat(32), bytes: 1 })),
            attestationSubject(assembleRecord({ commit: COMMIT_A, package_path: 'p2' }, { filename: 'f2', sha256: '02'.repeat(32), bytes: 1 })),
        ];
        const record = {
            '@version': BUILD_ATTESTATION_VERSION,
            source: { commit: COMMIT_A, package_path: 'p1' },
            artifact: { filename: 'f1', sha256: '01'.repeat(32), bytes: 1 },
            log_entry: buildLogEntry(subjects, 1),
        };
        expect(record.log_entry.merkle_proof.length).toBeGreaterThan(0);
        expect(verifyBuildAttestation(record).valid).toBe(true);
    });
});
describe('verifyBuildAttestation — rebuild link', () => {
    it('is complete + valid when the rebuild hash matches the claimed binary', () => {
        const result = verifyBuildAttestation(baseRecord(), { rebuild: rebuildReturning(HASH_H) });
        expect(result.valid).toBe(true);
        expect(result.complete).toBe(true);
        expect(result.links.rebuild.status).toBe('matched');
    });
    it('FAIL-CLOSED: rebuild hash mismatch is rejected with a reason', () => {
        const result = verifyBuildAttestation(baseRecord(), { rebuild: rebuildReturning(HASH_G) });
        expect(result.valid).toBe(false);
        expect(result.complete).toBe(true); // the rebuild link DID run
        expect(result.reason).toMatch(/rebuild_mismatch/);
        expect(result.links.rebuild.status).toBe('mismatch');
    });
    it('FAIL-CLOSED: matching bytes cannot be relabeled as a different source commit', () => {
        const result = verifyBuildAttestation(baseRecord(), {
            rebuild: () => ({
                source_commit: COMMIT_B,
                sha256: HASH_H,
                filename: 'pkg-1.0.0.tgz',
                bytes: 1024,
            }),
        });
        expect(result.valid).toBe(false);
        expect(result.complete).toBe(false);
        expect(result.reason).toMatch(/rebuild_source_mismatch/);
        expect(result.links.rebuild.status).toBe('source_mismatch');
    });
    it('FAIL-CLOSED: a throwing rebuild is caught, not propagated', () => {
        const result = verifyBuildAttestation(baseRecord(), {
            rebuild: () => { throw new Error('npm exploded'); },
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toBe('rebuild_error');
        expect(result.links.rebuild.status).toBe('error');
    });
    it('FAIL-CLOSED: a rebuild returning a non-hex hash is rejected', () => {
        const result = verifyBuildAttestation(baseRecord(), {
            rebuild: () => ({ source_commit: COMMIT_A, sha256: 'not-a-hash' }),
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toBe('rebuild_error');
    });
    it('FAIL-CLOSED: a rebuild that omits its actual source commit is rejected', () => {
        const result = verifyBuildAttestation(baseRecord(), {
            rebuild: () => ({ sha256: HASH_H, filename: 'pkg-1.0.0.tgz', bytes: 1024 }),
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toBe('rebuild_source_unverified');
    });
});
describe('verifyBuildAttestation — tamper / malformed input (fail-closed)', () => {
    it('rejects a tampered binary hash (leaf no longer binds)', () => {
        const record = baseRecord();
        record.artifact.sha256 = HASH_G; // flip the claimed binary, keep the old leaf
        const result = verifyBuildAttestation(record);
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/leaf_binding_failed/);
    });
    it('rejects a tampered merkle_root', () => {
        const record = baseRecord();
        record.log_entry.merkle_root = 'de'.repeat(32);
        const result = verifyBuildAttestation(record);
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/log_inclusion_failed/);
    });
    it('rejects a lifted inclusion proof from another leaf', () => {
        const other = assembleRecord({ commit: COMMIT_B, package_path: 'other' }, { filename: 'x', sha256: HASH_G, bytes: 2 });
        const record = baseRecord();
        record.log_entry.merkle_proof = other.log_entry.merkle_proof;
        record.log_entry.merkle_root = other.log_entry.merkle_root;
        expect(verifyBuildAttestation(record).valid).toBe(false);
    });
    it('rejects a checkpoint whose root disagrees with the inclusion root', () => {
        const record = baseRecord();
        record.log_entry.checkpoint = { tree_size: 1, root_hash: 'ee'.repeat(32), log_key_id: 'k' };
        const result = verifyBuildAttestation(record);
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/checkpoint_root_mismatch/);
    });
    it('accepts a checkpoint whose root matches the inclusion root', () => {
        const record = baseRecord();
        record.log_entry.checkpoint = { tree_size: 1, root_hash: record.log_entry.merkle_root, log_key_id: 'k' };
        expect(verifyBuildAttestation(record).valid).toBe(true);
    });
    it.each([
        ['null record', null],
        ['array record', []],
        ['wrong version', { '@version': 'nope' }],
        ['missing source', { '@version': BUILD_ATTESTATION_VERSION }],
        ['bad commit', { '@version': BUILD_ATTESTATION_VERSION, source: { commit: 'short', package_path: 'p' } }],
    ])('fails closed on %s', (_label, record) => {
        const result = verifyBuildAttestation(record);
        expect(result.valid).toBe(false);
        expect(typeof result.reason).toBe('string');
    });
    it('rejects a non-v2 merkle alg', () => {
        const record = baseRecord();
        record.log_entry.alg = 'EP-MERKLE-v1';
        expect(verifyBuildAttestation(record).valid).toBe(false);
    });
});
describe('TPM quote — fail-closed deployment verifier boundary', () => {
    const goodQuote = {
        '@format': TPM_QUOTE_FORMAT,
        quoted: 'base64-tpms-attest',
        signature: 'base64-sig',
        ak_public: 'base64-ak',
        nonce: 'deadbeef',
    };
    it('verifyTpmQuote refuses without hardware, honestly', () => {
        const r = verifyTpmQuote(goodQuote);
        expect(r.supported).toBe(false);
        expect(r.ok).toBe(false);
        expect(r.reason).toMatch(/tpm-hardware-required/);
    });
    it('a present TPM quote does NOT make the record complete without hardware', () => {
        const record = baseRecord();
        record.tpm_quote = goodQuote;
        const result = verifyBuildAttestation(record, { rebuild: rebuildReturning(HASH_H) });
        // Software chain still valid; TPM link honestly flagged hardware_required.
        expect(result.valid).toBe(true);
        expect(result.links.tpm_quote.status).toBe('hardware_required');
    });
    it('an injected hardware verifier that ACCEPTS marks the quote verified', () => {
        const record = baseRecord();
        record.tpm_quote = goodQuote;
        const result = verifyBuildAttestation(record, {
            rebuild: rebuildReturning(HASH_H),
            tpmHardwareVerifier: () => ({ ok: true, pcrDigest: 'ab'.repeat(32) }),
        });
        expect(result.valid).toBe(true);
        expect(result.links.tpm_quote.status).toBe('verified');
    });
    it('FAIL-CLOSED: an injected hardware verifier that REJECTS fails the record', () => {
        const record = baseRecord();
        record.tpm_quote = goodQuote;
        const result = verifyBuildAttestation(record, {
            rebuild: rebuildReturning(HASH_H),
            tpmHardwareVerifier: () => ({ ok: false, reason: 'pcr-mismatch' }),
        });
        expect(result.valid).toBe(false);
        expect(result.reason).toMatch(/tpm_quote_rejected/);
    });
    it('FAIL-CLOSED: a malformed TPM quote is rejected', () => {
        const record = baseRecord();
        record.tpm_quote = { '@format': 'wrong' };
        expect(verifyBuildAttestation(record).valid).toBe(false);
    });
});
