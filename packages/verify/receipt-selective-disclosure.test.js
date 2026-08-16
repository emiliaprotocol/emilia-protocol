// SPDX-License-Identifier: Apache-2.0
// Generated from receipt-selective-disclosure.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// EP-SD-v1 selective-disclosure profile: vitest suite.
//
// Run from packages/verify (the repo-root vitest config deliberately excludes
// packages/**, which run their own node:test suites; this file is vitest-only):
//   cd packages/verify && npx vitest run receipt-selective-disclosure.test.ts
//
// Exercises the conformance vectors in conformance/selective-disclosure/
// (including byte-level regeneration, proving the vectors are deterministic)
// plus module-level hostile cases the vectors do not carry.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { EP_SD_VERSION, EP_SD_PRESENTATION_VERSION, EP_SD_MIN_SALT_BYTES, NON_REDACTABLE_PATHS, prepareSelectiveDisclosure, createSelectiveDisclosurePresentation, verifySelectiveDisclosurePresentation, sdCommitmentDigest, sdPresentationBindingDigest, } from './src/receipt-selective-disclosure.js';
import { canonicalizeStrictJson } from './src/strict-json.js';
const VECTORS_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../conformance/selective-disclosure/vectors.json');
const vectors = JSON.parse(fs.readFileSync(VECTORS_PATH, 'utf8'));
function privateKeyFrom(pkcs8B64u) {
    return crypto.createPrivateKey({ key: Buffer.from(pkcs8B64u, 'base64url'), format: 'der', type: 'pkcs8' });
}
const issuerPrivate = privateKeyFrom(vectors.keys.issuer.pkcs8_b64u);
const issuerPublic = vectors.keys.issuer.spki_b64u;
const holderPrivate = privateKeyFrom(vectors.keys.holder.pkcs8_b64u);
const holderPublic = vectors.keys.holder.spki_b64u;
function signPayload(payload) {
    return crypto.sign(null, Buffer.from(canonicalizeStrictJson(payload), 'utf8'), issuerPrivate).toString('base64url');
}
function signedReceipt(payload) {
    return {
        '@version': 'EP-RECEIPT-v1',
        payload,
        signature: { algorithm: 'Ed25519', value: signPayload(payload) },
    };
}
describe('conformance vectors: valid presentations', () => {
    for (const entry of vectors.presentations) {
        it(`verifies ${entry.name}`, () => {
            const res = verifySelectiveDisclosurePresentation(entry.presentation, issuerPublic, entry.expectation);
            expect(res.refusals).toEqual([]);
            expect(res.ok).toBe(true);
            expect(res.caid).toBe(entry.expect.caid);
            expect(res.undisclosed_paths).toEqual(entry.expect.undisclosed_paths);
            expect(res.checks.receipt_signature).toBe(true);
            expect(res.checks.binding).toBe(true);
            // The binding digest pinned in the vectors reproduces exactly.
            const digest = sdPresentationBindingDigest(entry.presentation.receipt, entry.presentation.disclosed, entry.presentation.binding);
            expect(digest.toString('hex')).toBe(entry.binding_digest_hex);
        });
    }
    it('keeps VERIFIED distinct from ACCEPTED in the decision scope', () => {
        const entry = vectors.presentations[0];
        const res = verifySelectiveDisclosurePresentation(entry.presentation, issuerPublic, entry.expectation);
        expect(res.decision_scope.establishes).toContain('cryptographic verification');
        expect(res.decision_scope.does_not_establish).toContain('acceptance');
    });
});
describe('conformance vectors: hostile presentations refuse with named reasons', () => {
    for (const entry of vectors.hostile) {
        it(`refuses ${entry.name}`, () => {
            const res = verifySelectiveDisclosurePresentation(entry.presentation, issuerPublic, entry.expectation);
            expect(res.ok).toBe(false);
            expect(res.refusals).toEqual(entry.expected_refusals);
        });
    }
    for (const entry of vectors.prepare_refusals) {
        it(`prepare refuses ${entry.name}`, () => {
            const res = prepareSelectiveDisclosure(vectors.source_payload, entry.paths, vectors.salts);
            expect(res.ok).toBe(false);
            if (res.ok === false) {
                for (const expected of entry.expected_refusals)
                    expect(res.refusals).toContain(expected);
            }
        });
    }
});
describe('vector determinism: full regeneration is byte-identical', () => {
    it('re-derives the disclosure-ready receipt and every presentation from fixed seeds', () => {
        const prep = prepareSelectiveDisclosure(vectors.source_payload, vectors.disclosable_paths, vectors.salts);
        expect(prep.ok).toBe(true);
        if (!prep.ok)
            return;
        expect(canonicalizeStrictJson(prep.payload))
            .toBe(canonicalizeStrictJson(vectors.disclosure_ready_receipt.payload));
        expect(prep.openings).toEqual(vectors.openings);
        const receipt = signedReceipt(prep.payload);
        expect(canonicalizeStrictJson(receipt)).toBe(canonicalizeStrictJson(vectors.disclosure_ready_receipt));
        for (const entry of vectors.presentations) {
            const withHolder = entry.name === 'full-disclosure-with-holder-proof';
            const rebuilt = createSelectiveDisclosurePresentation(receipt, prep.openings, entry.presentation.disclosed.map((d) => d.path), entry.presentation.binding, withHolder ? { holder: { privateKey: holderPrivate, publicKeySpkiB64u: holderPublic } } : {});
            expect(rebuilt.ok).toBe(true);
            if (rebuilt.ok) {
                expect(canonicalizeStrictJson(rebuilt.presentation)).toBe(canonicalizeStrictJson(entry.presentation));
            }
        }
    });
});
describe('construction invariants', () => {
    it('publishes a closed non-redactable set covering CAID and evidence grading', () => {
        for (const required of ['caid', 'action.caid', 'action.action_type', 'evidence_grade', 'verification_status', 'signoffs', 'disclosure']) {
            expect(NON_REDACTABLE_PATHS).toContain(required);
        }
        expect(Object.isFrozen(NON_REDACTABLE_PATHS)).toBe(true);
    });
    it('binds the field path inside the commitment (same value+salt, different path, different digest)', () => {
        const salt = Buffer.alloc(EP_SD_MIN_SALT_BYTES, 7).toString('base64url');
        expect(sdCommitmentDigest('a.b', salt, 'v')).not.toBe(sdCommitmentDigest('a.c', salt, 'v'));
    });
    it('refuses to prepare an ancestor of a non-redactable path', () => {
        const res = prepareSelectiveDisclosure(vectors.source_payload, ['action'], {});
        expect(res.ok).toBe(false);
        if (res.ok === false)
            expect(res.refusals).toContain('non_redactable_path:action');
    });
    it('refuses overlapping designations', () => {
        const res = prepareSelectiveDisclosure(vectors.source_payload, ['action.parameters', 'action.parameters.memo'], {});
        expect(res.ok).toBe(false);
        if (res.ok === false) {
            expect(res.refusals.some((r) => r.startsWith('overlapping_paths:'))).toBe(true);
        }
    });
    it('refuses a payload that already contains commitment-marker strings', () => {
        const payload = { ...vectors.source_payload, note: 'ep-sd-commit:sha256:deadbeef' };
        const res = prepareSelectiveDisclosure(payload, ['note'], {});
        expect(res.ok).toBe(false);
        if (res.ok === false)
            expect(res.refusals).toContain('marker_collision:note');
    });
    it('generates fresh CSPRNG salts of at least 128 bits when none are pinned', () => {
        const res = prepareSelectiveDisclosure(vectors.source_payload, ['action.parameters.memo'], {});
        expect(res.ok).toBe(true);
        if (res.ok) {
            const salt = res.openings['action.parameters.memo'].salt;
            expect(Buffer.from(salt, 'base64url').length).toBeGreaterThanOrEqual(EP_SD_MIN_SALT_BYTES);
        }
    });
    it('exposes stable wire tags', () => {
        expect(EP_SD_VERSION).toBe('EP-SD-v1');
        expect(EP_SD_PRESENTATION_VERSION).toBe('EP-SD-PRESENTATION-v1');
    });
});
describe('fail-closed behavior (refusal, never a crash)', () => {
    const expectation = { audience: 'auditor.example', nonce: 'n-1' };
    it('refuses an already-issued plaintext receipt: disclosure-ready issuance is a real constraint', () => {
        const plain = signedReceipt({ receipt_id: 'r1', caid: vectors.source_payload.caid, created_at: '2026-08-16T12:00:00Z' });
        const res = verifySelectiveDisclosurePresentation({
            '@version': EP_SD_PRESENTATION_VERSION,
            receipt: plain,
            disclosed: [],
            binding: { audience: 'auditor.example', nonce: 'n-1', created_at: '2026-08-16T12:00:00Z' },
        }, issuerPublic, expectation);
        expect(res.ok).toBe(false);
        expect(res.refusals).toEqual(['missing_disclosure_block']);
    });
    it('refuses a smuggled undeclared commitment marker', () => {
        const prep = prepareSelectiveDisclosure(vectors.source_payload, ['action.parameters.memo'], {
            'action.parameters.memo': vectors.salts['action.parameters.memo'],
        });
        expect(prep.ok).toBe(true);
        if (!prep.ok)
            return;
        const payload = JSON.parse(JSON.stringify(prep.payload));
        payload.extra = `ep-sd-commit:sha256:${'a'.repeat(64)}`;
        const res = verifySelectiveDisclosurePresentation({
            '@version': EP_SD_PRESENTATION_VERSION,
            receipt: signedReceipt(payload),
            disclosed: [],
            binding: { audience: 'auditor.example', nonce: 'n-1', created_at: '2026-08-16T12:00:00Z' },
        }, issuerPublic, expectation);
        expect(res.ok).toBe(false);
        expect(res.refusals).toEqual(['undeclared_commitment:extra']);
    });
    it('requires and verifies a holder proof when a holder key is pinned', () => {
        const entry = vectors.presentations[1]; // has no holder proof
        const res = verifySelectiveDisclosurePresentation(entry.presentation, issuerPublic, {
            ...entry.expectation,
            holderPublicKeySpkiB64u: holderPublic,
        });
        expect(res.ok).toBe(false);
        expect(res.refusals).toEqual(['holder_proof_missing']);
    });
    it('refuses a holder proof under the wrong pinned key', () => {
        const entry = vectors.presentations[0]; // carries a holder proof
        const res = verifySelectiveDisclosurePresentation(entry.presentation, issuerPublic, {
            ...entry.expectation,
            holderPublicKeySpkiB64u: issuerPublic, // pin a different key
        });
        expect(res.ok).toBe(false);
        expect(res.refusals).toEqual(['holder_proof_key_mismatch']);
    });
    it('refuses a forged holder-proof signature', () => {
        const entry = JSON.parse(JSON.stringify(vectors.presentations[0]));
        entry.presentation.holder_proof.signature = Buffer.alloc(64, 3).toString('base64url');
        const res = verifySelectiveDisclosurePresentation(entry.presentation, issuerPublic, entry.expectation);
        expect(res.ok).toBe(false);
        expect(res.refusals).toEqual(['holder_proof_invalid']);
    });
    it('returns structured refusals for garbage inputs instead of throwing', () => {
        for (const garbage of [null, undefined, 42, 'x', [], { '@version': 'nope' }, { toJSON() { throw new Error('boom'); } }]) {
            const res = verifySelectiveDisclosurePresentation(garbage, issuerPublic, expectation);
            expect(res.ok).toBe(false);
            expect(res.refusals.length).toBeGreaterThan(0);
        }
        const missingExpectation = verifySelectiveDisclosurePresentation(vectors.presentations[0].presentation, issuerPublic, {});
        expect(missingExpectation.ok).toBe(false);
        expect(missingExpectation.refusals).toEqual(['verifier_expectation_missing']);
    });
    it('refuses a receipt without a plaintext CAID', () => {
        const prep = prepareSelectiveDisclosure({ receipt_id: 'r2', created_at: '2026-08-16T12:00:00Z', field: 'v' }, ['field'], { field: vectors.salts['action.parameters.memo'] });
        expect(prep.ok).toBe(true);
        if (!prep.ok)
            return;
        const res = verifySelectiveDisclosurePresentation({
            '@version': EP_SD_PRESENTATION_VERSION,
            receipt: signedReceipt(prep.payload),
            disclosed: [],
            binding: { audience: 'auditor.example', nonce: 'n-1', created_at: '2026-08-16T12:00:00Z' },
        }, issuerPublic, expectation);
        expect(res.ok).toBe(false);
        expect(res.refusals).toEqual(['missing_caid']);
    });
});
