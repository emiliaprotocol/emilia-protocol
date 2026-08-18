// SPDX-License-Identifier: Apache-2.0
// Generated from trust-program-revocation-v2.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
//
// EP-GATE-TRUST-PROGRAM-REVOCATION-TARGET-v1 -- hostile matrix for the
// EP-REVOCATION-v2 router adoption (verifyTrustProgramRevocationStatement /
// applyTrustProgramRevocationStatement). Package-root node:test file importing
// the compatibility shim './trust-program-revocation.js' (which re-exports
// ./dist/trust-program-revocation.js), matching this package's convention; the
// package-root trust-program-revocation.test.js, which covers the v1-only sync
// surface, is left untouched: that surface did not change a byte.
//
// The router itself is reached through the PUBLISHED package subpath
// '@emilia-protocol/verify/revocation', not a workspace-relative path, so this
// file fails to even load if that exports-map entry regresses.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';
import { deriveTrustProgramRevocationTarget, verifyTrustProgramRevocation, verifyTrustProgramRevocationStatement, applyTrustProgramRevocationStatement, } from './trust-program-revocation.js';
import { canonicalize } from '@emilia-protocol/verify';
import { REVOCATION_V2_VERSION, revocationV2SignedPayload } from '@emilia-protocol/verify/revocation';
import { signAgileSet } from '@emilia-protocol/verify/pq-signature-agility';
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const NOW = Date.parse('2026-08-17T12:00:00.000Z');
const DIGEST = (character) => `sha256:${character.repeat(64)}`;
const ROOT_CAID = `caid:1:payment.release.1:jcs-sha256:${'A'.repeat(43)}`;
function canonicalDigest(value) {
    return `sha256:${crypto.createHash('sha256').update(canonicalize(value)).digest('hex')}`;
}
const RECEIPT_CONTEXT = Object.freeze({
    issuer: 'emilia-test', tenant: 'tenant-a', environment: 'test',
    audience: 'trust-program-test', key_id: 'trust-program-test-key',
});
function authorizationBinding(overrides = {}) {
    return {
        instance_id: 'program-instance-v2-1',
        operation_id: 'provider-operation-v2-1',
        program_digest: DIGEST('1'),
        root_caid: ROOT_CAID,
        action_digest: DIGEST('2'),
        receipt_context_digest: canonicalDigest(RECEIPT_CONTEXT),
        terminal_stage_receipt_digests: [DIGEST('3'), DIGEST('4')],
        consequence_mode: 'receipt-program',
        capability_template_digest: DIGEST('5'),
        escrow_profile_digest: null,
        ...overrides,
    };
}
function derivationInput(binding = authorizationBinding()) {
    return { authorizationBinding: binding, programVersion: 7, receiptContext: RECEIPT_CONTEXT };
}
function ed25519KeyId(pubDer) {
    return `ep:revoker-key:sha256:${crypto.createHash('sha256').update(pubDer).digest('hex')}`;
}
function pqKeyId(pubRaw) {
    return `ep:revoker-key:ml-dsa-65:sha256:${crypto.createHash('sha256').update(Buffer.from(pubRaw)).digest('hex')}`;
}
function revokerFixture() {
    const ed = crypto.generateKeyPairSync('ed25519');
    const edPubB64u = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const pq = ml_dsa65.keygen(crypto.randomBytes(32));
    const pqPubB64u = Buffer.from(pq.publicKey).toString('base64url');
    const revokerId = 'ep:key:trust-program-v2-revoker#1';
    const edKeyId = ed25519KeyId(Buffer.from(edPubB64u, 'base64url'));
    const pqKeyIdValue = pqKeyId(pq.publicKey);
    async function v2Statement(target, overrides = {}) {
        const body = {
            '@version': REVOCATION_V2_VERSION,
            target_type: target.target_type,
            target_id: target.target_id,
            action_hash: target.action_hash,
            revoker_id: revokerId,
            revoked_at: '2026-08-17T11:59:00Z',
            reason: 'compromised trust-program authority (hybrid)',
        };
        const requiredAlgorithms = overrides.requiredAlgorithms ?? ['Ed25519', 'ML-DSA-65'];
        const bytes = new Uint8Array(revocationV2SignedPayload(body, requiredAlgorithms));
        const signatures = overrides.signatures ?? await signAgileSet(bytes, [
            { alg: 'Ed25519', private_key: ed.privateKey },
            { alg: 'ML-DSA-65', private_key: pq.secretKey },
        ]);
        return {
            ...body,
            proof: {
                profile: REVOCATION_V2_VERSION,
                required_algorithms: [...requiredAlgorithms],
                revoker_key_id: edKeyId,
                public_key: edPubB64u,
                pq_key_id: pqKeyIdValue,
                pq_public_key: pqPubB64u,
                signatures,
            },
        };
    }
    function v1Statement(target) {
        const signedFields = {
            '@version': 'EP-REVOCATION-v1',
            action_hash: target.action_hash,
            reason: 'classical-only revocation',
            revoked_at: '2026-08-17T11:59:00Z',
            revoker_id: revokerId,
            target_id: target.target_id,
            target_type: target.target_type,
        };
        return {
            ...signedFields,
            proof: {
                algorithm: 'Ed25519',
                revoker_key_id: edKeyId,
                signature_b64u: crypto.sign(null, Buffer.from(canonicalize(signedFields), 'utf8'), ed.privateKey)
                    .toString('base64url'),
                public_key: edPubB64u,
            },
        };
    }
    return {
        v2Statement,
        v1Statement,
        revokerId,
        ed,
        pq,
        edPubB64u,
        pqPubB64u,
        hybridPins: { [revokerId]: { public_key: edPubB64u, pq_public_key: pqPubB64u } },
        classicalOnlyPins: { [revokerId]: { public_key: edPubB64u } },
    };
}
describe('EP-REVOCATION-v2 router adoption in the Trust Program revocation target', () => {
    it('the published ./revocation subpath resolves and exposes the v2 router', async () => {
        // trust-program-revocation.ts resolves the router by dynamic import of
        // '@emilia-protocol/verify/revocation.js' with a workspace-relative
        // fallback, and turns a resolution failure into a fail-closed refusal.
        // Pin the PACKAGE path itself so a refusal below can never be silently
        // caused by an unresolvable router.
        const router = await import('@emilia-protocol/verify/revocation.js');
        assert.equal(typeof router.verifyRevocationStatement, 'function');
        assert.equal(REVOCATION_V2_VERSION, 'EP-REVOCATION-v2');
    });
    it('valid v2 roundtrip: verifies under a pin carrying both halves', async () => {
        const revoker = revokerFixture();
        const target = deriveTrustProgramRevocationTarget(derivationInput());
        const stmt = await revoker.v2Statement(target);
        const result = await verifyTrustProgramRevocationStatement({
            ...derivationInput(), statement: stmt, revokerKeys: revoker.hybridPins, now: NOW,
        });
        assert.equal(result.valid, true);
        assert.deepEqual(result.errors, []);
        // The v2 leg really ran: the router reports the hybrid checks as passed,
        // never a v1-only verdict smuggled through the any-version entry point.
        assert.equal(result.checks.portable_verifier_completed, true);
    });
    it('the router also accepts a v1 statement unchanged (either version, per relying-party pin)', async () => {
        const revoker = revokerFixture();
        const target = deriveTrustProgramRevocationTarget(derivationInput());
        const stmt = revoker.v1Statement(target);
        const result = await verifyTrustProgramRevocationStatement({
            ...derivationInput(), statement: stmt, revokerKeys: revoker.classicalOnlyPins, now: NOW,
        });
        assert.equal(result.valid, true);
    });
    it('v1-refuses-v2: the existing SYNC verifier is untouched and refuses a v2 statement on the version marker', async () => {
        const revoker = revokerFixture();
        const target = deriveTrustProgramRevocationTarget(derivationInput());
        const stmt = await revoker.v2Statement(target);
        // The old function stays synchronous -- no await needed, and none is used
        // to prove its call signature has not changed.
        const result = verifyTrustProgramRevocation({
            ...derivationInput(), statement: stmt, revokerKeys: revoker.classicalOnlyPins, now: NOW,
        });
        assert.equal(result.valid, false);
        // Refused at statement_structure (v1's PROOF_KEYS do not match v2's
        // proof shape) -- never mistaken for a signature or binding failure.
        assert.equal(result.checks.statement_structure, false);
    });
    it('a v2 statement from a revoker pinned WITHOUT the ML-DSA half refuses (never partial credit for one leg)', async () => {
        const revoker = revokerFixture();
        const target = deriveTrustProgramRevocationTarget(derivationInput());
        const stmt = await revoker.v2Statement(target);
        const result = await verifyTrustProgramRevocationStatement({
            ...derivationInput(), statement: stmt, revokerKeys: revoker.classicalOnlyPins, now: NOW,
        });
        assert.equal(result.valid, false);
    });
    it('stripped leg: dropping the ML-DSA signature while keeping required_algorithms full is refused, never a classical-only pass', async () => {
        const revoker = revokerFixture();
        const target = deriveTrustProgramRevocationTarget(derivationInput());
        const full = await revoker.v2Statement(target);
        const stripped = {
            ...full,
            proof: { ...full.proof, signatures: full.proof.signatures.filter((s) => s.alg !== 'ML-DSA-65') },
        };
        const result = await verifyTrustProgramRevocationStatement({
            ...derivationInput(), statement: stripped, revokerKeys: revoker.hybridPins, now: NOW,
        });
        assert.equal(result.valid, false);
    });
    it('narrowed set: claiming required_algorithms=["Ed25519"] only is refused structurally, not silently accepted', async () => {
        const revoker = revokerFixture();
        const target = deriveTrustProgramRevocationTarget(derivationInput());
        const full = await revoker.v2Statement(target);
        // An attacker takes a genuinely-issued full statement and narrows the
        // CLAIMED required set (dropping the PQ signature to match). The signer
        // never signs under a narrowed set -- revocationV2SignedPayload() itself
        // refuses to build bytes for a non-registered set -- so this is exactly
        // the shape a real stripping attempt would present: a mutated envelope
        // around a genuine Ed25519 signature.
        const narrowed = {
            ...full,
            proof: {
                ...full.proof,
                required_algorithms: ['Ed25519'],
                signatures: full.proof.signatures.filter((s) => s.alg === 'Ed25519'),
            },
        };
        const result = await verifyTrustProgramRevocationStatement({
            ...derivationInput(), statement: narrowed, revokerKeys: revoker.hybridPins, now: NOW,
        });
        assert.equal(result.valid, false);
    });
    it('wrong-length signature on the ML-DSA leg refuses, never crashes', async () => {
        const revoker = revokerFixture();
        const target = deriveTrustProgramRevocationTarget(derivationInput());
        const stmt = await revoker.v2Statement(target);
        const tampered = {
            ...stmt,
            proof: {
                ...stmt.proof,
                signatures: stmt.proof.signatures.map((s) => (s.alg === 'ML-DSA-65' ? { ...s, sig: Buffer.from(crypto.randomBytes(16)).toString('base64url') } : s)),
            },
        };
        const result = await verifyTrustProgramRevocationStatement({
            ...derivationInput(), statement: tampered, revokerKeys: revoker.hybridPins, now: NOW,
        });
        assert.equal(result.valid, false);
    });
    it('Ed448-masquerade: a non-Ed25519 SPKI presented as the classical half refuses, never verified under the wrong curve', async () => {
        const revoker = revokerFixture();
        const target = deriveTrustProgramRevocationTarget(derivationInput());
        const stmt = await revoker.v2Statement(target);
        const ed448 = crypto.generateKeyPairSync('ed448');
        const ed448PubB64u = ed448.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
        const masqueraded = { ...stmt, proof: { ...stmt.proof, public_key: ed448PubB64u } };
        const result = await verifyTrustProgramRevocationStatement({
            ...derivationInput(), statement: masqueraded, revokerKeys: revoker.hybridPins, now: NOW,
        });
        assert.equal(result.valid, false);
    });
    it('hostile input (prototype-bearing statement, throwing proxy) never throws and always refuses', async () => {
        const revoker = revokerFixture();
        const target = deriveTrustProgramRevocationTarget(derivationInput());
        const stmt = await revoker.v2Statement(target);
        const inherited = Object.assign(Object.create({ target_id: 'inherited' }), stmt);
        const inheritedResult = await verifyTrustProgramRevocationStatement({
            ...derivationInput(), statement: inherited, revokerKeys: revoker.hybridPins, now: NOW,
        });
        assert.equal(inheritedResult.valid, false);
        const throwing = new Proxy(stmt, { get() { throw new Error('hostile'); } });
        const throwingResult = await verifyTrustProgramRevocationStatement({
            ...derivationInput(), statement: throwing, revokerKeys: revoker.hybridPins, now: NOW,
        });
        assert.equal(throwingResult.valid, false);
    });
    it('applyTrustProgramRevocationStatement invalidates an unclaimed instance on a valid hybrid statement', async () => {
        const revoker = revokerFixture();
        const target = deriveTrustProgramRevocationTarget(derivationInput());
        const stmt = await revoker.v2Statement(target);
        let invalidateCalls = 0;
        const kernel = {
            async status() {
                return { ok: true, state: { status: 'active', revision: 3, execution: { status: 'ready' } } };
            },
            async invalidate() {
                invalidateCalls += 1;
                return { ok: true, state: { status: 'invalidated', revision: 4, execution: { status: 'invalidated' } } };
            },
        };
        const result = await applyTrustProgramRevocationStatement({
            ...derivationInput(), statement: stmt, revokerKeys: revoker.hybridPins, now: NOW,
            expectedRevision: 3, kernel,
        });
        assert.equal(result.verified, true);
        assert.equal(result.applied, true);
        assert.equal(result.disposition, 'invalidated_before_claim');
        assert.equal(invalidateCalls, 1);
    });
    it('applyTrustProgramRevocationStatement never invalidates on a refused (unpinned PQ leg) statement', async () => {
        const revoker = revokerFixture();
        const target = deriveTrustProgramRevocationTarget(derivationInput());
        const stmt = await revoker.v2Statement(target);
        let invalidateCalls = 0;
        const kernel = {
            async status() {
                return { ok: true, state: { status: 'active', revision: 3, execution: { status: 'ready' } } };
            },
            async invalidate() {
                invalidateCalls += 1;
                throw new Error('must not be called');
            },
        };
        const result = await applyTrustProgramRevocationStatement({
            ...derivationInput(), statement: stmt, revokerKeys: revoker.classicalOnlyPins, now: NOW,
            expectedRevision: 3, kernel,
        });
        assert.equal(result.verified, false);
        assert.equal(result.applied, false);
        assert.equal(result.disposition, 'refused');
        assert.equal(invalidateCalls, 0);
    });
});
