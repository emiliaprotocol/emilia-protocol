// SPDX-License-Identifier: Apache-2.0
// Generated from reliance-refusal-bridge.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { signRelianceRefusal, relianceRefusalClass, MAPPED_RELIANCE_VERDICTS, } from './reliance-refusal-bridge.js';
import { verifyActionRefusalStatement } from './action-refusal-statement.js';
const keys = crypto.generateKeyPairSync('ed25519');
const SIGNER = { issuer_id: 'rp.example', key_id: 'rp-key-1', private_key: keys.privateKey };
const TRUSTED = {
    'rp-key-1': {
        issuer_id: 'rp.example',
        public_key: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    },
};
const DIGEST = `sha256:${'a'.repeat(64)}`;
const EVIDENCE = `sha256:${'b'.repeat(64)}`;
const CHALLENGE = `sha256:${'c'.repeat(64)}`;
function context(overrides = {}) {
    return {
        decision: { verdict: 'do_not_rely_quorum_unsatisfied', reasons: ['quorum'], allow: false },
        program: {
            program_id: 'payments.high-value',
            version: 1,
            source_digest: `sha256:${'d'.repeat(64)}`,
            program_digest: `sha256:${'e'.repeat(64)}`,
        },
        relying_party_id: 'rp.example',
        caid: 'caid:1:payment.release.1:jcs-sha256:w5frm5Cl8eHeCZ4DMdsVvLGOdP7XByOjOrynopvQYTo',
        action_digest: DIGEST,
        refusal_id: 'refusal-0001',
        nonce: 'nonce-0001',
        refused_at: '2026-07-29T00:00:00Z',
        expires_at: '2026-07-30T00:00:00Z',
        evidence_digests: [EVIDENCE],
        challenge_digest: CHALLENGE,
        failed_requirement_ids: ['requirement.human-quorum'],
        ...overrides,
    };
}
test('a reliance refusal produces a signed statement that verifies offline', () => {
    const statement = signRelianceRefusal(context(), SIGNER);
    const result = verifyActionRefusalStatement(statement, { trusted_keys: TRUSTED, now: '2026-07-29T00:00:01Z' });
    assert.equal(result.accepted, true, JSON.stringify(result.reasons ?? result));
    assert.equal(statement.refusal_class, 'evidence_unsatisfied');
    assert.equal(statement.semantics.satisfaction, 'NOT_SATISFIED');
    assert.deepEqual(statement.failed_requirement_ids, ['requirement.human-quorum']);
});
test('an allow verdict can never be signed as a refusal', () => {
    assert.throws(() => signRelianceRefusal(context({ decision: { verdict: 'rely', allow: true } }), SIGNER), /cannot be signed for an allow verdict/);
    // allow:true must be refused even when the verdict string looks like a denial
    assert.throws(() => signRelianceRefusal(context({ decision: { verdict: 'do_not_rely_unsigned', allow: true } }), SIGNER), /cannot be signed for an allow verdict/);
});
test('every mapped verdict yields semantics the statement validator accepts', () => {
    for (const verdict of MAPPED_RELIANCE_VERDICTS) {
        const statement = signRelianceRefusal(context({ decision: { verdict, allow: false } }), SIGNER);
        const result = verifyActionRefusalStatement(statement, { trusted_keys: TRUSTED, now: '2026-07-29T00:00:01Z' });
        assert.equal(result.accepted, true, `${verdict}: ${JSON.stringify(result.reasons ?? result)}`);
        assert.notEqual(statement.semantics.satisfaction, 'SATISFIED', `${verdict} must not claim satisfaction`);
    }
});
test('an unmapped verdict fails closed to indeterminate rather than borrowing semantics', () => {
    const mapping = relianceRefusalClass('do_not_rely_some_future_verdict');
    assert.equal(mapping.mapped, false);
    assert.equal(mapping.refusal_class, 'indeterminate');
    assert.equal(mapping.semantics.satisfaction, 'INDETERMINATE');
    const statement = signRelianceRefusal(context({ decision: { verdict: 'do_not_rely_some_future_verdict', allow: false } }), SIGNER);
    assert.equal(verifyActionRefusalStatement(statement, { trusted_keys: TRUSTED, now: '2026-07-29T00:00:01Z' }).accepted, true);
    assert.equal(statement.refusal_class, 'indeterminate');
});
test('a tampered refusal statement is rejected', () => {
    const statement = signRelianceRefusal(context(), SIGNER);
    const tampered = { ...statement, action_digest: `sha256:${'f'.repeat(64)}` };
    const result = verifyActionRefusalStatement(tampered, { trusted_keys: TRUSTED, now: '2026-07-29T00:00:01Z' });
    assert.equal(result.accepted, false);
});
test('the caller supplies evidence digests; the bridge never invents them', () => {
    const statement = signRelianceRefusal(context({ evidence_digests: [] }), SIGNER);
    assert.deepEqual(statement.evidence_digests, []);
    assert.equal(verifyActionRefusalStatement(statement, { trusted_keys: TRUSTED, now: '2026-07-29T00:00:01Z' }).accepted, true);
});
test('explicit failed requirement ids are preserved', () => {
    const statement = signRelianceRefusal(context({ failed_requirement_ids: ['admissibility-01', 'admissibility-02'] }), SIGNER);
    assert.deepEqual(statement.failed_requirement_ids, ['admissibility-01', 'admissibility-02']);
    assert.equal(verifyActionRefusalStatement(statement, { trusted_keys: TRUSTED, now: '2026-07-29T00:00:01Z' }).accepted, true);
});
test('the bridge refuses to invent a failed requirement identifier', () => {
    assert.throws(() => signRelianceRefusal(context({ failed_requirement_ids: undefined }), SIGNER), /requires explicit failed requirement ids/);
});
test('scope, policy, and amount failures preserve exact-action MATCH', () => {
    for (const verdict of [
        'do_not_rely_scope_mismatch',
        'do_not_rely_policy_mismatch',
        'do_not_rely_amount_exceeded',
    ]) {
        const mapping = relianceRefusalClass(verdict);
        assert.equal(mapping.refusal_class, 'authorization_refused');
        assert.equal(mapping.semantics.match, 'MATCH');
        assert.equal(mapping.semantics.authorization, 'NOT_AUTHORIZED');
    }
});
test('absence of a reliance profile does not falsely claim verification', () => {
    const mapping = relianceRefusalClass('do_not_rely_no_profile');
    assert.equal(mapping.refusal_class, 'indeterminate');
    assert.equal(mapping.semantics.verification, 'INDETERMINATE');
    assert.equal(mapping.semantics.match, 'INDETERMINATE');
});
