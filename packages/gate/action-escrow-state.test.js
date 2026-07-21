// SPDX-License-Identifier: Apache-2.0
// Generated from action-escrow-state.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import test from 'node:test';
import { ACTION_ESCROW_STATE_STATEMENT_VERSION, createActionEscrowStatePackageVerifier, signActionEscrowStateStatement, verifyActionEscrowStateStatement, } from './action-escrow-state.js';
const NOW = '2026-07-17T18:00:00.000Z';
const hashes = {
    binding: `sha256:${'11'.repeat(32)}`,
    action: `sha256:${'22'.repeat(32)}`,
    profile: `sha256:${'33'.repeat(32)}`,
    amendment: `sha256:${'44'.repeat(32)}`,
    previous: `sha256:${'55'.repeat(32)}`,
};
const stateRecord = {
    agreement_id: 'agreement-kitchen-001',
    state: 'released',
    revision: 7,
    release: {
        provider: 'external-custodian',
        effect_reference: 'release-001',
        status: 'released',
    },
};
function keyPair() {
    const pair = crypto.generateKeyPairSync('ed25519');
    return {
        ...pair,
        publicKeyB64u: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    };
}
function fixture() {
    const key = keyPair();
    const statement = signActionEscrowStateStatement({
        statementId: 'state-001',
        agreementId: 'agreement-kitchen-001',
        bindingDigest: hashes.binding,
        actionDigest: hashes.action,
        profileDigest: hashes.profile,
        state: 'released',
        revision: 7,
        amendmentDigests: [hashes.amendment],
        stateRecord,
        previousStatementDigest: hashes.previous,
        occurredAt: '2026-07-17T17:59:00.000Z',
    }, {
        operatorId: 'operator:emilia-gate',
        keyId: 'key:operator-1',
        privateKey: key.privateKey,
    });
    const opts = {
        trustedKeys: {
            'key:operator-1': {
                operator_id: 'operator:emilia-gate',
                public_key: key.publicKeyB64u,
            },
        },
        stateRecord,
        expectedAgreementId: 'agreement-kitchen-001',
        expectedBindingDigest: hashes.binding,
        expectedActionDigest: hashes.action,
        expectedProfileDigest: hashes.profile,
        expectedState: 'released',
        expectedRevision: 7,
        expectedAmendmentDigests: [hashes.amendment],
        expectedPreviousStatementDigest: hashes.previous,
        now: NOW,
    };
    return { key, statement, opts };
}
test('signs and verifies the exact durable state snapshot under a pinned operator key', () => {
    const { statement, opts } = fixture();
    assert.equal(statement.version, ACTION_ESCROW_STATE_STATEMENT_VERSION);
    const result = verifyActionEscrowStateStatement(statement, opts);
    assert.equal(result.valid, true);
    assert.equal(result.reason, 'verified');
    assert.equal(result.state, 'released');
    assert.equal(result.revision, 7);
    assert.deepEqual(result.amendment_digests, [hashes.amendment]);
    assert.deepEqual(Object.values(result.checks), Array(Object.keys(result.checks).length).fill(true));
});
test('a changed state snapshot is refused even when the statement signature is intact', () => {
    const { statement, opts } = fixture();
    const result = verifyActionEscrowStateStatement(statement, {
        ...opts,
        stateRecord: { ...stateRecord, state: 'release_indeterminate' },
    });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'state_record_digest_mismatch');
});
test('agreement, binding, action, profile, stage, revision, amendment, and predecessor joins fail closed', async (t) => {
    const cases = [
        ['agreement', { expectedAgreementId: 'agreement-attacker' }],
        ['binding', { expectedBindingDigest: `sha256:${'aa'.repeat(32)}` }],
        ['action', { expectedActionDigest: `sha256:${'bb'.repeat(32)}` }],
        ['profile', { expectedProfileDigest: `sha256:${'cc'.repeat(32)}` }],
        ['stage', { expectedState: 'completed' }],
        ['revision', { expectedRevision: 8 }],
        ['amendment', { expectedAmendmentDigests: [] }],
        ['predecessor', { expectedPreviousStatementDigest: null }],
    ];
    for (const [name, override] of cases) {
        await t.test(name, () => {
            const { statement, opts } = fixture();
            const result = verifyActionEscrowStateStatement(statement, { ...opts, ...override });
            assert.equal(result.valid, false);
            assert.equal(result.reason, 'state_expected_binding_mismatch');
        });
    }
});
test('an embedded or cross-operator key cannot establish authority', () => {
    const { statement, opts } = fixture();
    const attacker = keyPair();
    const unpinned = {
        ...statement,
        public_key: attacker.publicKeyB64u,
    };
    assert.equal(verifyActionEscrowStateStatement(unpinned, opts).reason, 'malformed_state_statement');
    const crossed = structuredClone(statement);
    const result = verifyActionEscrowStateStatement(crossed, {
        ...opts,
        trustedKeys: {
            'key:operator-1': {
                operator_id: 'operator:attacker',
                public_key: attacker.publicKeyB64u,
            },
        },
    });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'operator_key_not_pinned');
});
test('signature and statement digest substitution are independently refused', () => {
    const { statement, opts } = fixture();
    const signatureTamper = structuredClone(statement);
    const signatureBytes = Buffer.from(signatureTamper.signature.signature_b64u, 'base64url');
    signatureBytes[0] ^= 0x01;
    signatureTamper.signature.signature_b64u = signatureBytes.toString('base64url');
    assert.equal(verifyActionEscrowStateStatement(signatureTamper, opts).reason, 'state_signature_invalid');
    const digestTamper = structuredClone(statement);
    digestTamper.statement_digest = `sha256:${'ff'.repeat(32)}`;
    assert.equal(verifyActionEscrowStateStatement(digestTamper, opts).reason, 'state_statement_digest_mismatch');
});
test('future and impossible timestamps are refused', () => {
    const { key } = fixture();
    const future = signActionEscrowStateStatement({
        statementId: 'state-future',
        agreementId: 'agreement-kitchen-001',
        bindingDigest: hashes.binding,
        actionDigest: hashes.action,
        profileDigest: hashes.profile,
        state: 'released',
        revision: 7,
        amendmentDigests: [hashes.amendment],
        stateRecord,
        previousStatementDigest: hashes.previous,
        occurredAt: '2026-07-17T19:00:00.000Z',
    }, {
        operatorId: 'operator:emilia-gate',
        keyId: 'key:operator-1',
        privateKey: key.privateKey,
    });
    const opts = fixture().opts;
    opts.trustedKeys['key:operator-1'].public_key = key.publicKeyB64u;
    assert.equal(verifyActionEscrowStateStatement(future, opts).reason, 'state_statement_from_future');
    assert.throws(() => signActionEscrowStateStatement({
        statementId: 'state-impossible',
        agreementId: 'agreement-kitchen-001',
        bindingDigest: hashes.binding,
        actionDigest: hashes.action,
        profileDigest: hashes.profile,
        state: 'released',
        revision: 7,
        amendmentDigests: [],
        stateRecord,
        occurredAt: '2026-02-30T12:00:00.000Z',
    }, {
        operatorId: 'operator:emilia-gate',
        keyId: 'key:operator-1',
        privateKey: key.privateKey,
    }), /input is invalid/);
});
test('hostile values return a typed refusal and never leak thrown details', () => {
    for (const value of [null, [], 'statement', 1, {}]) {
        assert.doesNotThrow(() => verifyActionEscrowStateStatement(value, {}));
        assert.equal(verifyActionEscrowStateStatement(value, {}).valid, false);
    }
    const hostile = {};
    Object.defineProperty(hostile, 'version', {
        enumerable: true,
        get() {
            throw new Error('secret state backend payload');
        },
    });
    const result = verifyActionEscrowStateStatement(hostile, {});
    assert.equal(result.valid, false);
    assert.doesNotMatch(JSON.stringify(result), /secret state backend payload/);
});
test('package verifier binds an embedded snapshot without trusting package keys', async () => {
    const { statement, opts } = fixture();
    const verifyPackaged = createActionEscrowStatePackageVerifier({
        trustedKeys: opts.trustedKeys,
        now: NOW,
        minimumRevision: 7,
    });
    const result = await verifyPackaged({
        snapshot: stateRecord,
        statement,
    }, {
        agreementId: opts.expectedAgreementId,
        bindingDigest: opts.expectedBindingDigest,
        actionDigest: opts.expectedActionDigest,
        profileDigest: opts.expectedProfileDigest,
        amendmentDigests: opts.expectedAmendmentDigests,
        stage: opts.expectedState,
    });
    assert.equal(result.valid, true);
    const staleVerifier = createActionEscrowStatePackageVerifier({
        trustedKeys: opts.trustedKeys,
        now: NOW,
        minimumRevision: 8,
    });
    assert.equal((await staleVerifier({ snapshot: stateRecord, statement }, {})).valid, false);
});
test('package verifier refuses a signed state or revision that contradicts its snapshot', async (t) => {
    const { key, opts } = fixture();
    const verifyPackaged = createActionEscrowStatePackageVerifier({
        trustedKeys: opts.trustedKeys,
        now: NOW,
    });
    for (const [name, state, revision] of [
        ['state', 'completed', stateRecord.revision],
        ['revision', stateRecord.state, stateRecord.revision + 1],
    ]) {
        await t.test(name, async () => {
            const statement = signActionEscrowStateStatement({
                statementId: `state-contradiction-${name}`,
                agreementId: opts.expectedAgreementId,
                bindingDigest: opts.expectedBindingDigest,
                actionDigest: opts.expectedActionDigest,
                profileDigest: opts.expectedProfileDigest,
                state,
                revision,
                amendmentDigests: opts.expectedAmendmentDigests,
                stateRecord,
                previousStatementDigest: opts.expectedPreviousStatementDigest,
                occurredAt: '2026-07-17T17:59:00.000Z',
            }, {
                operatorId: 'operator:emilia-gate',
                keyId: 'key:operator-1',
                privateKey: key.privateKey,
            });
            const result = await verifyPackaged({
                snapshot: stateRecord,
                statement,
            }, {
                agreementId: opts.expectedAgreementId,
                bindingDigest: opts.expectedBindingDigest,
                actionDigest: opts.expectedActionDigest,
                profileDigest: opts.expectedProfileDigest,
                amendmentDigests: opts.expectedAmendmentDigests,
                stage: state,
            });
            assert.equal(result.valid, false);
            assert.equal(result.reason, 'malformed_packaged_state');
        });
    }
});
