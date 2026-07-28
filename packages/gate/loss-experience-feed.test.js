// SPDX-License-Identifier: Apache-2.0
// Generated from loss-experience-feed.test.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY, LOSS_EXPERIENCE_FEED_VERSION, signLossExperienceFeed, verifyLossExperienceFeed, } from './loss-experience-feed.js';
import { riskDigest, signRiskBody } from './dist/reliance-risk-crypto.js';
const D = (character) => `sha256:${character.repeat(64)}`;
function fixture() {
    const pair = generateKeyPairSync('ed25519');
    const hostilePair = generateKeyPairSync('ed25519');
    return {
        pair,
        hostilePair,
        trustedKeys: {
            'carrier-key-1': {
                issuer_id: 'carrier:example',
                public_key: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
            },
            'hostile-key-1': {
                issuer_id: 'payer:example',
                public_key: hostilePair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
            },
        },
    };
}
function input() {
    return {
        feed_id: 'loss-feed:2026-07',
        reporting_party_id: 'carrier:example',
        relying_party_id: 'payer:example',
        program: {
            program_id: 'rp.payer.pas.1',
            version: 3,
            source_digest: D('1'),
            program_digest: D('2'),
        },
        period: { start: '2026-07-01T00:00:00Z', end: '2026-08-01T00:00:00Z' },
        census_digest: D('3'),
        source_inventory_digest: D('4'),
        records: [
            {
                record_id: 'loss-event:001',
                receipt_digest: D('5'),
                action_class: 'health.prior-authorization',
                classification: 'LOSS_REPORTED',
                reported_amount_minor: '12500',
                currency: 'USD',
                occurred_at: '2026-07-15T12:00:00Z',
                reported_at: '2026-07-20T12:00:00Z',
                source_record_digest: D('6'),
                event_type: 'OBSERVED',
                supersedes_record_digest: null,
            },
        ],
        issued_at: '2026-08-01T01:00:00Z',
        expires_at: '2026-09-01T01:00:00Z',
        timestamp_anchor: { method: 'scitt', evidence_digest: D('7') },
        claim_boundary: LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY,
    };
}
test('signs privacy-bounded externally reported loss experience and pins its census', () => {
    const { pair, trustedKeys } = fixture();
    const feed = signLossExperienceFeed(input(), {
        issuer_id: 'carrier:example',
        key_id: 'carrier-key-1',
        private_key: pair.privateKey,
    });
    assert.equal(feed['@version'], LOSS_EXPERIENCE_FEED_VERSION);
    assert.equal(verifyLossExperienceFeed(feed, {
        trusted_keys: trustedKeys,
        now: '2026-08-02T00:00:00Z',
        expected_program_digest: D('2'),
        expected_census_digest: D('3'),
    }).accepted, true);
    const tampered = structuredClone(feed);
    tampered.records[0].reported_amount_minor = '999999';
    assert.equal(verifyLossExperienceFeed(tampered, { trusted_keys: trustedKeys }).reason, 'digest_mismatch');
});
test('rejects raw payloads, impossible supersession, future reports, and issuer substitution', () => {
    const { pair } = fixture();
    const signer = {
        issuer_id: 'carrier:example',
        key_id: 'carrier-key-1',
        private_key: pair.privateKey,
    };
    assert.throws(() => signLossExperienceFeed({
        ...input(),
        records: [{ ...input().records[0], raw_claim: { member_id: 'PHI' } }],
    }, signer), /record|field|shape/i);
    assert.throws(() => signLossExperienceFeed({
        ...input(),
        records: [{ ...input().records[0], event_type: 'CORRECTED', supersedes_record_digest: null }],
    }, signer), /supersed/i);
    assert.throws(() => signLossExperienceFeed({
        ...input(),
        records: [{ ...input().records[0], reported_at: '2026-08-02T00:00:00Z' }],
    }, signer), /reported|issued/i);
    assert.throws(() => signLossExperienceFeed(input(), {
        ...signer,
        issuer_id: 'payer:example',
    }), /reporting party/i);
});
test('does not accept loss evidence as coverage, causation, liability, adjudication, solvency, or payment', () => {
    assert.match(LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY, /not_/);
    for (const forbidden of ['verified_causation', 'insurance_coverage', 'legal_liability', 'adjudicated_loss', 'solvency', 'payment']) {
        assert.equal(LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY.includes(forbidden), true);
    }
});
test('feed verification separates a valid signature from reporting-party authority', () => {
    const { hostilePair, trustedKeys } = fixture();
    const hostile = signRiskBody(LOSS_EXPERIENCE_FEED_VERSION, {
        '@version': LOSS_EXPERIENCE_FEED_VERSION,
        ...input(),
    }, {
        issuer_id: 'payer:example',
        key_id: 'hostile-key-1',
        private_key: hostilePair.privateKey,
    });
    assert.deepEqual(verifyLossExperienceFeed(hostile, {
        trusted_keys: trustedKeys,
        now: '2026-08-02T00:00:00Z',
    }), {
        accepted: false,
        verified: true,
        reason: 'reporting_party_issuer_mismatch',
        feed_digest: riskDigest(hostile),
        claim_boundary: LOSS_EXPERIENCE_FEED_CLAIM_BOUNDARY,
    });
});
test('checked-in synthetic loss-experience vector verifies under the pinned reporter key', () => {
    const vector = JSON.parse(readFileSync(fileURLToPath(new URL('../../conformance/vectors/loss-experience-feed.v1.json', import.meta.url)), 'utf8'));
    assert.deepEqual(verifyLossExperienceFeed(vector.artifact, {
        trusted_keys: vector.trusted_keys,
        now: vector.verification_time,
        expected_program_digest: vector.artifact.program.program_digest,
        expected_census_digest: vector.artifact.census_digest,
        expected_relying_party_id: vector.artifact.relying_party_id,
    }), vector.expected);
});
