// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/** Privacy-bounded aggregate receipt census and externally reported loss experience. */
import { RISK_DIGEST, riskDigest, riskExact, riskIdentifier, riskInstant, riskRecord, riskFreeze } from './reliance-risk-crypto.js';
export const RECEIPT_CENSUS_VERSION = 'EP-RECEIPT-CENSUS-v1';
export const RECEIPT_CENSUS_CLAIM_BOUNDARY = 'aggregate_observation_not_causation_coverage_or_adjudication';
const PERIOD_KEYS = ['start', 'end'];
const BUCKET_KEYS = ['action_class', 'program_version', 'outcome', 'count', 'open_exposure_amount_minor', 'reported_loss_amount_minor', 'currency'];
const BODY_KEYS = ['@version', 'census_id', 'relying_party_id', 'period', 'program_digest', 'minimum_bucket_count', 'buckets', 'suppressed', 'source_inventory_digest', 'generated_at', 'claim_boundary'];
function money(value) { return typeof value === 'string' && /^(?:0|[1-9][0-9]{0,39})$/.test(value); }
function validBucket(value) {
    return riskExact(value, BUCKET_KEYS) && riskIdentifier(value.action_class)
        && Number.isSafeInteger(value.program_version) && value.program_version >= 1
        && riskIdentifier(value.outcome) && Number.isSafeInteger(value.count) && value.count >= 0
        && money(value.open_exposure_amount_minor) && money(value.reported_loss_amount_minor)
        && typeof value.currency === 'string' && /^[A-Z]{3}$/.test(value.currency);
}
function bucketKey(bucket) {
    return JSON.stringify([
        bucket.action_class,
        bucket.program_version,
        bucket.outcome,
        bucket.currency,
    ]);
}
function uniqueSortedBuckets(buckets) {
    let prior = null;
    for (const bucket of buckets) {
        const current = bucketKey(bucket);
        if (prior !== null && prior >= current)
            return false;
        prior = current;
    }
    return true;
}
export function createReceiptCensus(input) {
    const allowedInput = ['census_id', 'relying_party_id', 'period', 'program_digest', 'minimum_bucket_count', 'buckets', 'source_inventory_digest', 'generated_at'];
    if (!riskExact(input, allowedInput) || !riskIdentifier(input.census_id) || !riskIdentifier(input.relying_party_id)
        || !riskExact(input.period, PERIOD_KEYS) || !RISK_DIGEST.test(input.program_digest)
        || !Number.isSafeInteger(input.minimum_bucket_count) || input.minimum_bucket_count < 2
        || input.minimum_bucket_count > 1000 || !Array.isArray(input.buckets) || input.buckets.length > 10_000
        || !input.buckets.every(validBucket) || !RISK_DIGEST.test(input.source_inventory_digest)
        || !Number.isFinite(riskInstant(input.generated_at)))
        throw new TypeError('receipt census input or bucket fields are invalid');
    const start = riskInstant(input.period.start);
    const end = riskInstant(input.period.end);
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start || riskInstant(input.generated_at) < end) {
        throw new TypeError('receipt census period is invalid');
    }
    const keys = input.buckets.map((bucket) => bucketKey(bucket));
    if (new Set(keys).size !== keys.length)
        throw new TypeError('receipt census contains duplicate bucket identities');
    const visible = input.buckets
        .filter((bucket) => bucket.count >= input.minimum_bucket_count)
        .map((bucket) => ({ ...bucket }))
        .sort((left, right) => bucketKey(left).localeCompare(bucketKey(right)));
    const hidden = input.buckets.filter((bucket) => bucket.count < input.minimum_bucket_count);
    const body = {
        '@version': RECEIPT_CENSUS_VERSION,
        census_id: input.census_id,
        relying_party_id: input.relying_party_id,
        period: input.period,
        program_digest: input.program_digest,
        minimum_bucket_count: input.minimum_bucket_count,
        buckets: visible,
        suppressed: { bucket_count: hidden.length, record_count: hidden.reduce((sum, bucket) => sum + bucket.count, 0) },
        source_inventory_digest: input.source_inventory_digest,
        generated_at: input.generated_at,
        claim_boundary: RECEIPT_CENSUS_CLAIM_BOUNDARY,
    };
    return riskFreeze({ ...body, census_digest: riskDigest(body) });
}
export function validateReceiptCensus(value) {
    try {
        if (!riskRecord(value) || !Object.hasOwn(value, 'census_digest'))
            return { valid: false, reason: 'census_shape_invalid' };
        const { census_digest: supplied, ...body } = value;
        if (!riskExact(body, BODY_KEYS) || body['@version'] !== RECEIPT_CENSUS_VERSION
            || !riskIdentifier(body.census_id) || !riskIdentifier(body.relying_party_id)
            || !riskExact(body.period, PERIOD_KEYS) || !RISK_DIGEST.test(body.program_digest)
            || !Number.isSafeInteger(body.minimum_bucket_count) || body.minimum_bucket_count < 2
            || body.minimum_bucket_count > 1000
            || !Array.isArray(body.buckets) || body.buckets.length > 10_000
            || !body.buckets.every(validBucket)
            || !body.buckets.every((bucket) => bucket.count >= body.minimum_bucket_count)
            || !uniqueSortedBuckets(body.buckets)
            || !riskExact(body.suppressed, ['bucket_count', 'record_count'])
            || !Number.isSafeInteger(body.suppressed.bucket_count) || body.suppressed.bucket_count < 0
            || !Number.isSafeInteger(body.suppressed.record_count) || body.suppressed.record_count < 0
            || !RISK_DIGEST.test(body.source_inventory_digest)
            || !Number.isFinite(riskInstant(body.generated_at))
            || body.claim_boundary !== RECEIPT_CENSUS_CLAIM_BOUNDARY
            || !RISK_DIGEST.test(supplied) || riskDigest(body) !== supplied)
            return { valid: false, reason: 'census_integrity_invalid' };
        const start = riskInstant(body.period.start);
        const end = riskInstant(body.period.end);
        if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start
            || riskInstant(body.generated_at) < end)
            return { valid: false, reason: 'census_period_invalid' };
        return { valid: true, reason: null, census_digest: supplied };
    }
    catch {
        return { valid: false, reason: 'census_invalid' };
    }
}
//# sourceMappingURL=receipt-census.js.map