// SPDX-License-Identifier: Apache-2.0
/** Governed-taxonomy aggregate receipt census with coarse primary suppression. */
import { RISK_DIGEST, riskDigest, riskExact, riskIdentifier, riskInstant, riskRecord, riskFreeze } from './reliance-risk-crypto.js';
export const RECEIPT_CENSUS_VERSION = 'EP-RECEIPT-CENSUS-v1';
export const RECEIPT_CENSUS_CLAIM_BOUNDARY = 'aggregate_observation_with_primary_suppression_not_differential_privacy_or_identifier_detection_not_causation_coverage_legal_liability_adjudication_solvency_payment_population_completeness_or_authorization';
const PERIOD_KEYS = ['start', 'end'];
const PROGRAM_KEYS = ['program_id', 'version', 'source_digest', 'program_digest'];
const BUCKET_KEYS = ['action_class', 'program_version', 'outcome', 'count', 'open_exposure_amount_minor', 'reported_loss_amount_minor', 'currency'];
const BODY_KEYS = ['@version', 'census_id', 'relying_party_id', 'period', 'program', 'taxonomy_digest', 'minimum_bucket_count', 'buckets', 'suppressed', 'source_inventory_digest', 'generated_at', 'claim_boundary'];
const utf8 = new TextEncoder();
function utf8ByteCompare(left, right) {
    const a = utf8.encode(left);
    const b = utf8.encode(right);
    const length = Math.min(a.length, b.length);
    for (let index = 0; index < length; index += 1) {
        if (a[index] !== b[index])
            return a[index] - b[index];
    }
    return a.length - b.length;
}
function normalizeTaxonomy(value) {
    if (!riskExact(value, ['taxonomy_id', 'allowed_action_classes', 'allowed_outcomes'])
        || !riskIdentifier(value.taxonomy_id)
        || !Array.isArray(value.allowed_action_classes) || value.allowed_action_classes.length < 1
        || value.allowed_action_classes.length > 10_000
        || !value.allowed_action_classes.every(riskIdentifier)
        || new Set(value.allowed_action_classes).size !== value.allowed_action_classes.length
        || !Array.isArray(value.allowed_outcomes) || value.allowed_outcomes.length < 1
        || value.allowed_outcomes.length > 1_000
        || !value.allowed_outcomes.every(riskIdentifier)
        || new Set(value.allowed_outcomes).size !== value.allowed_outcomes.length) {
        throw new TypeError('receipt census taxonomy is invalid');
    }
    return {
        taxonomy_id: value.taxonomy_id,
        allowed_action_classes: [...value.allowed_action_classes].sort(utf8ByteCompare),
        allowed_outcomes: [...value.allowed_outcomes].sort(utf8ByteCompare),
    };
}
export function receiptCensusTaxonomyDigest(taxonomy) {
    return riskDigest(normalizeTaxonomy(taxonomy));
}
function money(value) { return typeof value === 'string' && /^(?:0|[1-9][0-9]{0,39})$/.test(value); }
function validProgram(value) {
    return riskExact(value, PROGRAM_KEYS) && riskIdentifier(value.program_id)
        && Number.isSafeInteger(value.version) && value.version >= 1
        && RISK_DIGEST.test(value.source_digest) && RISK_DIGEST.test(value.program_digest);
}
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
        if (prior !== null && utf8ByteCompare(prior, current) >= 0)
            return false;
        prior = current;
    }
    return true;
}
export function createReceiptCensus(input, taxonomy) {
    const normalizedTaxonomy = normalizeTaxonomy(taxonomy);
    const allowedActionClasses = new Set(normalizedTaxonomy.allowed_action_classes);
    const allowedOutcomes = new Set(normalizedTaxonomy.allowed_outcomes);
    const allowedInput = ['census_id', 'relying_party_id', 'period', 'program', 'minimum_bucket_count', 'buckets', 'source_inventory_digest', 'generated_at'];
    if (!riskExact(input, allowedInput) || !riskIdentifier(input.census_id) || !riskIdentifier(input.relying_party_id)
        || !riskExact(input.period, PERIOD_KEYS) || !validProgram(input.program)
        || !Number.isSafeInteger(input.minimum_bucket_count) || input.minimum_bucket_count < 2
        || input.minimum_bucket_count > 1000 || !Array.isArray(input.buckets) || input.buckets.length > 10_000
        || !input.buckets.every(validBucket) || !RISK_DIGEST.test(input.source_inventory_digest)
        || !Number.isFinite(riskInstant(input.generated_at)))
        throw new TypeError('receipt census input or bucket fields are invalid');
    if (!input.buckets.every((bucket) => allowedActionClasses.has(bucket.action_class)
        && allowedOutcomes.has(bucket.outcome) && bucket.program_version === input.program.version)) {
        throw new TypeError('receipt census bucket is outside the relying-party taxonomy');
    }
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
        .sort((left, right) => utf8ByteCompare(bucketKey(left), bucketKey(right)));
    const hidden = input.buckets.filter((bucket) => bucket.count < input.minimum_bucket_count);
    const body = {
        '@version': RECEIPT_CENSUS_VERSION,
        census_id: input.census_id,
        relying_party_id: input.relying_party_id,
        period: input.period,
        program: input.program,
        taxonomy_digest: riskDigest(normalizedTaxonomy),
        minimum_bucket_count: input.minimum_bucket_count,
        buckets: visible,
        suppressed: { bucket_count: hidden.length, record_count: hidden.reduce((sum, bucket) => sum + bucket.count, 0) },
        source_inventory_digest: input.source_inventory_digest,
        generated_at: input.generated_at,
        claim_boundary: RECEIPT_CENSUS_CLAIM_BOUNDARY,
    };
    return riskFreeze({ ...body, census_digest: riskDigest(body) });
}
export function validateReceiptCensus(value, taxonomy) {
    try {
        if (taxonomy === undefined)
            return { valid: false, reason: 'census_taxonomy_required' };
        const normalizedTaxonomy = normalizeTaxonomy(taxonomy);
        const taxonomyDigest = riskDigest(normalizedTaxonomy);
        const allowedActionClasses = new Set(normalizedTaxonomy.allowed_action_classes);
        const allowedOutcomes = new Set(normalizedTaxonomy.allowed_outcomes);
        if (!riskRecord(value) || !Object.hasOwn(value, 'census_digest'))
            return { valid: false, reason: 'census_shape_invalid' };
        const { census_digest: supplied, ...body } = value;
        if (!riskExact(body, BODY_KEYS) || body['@version'] !== RECEIPT_CENSUS_VERSION
            || !riskIdentifier(body.census_id) || !riskIdentifier(body.relying_party_id)
            || !riskExact(body.period, PERIOD_KEYS) || !validProgram(body.program)
            || body.taxonomy_digest !== taxonomyDigest
            || !Number.isSafeInteger(body.minimum_bucket_count) || body.minimum_bucket_count < 2
            || body.minimum_bucket_count > 1000
            || !Array.isArray(body.buckets) || body.buckets.length > 10_000
            || !body.buckets.every(validBucket)
            || !body.buckets.every((bucket) => allowedActionClasses.has(bucket.action_class)
                && allowedOutcomes.has(bucket.outcome) && bucket.program_version === body.program.version)
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