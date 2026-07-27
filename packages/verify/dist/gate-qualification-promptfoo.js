// SPDX-License-Identifier: Apache-2.0
/**
 * Strict Promptfoo upstream-evidence adapter for Gate Qualification v2.
 *
 * Promptfoo evaluates a candidate. It does not authorize that candidate to
 * execute a consequential action. This adapter therefore emits only an
 * immutable EVALUATION_ONLY evidence input. A separate Qualification v2
 * evaluator and relying-party policy must decide what, if anything, the
 * evidence satisfies.
 *
 * The accepted artifact is Promptfoo's version-3 JSON OutputFile envelope plus
 * an EMILIA metadata extension. All trust, lineage, coverage, and freshness
 * inputs are supplied out of band and pinned by the relying party. The adapter
 * has no network or ambient "latest" resolution.
 */
import crypto from 'node:crypto';
export const PROMPTFOO_QUALIFICATION_ADAPTER_VERSION = 'EP-GATE-QUALIFICATION-PROMPTFOO-ADAPTER-v1';
export const PROMPTFOO_QUALIFICATION_RUN_METADATA_VERSION = 'EP-GATE-QUALIFICATION-PROMPTFOO-RUN-v1';
export const PROMPTFOO_QUALIFICATION_EVIDENCE_VERSION = 'EP-GATE-QUALIFICATION-EVALUATION-EVIDENCE-v2';
export const PROMPTFOO_QUALIFICATION_LIMITS = Object.freeze({
    max_input_bytes: 8 * 1024 * 1024,
    max_input_nodes: 65_536,
    max_input_depth: 32,
    max_summary_results: 100_000,
});
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const ID_RE = /^[A-Za-z0-9_.:-]{1,256}$/;
const EXACT_SEMVER_RE = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const MUTABLE_ALIAS_RE = /(?:^|[/:@._-])(?:latest|current|default|stable|head|main|master|nightly|canary)(?:$|[/:@._-])/i;
const MAX_ATTEMPTS = PROMPTFOO_QUALIFICATION_LIMITS.max_summary_results;
const MAX_COST = 1_000_000_000;
const MAX_LATENCY_MS = 86_400_000;
const MAX_AGE_SECONDS = 31_536_000;
const PIN_KEYS = new Set([
    '@version',
    'eval_id',
    'artifact_ref',
    'artifact_digest',
    'promptfoo_version',
    'output_version',
    'candidate',
    'assignment',
    'harness',
    'environment',
    'challenge_campaign',
    'verifier',
    'quality_metrics',
    'max_evidence_age_seconds',
]);
const MANIFEST_PIN_KEYS = new Set([
    'id',
    'immutable_ref',
    'manifest',
    'manifest_digest',
]);
const HARNESS_PIN_KEYS = new Set([
    ...MANIFEST_PIN_KEYS,
    'config_digest',
]);
const VERIFIER_PIN_KEYS = new Set([
    'id',
    'immutable_ref',
    'trust_config',
    'trust_config_digest',
]);
const CANDIDATE_MANIFEST_KEYS = new Set([
    'provider_id',
    'provider_revision',
    'prompt_id',
    'prompt_digest',
]);
const CAMPAIGN_MANIFEST_KEYS = new Set([
    'challenge_set_digest',
    'attempts',
]);
const CAMPAIGN_ATTEMPT_KEYS = new Set([
    'attempt_id',
    'challenge_id',
    'ordinal',
    'challenge_digest',
]);
const OUTPUT_FILE_KEYS = new Set([
    'evalId',
    'results',
    'config',
    'shareableUrl',
    'metadata',
]);
const SUMMARY_KEYS = new Set([
    'version',
    'timestamp',
    'stats',
    'prompts',
    'results',
]);
const STATS_KEYS = new Set([
    'successes',
    'failures',
    'errors',
    'tokenUsage',
    'durationMs',
    'generationDurationMs',
    'evaluationDurationMs',
]);
const TOKEN_USAGE_KEYS = new Set([
    'total',
    'prompt',
    'completion',
    'cached',
]);
const RESULT_KEYS = new Set([
    'id',
    'description',
    'promptIdx',
    'testIdx',
    'testCase',
    'promptId',
    'provider',
    'prompt',
    'vars',
    'response',
    'error',
    'failureReason',
    'success',
    'score',
    'latencyMs',
    'gradingResult',
    'namedScores',
    'cost',
    'metadata',
    'tokenUsage',
    'evaluationId',
]);
const PROVIDER_KEYS = new Set(['id', 'label']);
const PROMPT_KEYS = new Set(['raw', 'label']);
const RESPONSE_KEYS = new Set([
    'output',
    'tokenUsage',
    'error',
    'cached',
    'cost',
    'metadata',
    'isRefusal',
    'logProbs',
]);
const GRADING_KEYS = new Set([
    'pass',
    'score',
    'reason',
    'namedScores',
    'namedScoreWeights',
    'tokensUsed',
    'componentResults',
    'assertion',
    'comment',
    'suggestions',
    'metadata',
]);
const METADATA_KEYS = new Set(['emilia_gate_qualification_v2']);
const ATTEMPT_METADATA_KEYS = new Set([
    'attempt_id',
    'challenge_id',
    'ordinal',
    'status',
    'started_at',
    'completed_at',
    'expired_at',
    'request_payload_digest',
    'response_payload_digest',
    'test_case_digest',
]);
const RUN_METADATA_KEYS = new Set([
    '@version',
    'promptfoo_version',
    'candidate',
    'assignment',
    'harness',
    'environment',
    'challenge_campaign',
    'verifier',
    'started_at',
    'completed_at',
    'expires_at',
    'attempt_counts',
]);
const RUN_LINEAGE_KEYS = new Set(['id', 'digest']);
const RUN_HARNESS_KEYS = new Set(['id', 'digest', 'config_digest']);
const RUN_VERIFIER_KEYS = new Set(['id', 'trust_config_digest']);
const ATTEMPT_COUNT_KEYS = new Set([
    'expected',
    'observed',
    'passed',
    'failed',
    'errors',
    'aborted',
    'expired',
]);
const STATUSES = new Set([
    'PASS',
    'FAIL',
    'ERROR',
    'ABORTED',
    'EXPIRED',
]);
function isObject(value) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function validUnicode(value) {
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (next < 0xdc00 || next > 0xdfff)
                return false;
            index += 1;
        }
        else if (code >= 0xdc00 && code <= 0xdfff) {
            return false;
        }
    }
    return true;
}
function dataPropertyValue(value, key) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined)
        return { inspectable: true, value: undefined };
    if (!Object.hasOwn(descriptor, 'value'))
        return { inspectable: false };
    return { inspectable: true, value: descriptor.value };
}
function summaryResultsLimitReason(value) {
    try {
        if (!isObject(value))
            return null;
        const artifactProperty = dataPropertyValue(value, 'artifact');
        if (!artifactProperty.inspectable || !isObject(artifactProperty.value))
            return null;
        const resultsProperty = dataPropertyValue(artifactProperty.value, 'results');
        if (!resultsProperty.inspectable || !isObject(resultsProperty.value))
            return null;
        const summaryResultsProperty = dataPropertyValue(resultsProperty.value, 'results');
        if (!summaryResultsProperty.inspectable)
            return null;
        return Array.isArray(summaryResultsProperty.value)
            && summaryResultsProperty.value.length
                > PROMPTFOO_QUALIFICATION_LIMITS.max_summary_results
            ? 'summary_results_limit_exceeded'
            : null;
    }
    catch {
        return 'input_not_inspectable';
    }
}
function aggregateInputLimitReason(value) {
    const stack = [{ value, depth: 0 }];
    let bytes = 0;
    let nodes = 0;
    const addBytes = (amount) => {
        bytes += amount;
        return bytes > PROMPTFOO_QUALIFICATION_LIMITS.max_input_bytes;
    };
    try {
        while (stack.length > 0) {
            const current = stack.pop();
            nodes += 1;
            if (nodes > PROMPTFOO_QUALIFICATION_LIMITS.max_input_nodes) {
                return 'input_nodes_limit_exceeded';
            }
            if (current.depth > PROMPTFOO_QUALIFICATION_LIMITS.max_input_depth) {
                return 'input_depth_limit_exceeded';
            }
            if (current.value === null) {
                if (addBytes(4))
                    return 'input_bytes_limit_exceeded';
                continue;
            }
            if (typeof current.value === 'boolean') {
                if (addBytes(current.value ? 4 : 5))
                    return 'input_bytes_limit_exceeded';
                continue;
            }
            if (typeof current.value === 'string') {
                const rawBytes = Buffer.byteLength(current.value, 'utf8');
                if (rawBytes + 2 > PROMPTFOO_QUALIFICATION_LIMITS.max_input_bytes - bytes) {
                    return 'input_bytes_limit_exceeded';
                }
                if (addBytes(Buffer.byteLength(JSON.stringify(current.value), 'utf8'))) {
                    return 'input_bytes_limit_exceeded';
                }
                continue;
            }
            if (typeof current.value === 'number') {
                const encoded = Number.isFinite(current.value)
                    ? JSON.stringify(Object.is(current.value, -0) ? 0 : current.value)
                    : 'null';
                if (addBytes(Buffer.byteLength(encoded, 'utf8'))) {
                    return 'input_bytes_limit_exceeded';
                }
                continue;
            }
            if (typeof current.value !== 'object' || current.value === undefined) {
                continue;
            }
            const keys = Object.keys(current.value);
            if (Array.isArray(current.value)) {
                if (current.value.length > PROMPTFOO_QUALIFICATION_LIMITS.max_input_nodes - nodes) {
                    return 'input_nodes_limit_exceeded';
                }
                if (addBytes(2 + Math.max(0, current.value.length - 1))) {
                    return 'input_bytes_limit_exceeded';
                }
                if (keys.length !== current.value.length
                    || keys.some((key) => !/^(0|[1-9][0-9]*)$/.test(key))) {
                    continue;
                }
                for (let index = current.value.length - 1; index >= 0; index -= 1) {
                    const child = dataPropertyValue(current.value, String(index));
                    if (!child.inspectable)
                        return 'input_not_inspectable';
                    stack.push({ value: child.value, depth: current.depth + 1 });
                }
                continue;
            }
            if (!isObject(current.value))
                continue;
            if (keys.length > PROMPTFOO_QUALIFICATION_LIMITS.max_input_nodes - nodes) {
                return 'input_nodes_limit_exceeded';
            }
            if (addBytes(2 + Math.max(0, keys.length - 1))) {
                return 'input_bytes_limit_exceeded';
            }
            keys.sort();
            for (let index = keys.length - 1; index >= 0; index -= 1) {
                const key = keys[index];
                const rawKeyBytes = Buffer.byteLength(key, 'utf8');
                if (rawKeyBytes + 2 > PROMPTFOO_QUALIFICATION_LIMITS.max_input_bytes - bytes) {
                    return 'input_bytes_limit_exceeded';
                }
                if (addBytes(Buffer.byteLength(JSON.stringify(key), 'utf8') + 1)) {
                    return 'input_bytes_limit_exceeded';
                }
                const child = dataPropertyValue(current.value, key);
                if (!child.inspectable)
                    return 'input_not_inspectable';
                stack.push({ value: child.value, depth: current.depth + 1 });
            }
        }
        return null;
    }
    catch {
        return 'input_not_inspectable';
    }
}
function adapterInputLimitReason(value) {
    return summaryResultsLimitReason(value) ?? aggregateInputLimitReason(value);
}
function canonicalize(value, seen = new WeakSet()) {
    if (value === null)
        return 'null';
    if (typeof value === 'boolean')
        return value ? 'true' : 'false';
    if (typeof value === 'string') {
        if (!validUnicode(value))
            throw new TypeError('invalid Unicode scalar value');
        return JSON.stringify(value);
    }
    if (typeof value === 'number') {
        if (!Number.isFinite(value))
            throw new TypeError('non-finite number');
        if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
            throw new TypeError('unsafe integer');
        }
        return JSON.stringify(Object.is(value, -0) ? 0 : value);
    }
    if (typeof value !== 'object' || value === undefined) {
        throw new TypeError('value is not JSON');
    }
    if (seen.has(value))
        throw new TypeError('cyclic value');
    seen.add(value);
    let output;
    if (Array.isArray(value)) {
        if (Object.keys(value).some((key) => !/^(0|[1-9][0-9]*)$/.test(key))
            || Object.keys(value).length !== value.length) {
            throw new TypeError('sparse or decorated array');
        }
        output = `[${value.map((entry) => canonicalize(entry, seen)).join(',')}]`;
    }
    else {
        if (!isObject(value))
            throw new TypeError('non-plain object');
        const keys = Object.keys(value);
        for (const key of keys) {
            if (!validUnicode(key) || key === '__proto__' || key === 'prototype'
                || key === 'constructor') {
                throw new TypeError('unsafe object member');
            }
        }
        keys.sort();
        output = `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key], seen)}`).join(',')}}`;
    }
    seen.delete(value);
    return output;
}
/**
 * Canonical SHA-256 used for every adapter pin and derived payload binding.
 * It accepts finite JSON numbers because Promptfoo costs and quality scores are
 * commonly fractional.
 */
export function digestPromptfooQualification(value) {
    const limitReason = aggregateInputLimitReason(value);
    if (limitReason !== null)
        throw new TypeError(limitReason);
    const bytes = Buffer.from(canonicalize(value), 'utf8');
    return `sha256:${crypto.createHash('sha256').update(bytes).digest('hex')}`;
}
function digestPromptBytes(value) {
    return `sha256:${crypto.createHash('sha256').update(Buffer.from(value, 'utf8')).digest('hex')}`;
}
function jsonClone(value) {
    return JSON.parse(canonicalize(value));
}
function deepFreeze(value) {
    if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
        Object.freeze(value);
        for (const child of Object.values(value)) {
            deepFreeze(child);
        }
    }
    return value;
}
function addReason(reasons, reason) {
    if (!reasons.includes(reason))
        reasons.push(reason);
}
function exactKeys(value, allowed, reasons) {
    if (!isObject(value))
        return false;
    if (Object.keys(value).some((key) => !allowed.has(key))) {
        addReason(reasons, 'unsupported_field');
        return false;
    }
    return true;
}
function validDigest(value) {
    return typeof value === 'string' && DIGEST_RE.test(value);
}
function validId(value) {
    return typeof value === 'string' && ID_RE.test(value);
}
function validCount(value) {
    return Number.isSafeInteger(value)
        && value >= 0
        && value <= MAX_ATTEMPTS;
}
function validBoundedNumber(value, minimum, maximum) {
    return typeof value === 'number'
        && Number.isFinite(value)
        && value >= minimum
        && value <= maximum;
}
function instant(value) {
    if (typeof value !== 'string' || !RFC3339_RE.test(value))
        return Number.NaN;
    const parsed = Date.parse(value);
    if (!Number.isFinite(parsed))
        return Number.NaN;
    const canonical = new Date(parsed).toISOString();
    const expected = value.includes('.')
        ? canonical
        : canonical.replace('.000Z', 'Z');
    return expected === value ? parsed : Number.NaN;
}
function mutableAlias(value) {
    return MUTABLE_ALIAS_RE.test(value)
        || /[*~^<>=|\s]/.test(value)
        || value.endsWith('@latest');
}
function immutableRef(kind, id, digest, value) {
    return typeof id === 'string'
        && typeof digest === 'string'
        && typeof value === 'string'
        && !mutableAlias(value)
        && value === `${kind}:${id}@${digest}`;
}
function safeDigest(value, mismatchReason, reasons) {
    try {
        return digestPromptfooQualification(value);
    }
    catch {
        addReason(reasons, mismatchReason);
        return null;
    }
}
function validateManifestPin(pin, kind, reasons, allowedKeys = MANIFEST_PIN_KEYS) {
    if (!exactKeys(pin, allowedKeys, reasons)
        || !validId(pin.id)
        || !validDigest(pin.manifest_digest)) {
        addReason(reasons, `invalid_pin:${kind}`);
        return false;
    }
    const digest = safeDigest(pin.manifest, `${kind}_manifest_digest_mismatch`, reasons);
    if (digest !== pin.manifest_digest) {
        addReason(reasons, `${kind}_manifest_digest_mismatch`);
    }
    if (!immutableRef(kind, pin.id, pin.manifest_digest, pin.immutable_ref)) {
        addReason(reasons, `mutable_or_unpinned_ref:${kind}`);
    }
    return true;
}
function validateTokenUsage(value) {
    return isObject(value)
        && Object.keys(value).every((key) => TOKEN_USAGE_KEYS.has(key))
        && Object.keys(value).length === TOKEN_USAGE_KEYS.size
        && validCount(value.total)
        && validCount(value.prompt)
        && validCount(value.completion)
        && validCount(value.cached)
        && value.total === value.prompt + value.completion
        && value.cached <= value.prompt;
}
function addTokenUsage(left, right) {
    return {
        total: left.total + right.total,
        prompt: left.prompt + right.prompt,
        completion: left.completion + right.completion,
        cached: left.cached + right.cached,
    };
}
function sameTokenUsage(left, right) {
    return validateTokenUsage(left)
        && left.total === right.total
        && left.prompt === right.prompt
        && left.completion === right.completion
        && left.cached === right.cached;
}
function challengeDigestPayload(row) {
    const requestDigest = digestPromptfooQualification({
        prompt: row.prompt,
        vars: row.vars,
    });
    return {
        prompt_id: row.promptId,
        provider: row.provider,
        prompt: row.prompt,
        vars: row.vars,
        test_case_digest: digestPromptfooQualification(row.testCase),
        request_payload_digest: requestDigest,
    };
}
/**
 * Re-derive the challenge digest represented by one Promptfoo result row.
 * The result's mutable outcome fields are intentionally excluded.
 */
export function promptfooQualificationChallengeDigest(row) {
    if (!isObject(row))
        throw new TypeError('Promptfoo result row must be an object');
    return digestPromptfooQualification(challengeDigestPayload(row));
}
function runLineage(run, field, allowed, reasons) {
    const value = run[field];
    if (value === undefined) {
        addReason(reasons, `run_lineage_missing:${field}`);
        return null;
    }
    if (!exactKeys(value, allowed, reasons)) {
        addReason(reasons, `run_lineage_invalid:${field}`);
        return null;
    }
    return value;
}
function compareRunLineage(field, runValue, pin, reasons) {
    if (runValue === null || pin === null)
        return;
    if (runValue.id !== pin.id || runValue.digest !== pin.manifest_digest) {
        addReason(reasons, `run_lineage_mismatch:${field}`);
    }
}
function statusCounts(attempts) {
    const counts = {
        passed: 0,
        failed: 0,
        errors: 0,
        aborted: 0,
        expired: 0,
    };
    for (const attempt of attempts) {
        if (attempt.status === 'PASS')
            counts.passed += 1;
        else if (attempt.status === 'FAIL')
            counts.failed += 1;
        else if (attempt.status === 'ERROR')
            counts.errors += 1;
        else if (attempt.status === 'ABORTED')
            counts.aborted += 1;
        else
            counts.expired += 1;
    }
    return counts;
}
function statusConsistent(row, metadata, status, tokenUsage, cost, latencyMs) {
    const success = row.success === true;
    const errorIsNull = row.error === null;
    const errorPresent = typeof row.error === 'string' && row.error.length > 0;
    const hasResponse = row.response !== undefined;
    const expiredAt = metadata.expired_at;
    if (status === 'PASS') {
        return success && errorIsNull && row.failureReason === 'none'
            && hasResponse && expiredAt === null;
    }
    if (status === 'FAIL') {
        return !success && errorIsNull && row.failureReason !== 'none'
            && hasResponse && expiredAt === null;
    }
    if (status === 'ERROR') {
        return !success && errorPresent && row.failureReason !== 'none'
            && expiredAt === null;
    }
    const emptyMeasurements = cost === 0
        && latencyMs === 0
        && row.score === 0
        && row.gradingResult === null
        && tokenUsage.total === 0
        && tokenUsage.prompt === 0
        && tokenUsage.completion === 0
        && tokenUsage.cached === 0;
    if (status === 'ABORTED') {
        return !success && errorPresent && !hasResponse && expiredAt === null
            && emptyMeasurements;
    }
    return !success && errorPresent && !hasResponse
        && typeof expiredAt === 'string'
        && expiredAt === metadata.completed_at
        && emptyMeasurements;
}
function validateResultBoundary(row, reasons) {
    exactKeys(row, RESULT_KEYS, reasons);
    if (isObject(row.provider))
        exactKeys(row.provider, PROVIDER_KEYS, reasons);
    if (isObject(row.prompt))
        exactKeys(row.prompt, PROMPT_KEYS, reasons);
    if (isObject(row.response))
        exactKeys(row.response, RESPONSE_KEYS, reasons);
    if (isObject(row.gradingResult)) {
        exactKeys(row.gradingResult, GRADING_KEYS, reasons);
    }
    if (isObject(row.metadata))
        exactKeys(row.metadata, METADATA_KEYS, reasons);
}
function normalizeAttempt(rowValue, index, evalId, candidate, qualityMetrics, runStarted, runCompleted, reasons) {
    if (!isObject(rowValue)) {
        addReason(reasons, `result_schema_invalid:${index}`);
        return null;
    }
    const row = rowValue;
    validateResultBoundary(row, reasons);
    if (!isObject(row.metadata)
        || !exactKeys(row.metadata, METADATA_KEYS, reasons)
        || !isObject(row.metadata.emilia_gate_qualification_v2)
        || !exactKeys(row.metadata.emilia_gate_qualification_v2, ATTEMPT_METADATA_KEYS, reasons)) {
        addReason(reasons, `attempt_metadata_invalid:${index}`);
        return null;
    }
    const metadata = row.metadata.emilia_gate_qualification_v2;
    const attemptId = metadata.attempt_id;
    const challengeId = metadata.challenge_id;
    if (!validId(attemptId) || !validId(challengeId)
        || !Number.isSafeInteger(metadata.ordinal)
        || metadata.ordinal < 1
        || metadata.ordinal > MAX_ATTEMPTS
        || typeof metadata.status !== 'string'
        || !STATUSES.has(metadata.status)) {
        addReason(reasons, `attempt_metadata_invalid:${index}`);
        return null;
    }
    const typedAttemptId = attemptId;
    const status = metadata.status;
    if (row.evaluationId !== evalId) {
        addReason(reasons, `result_eval_id_mismatch:${typedAttemptId}`);
    }
    const providerId = isObject(row.provider) ? row.provider.id : null;
    if (providerId !== candidate.manifest.provider_id) {
        addReason(reasons, `candidate_provider_mismatch:${typedAttemptId}`);
    }
    if (row.promptId !== candidate.manifest.prompt_id) {
        addReason(reasons, `candidate_prompt_mismatch:${typedAttemptId}`);
    }
    if (!isObject(row.provider)
        || typeof row.provider.id !== 'string'
        || typeof row.provider.label !== 'string'
        || !isObject(row.prompt)
        || typeof row.prompt.raw !== 'string'
        || typeof row.prompt.label !== 'string'
        || !isObject(row.vars)
        || typeof row.failureReason !== 'string'
        || typeof row.success !== 'boolean') {
        addReason(reasons, `result_schema_invalid:${typedAttemptId}`);
    }
    if (isObject(row.prompt) && typeof row.prompt.raw === 'string'
        && digestPromptBytes(row.prompt.raw) !== candidate.manifest.prompt_digest) {
        addReason(reasons, `candidate_prompt_digest_mismatch:${typedAttemptId}`);
    }
    if (!validBoundedNumber(row.cost, 0, MAX_COST)) {
        addReason(reasons, `attempt_cost_invalid:${typedAttemptId}`);
    }
    if (!validBoundedNumber(row.latencyMs, 0, MAX_LATENCY_MS)) {
        addReason(reasons, `attempt_latency_invalid:${typedAttemptId}`);
    }
    if (!validBoundedNumber(row.score, 0, 1)) {
        addReason(reasons, `attempt_quality_invalid:${typedAttemptId}`);
    }
    if (!validateTokenUsage(row.tokenUsage)) {
        addReason(reasons, `attempt_token_usage_invalid:${typedAttemptId}`);
    }
    if (!isObject(row.namedScores)
        || Object.keys(row.namedScores).sort().join('\0')
            !== [...qualityMetrics].sort().join('\0')
        || Object.values(row.namedScores).some((value) => !validBoundedNumber(value, 0, 1))) {
        addReason(reasons, `attempt_quality_metrics_mismatch:${typedAttemptId}`);
    }
    const startedAt = instant(metadata.started_at);
    const completedAt = instant(metadata.completed_at);
    const expiredAt = metadata.expired_at === null
        ? null
        : instant(metadata.expired_at);
    if (!Number.isFinite(startedAt)
        || !Number.isFinite(completedAt)
        || startedAt > completedAt
        || startedAt < runStarted
        || completedAt > runCompleted
        || (expiredAt !== null && !Number.isFinite(expiredAt))) {
        addReason(reasons, `attempt_timestamp_invalid:${typedAttemptId}`);
    }
    let requestDigest = null;
    let responseDigest = null;
    let testCaseDigest = null;
    let gradingDigest = null;
    let resultDigest = null;
    try {
        requestDigest = digestPromptfooQualification({
            prompt: row.prompt,
            vars: row.vars,
        });
        responseDigest = row.response === undefined
            ? null
            : isObject(row.response) && Object.hasOwn(row.response, 'output')
                ? digestPromptfooQualification(row.response.output)
                : null;
        testCaseDigest = digestPromptfooQualification(row.testCase);
        gradingDigest = row.gradingResult === null
            ? null
            : digestPromptfooQualification(row.gradingResult);
        resultDigest = digestPromptfooQualification(row);
    }
    catch {
        addReason(reasons, `attempt_payload_not_canonicalizable:${typedAttemptId}`);
    }
    if (isObject(row.response) && !Object.hasOwn(row.response, 'output')) {
        addReason(reasons, `response_payload_missing:${typedAttemptId}`);
    }
    if (requestDigest === null
        || metadata.request_payload_digest !== requestDigest) {
        addReason(reasons, `request_payload_digest_mismatch:${typedAttemptId}`);
    }
    if (metadata.response_payload_digest !== responseDigest) {
        addReason(reasons, `response_payload_digest_mismatch:${typedAttemptId}`);
    }
    if (testCaseDigest === null
        || metadata.test_case_digest !== testCaseDigest) {
        addReason(reasons, `test_case_digest_mismatch:${typedAttemptId}`);
    }
    const cost = typeof row.cost === 'number' ? row.cost : 0;
    const latencyMs = typeof row.latencyMs === 'number' ? row.latencyMs : 0;
    const score = typeof row.score === 'number' ? row.score : 0;
    const tokenUsage = validateTokenUsage(row.tokenUsage)
        ? {
            total: row.tokenUsage.total,
            prompt: row.tokenUsage.prompt,
            completion: row.tokenUsage.completion,
            cached: row.tokenUsage.cached,
        }
        : { total: 0, prompt: 0, completion: 0, cached: 0 };
    if (isObject(row.response)
        && row.response.tokenUsage !== undefined
        && !sameTokenUsage(row.response.tokenUsage, tokenUsage)) {
        addReason(reasons, `response_token_usage_mismatch:${typedAttemptId}`);
    }
    if (isObject(row.response)
        && row.response.cost !== undefined
        && row.response.cost !== cost) {
        addReason(reasons, `response_cost_mismatch:${typedAttemptId}`);
    }
    const namedScores = {};
    if (isObject(row.namedScores)) {
        for (const metric of qualityMetrics) {
            const value = row.namedScores[metric];
            namedScores[metric] = typeof value === 'number' ? value : 0;
        }
    }
    if (row.gradingResult !== null) {
        if (!isObject(row.gradingResult)
            || typeof row.gradingResult.pass !== 'boolean'
            || !validBoundedNumber(row.gradingResult.score, 0, 1)
            || typeof row.gradingResult.reason !== 'string'
            || row.gradingResult.pass !== (status === 'PASS')
            || row.gradingResult.score !== score
            || (row.gradingResult.namedScores !== undefined
                && (!isObject(row.gradingResult.namedScores)
                    || safeDigest(row.gradingResult.namedScores, `grading_quality_mismatch:${typedAttemptId}`, reasons) !== safeDigest(namedScores, `grading_quality_mismatch:${typedAttemptId}`, reasons)))) {
            addReason(reasons, `grading_quality_mismatch:${typedAttemptId}`);
        }
    }
    if (!statusConsistent(row, metadata, status, tokenUsage, cost, latencyMs)) {
        addReason(reasons, `attempt_status_inconsistent:${typedAttemptId}`);
    }
    let challengeDigest;
    try {
        challengeDigest = promptfooQualificationChallengeDigest(row);
    }
    catch {
        addReason(reasons, `challenge_not_canonicalizable:${typedAttemptId}`);
        challengeDigest = `sha256:${'0'.repeat(64)}`;
    }
    return {
        evidence: {
            attempt_id: typedAttemptId,
            challenge_id: challengeId,
            challenge_digest: challengeDigest,
            ordinal: metadata.ordinal,
            status,
            provider_id: typeof providerId === 'string' ? providerId : '',
            prompt_id: typeof row.promptId === 'string' ? row.promptId : '',
            started_at: typeof metadata.started_at === 'string'
                ? metadata.started_at
                : '',
            completed_at: typeof metadata.completed_at === 'string'
                ? metadata.completed_at
                : '',
            expired_at: typeof metadata.expired_at === 'string'
                ? metadata.expired_at
                : null,
            failure: {
                reason: typeof row.failureReason === 'string' ? row.failureReason : '',
                error: typeof row.error === 'string' ? row.error : null,
            },
            payload_digests: {
                request: requestDigest ?? `sha256:${'0'.repeat(64)}`,
                response: responseDigest,
                test_case: testCaseDigest ?? `sha256:${'0'.repeat(64)}`,
                grading: gradingDigest,
                result: resultDigest ?? `sha256:${'0'.repeat(64)}`,
            },
            measurements: {
                cost,
                latency_ms: latencyMs,
                score,
                named_scores: namedScores,
                token_usage: tokenUsage,
            },
        },
        status,
        tokenUsage,
        score,
        namedScores,
        cost,
        latencyMs,
    };
}
function lineageOutput(pin) {
    return {
        id: pin.id,
        immutable_ref: pin.immutable_ref,
        digest: pin.manifest_digest,
        manifest: jsonClone(pin.manifest),
    };
}
/**
 * Convert a single content-pinned Promptfoo run into Qualification v2
 * evaluation evidence. Every refusal is fail-closed and no output of this
 * function is execution-authorizing.
 */
export function adaptPromptfooQualificationArtifact(options) {
    const limitReason = adapterInputLimitReason(options);
    if (limitReason !== null)
        return { ok: false, reasons: [limitReason] };
    try {
        return adaptPromptfooQualificationArtifactInternal(options);
    }
    catch {
        return { ok: false, reasons: ['input_not_inspectable'] };
    }
}
function adaptPromptfooQualificationArtifactInternal(options) {
    const reasons = [];
    const { artifact, pins: pinValue, now } = options;
    if (!exactKeys(pinValue, PIN_KEYS, reasons)) {
        return { ok: false, reasons: [...new Set([...reasons, 'pins_schema_invalid'])] };
    }
    const pins = pinValue;
    if (pins['@version'] !== PROMPTFOO_QUALIFICATION_ADAPTER_VERSION) {
        addReason(reasons, 'adapter_version_mismatch');
    }
    if (!validId(pins.eval_id))
        addReason(reasons, 'eval_id_invalid');
    if (typeof pins.eval_id === 'string' && mutableAlias(pins.eval_id)) {
        addReason(reasons, 'mutable_eval_alias');
    }
    if (typeof pins.promptfoo_version !== 'string'
        || !EXACT_SEMVER_RE.test(pins.promptfoo_version)
        || mutableAlias(pins.promptfoo_version)) {
        addReason(reasons, 'promptfoo_version_not_exact');
    }
    if (pins.output_version !== 3)
        addReason(reasons, 'output_version_unsupported');
    if (!validDigest(pins.artifact_digest)) {
        addReason(reasons, 'artifact_digest_invalid');
    }
    if (!Number.isSafeInteger(pins.max_evidence_age_seconds)
        || pins.max_evidence_age_seconds < 1
        || pins.max_evidence_age_seconds > MAX_AGE_SECONDS) {
        addReason(reasons, 'max_evidence_age_invalid');
    }
    if (!Array.isArray(pins.quality_metrics)
        || pins.quality_metrics.length === 0
        || pins.quality_metrics.length > 256
        || pins.quality_metrics.some((metric) => !validId(metric))
        || new Set(pins.quality_metrics).size !== pins.quality_metrics.length) {
        addReason(reasons, 'quality_metrics_invalid');
    }
    const candidateValid = validateManifestPin(pins.candidate, 'candidate', reasons);
    const assignmentValid = validateManifestPin(pins.assignment, 'assignment', reasons);
    const harnessValid = validateManifestPin(pins.harness, 'harness', reasons, HARNESS_PIN_KEYS);
    const environmentValid = validateManifestPin(pins.environment, 'environment', reasons);
    const campaignValid = validateManifestPin(pins.challenge_campaign, 'campaign', reasons);
    let candidateManifestValid = candidateValid;
    if (candidateValid) {
        if (!exactKeys(pins.candidate.manifest, CANDIDATE_MANIFEST_KEYS, reasons)
            || !validId(pins.candidate.manifest.provider_id)
            || !validId(pins.candidate.manifest.provider_revision)
            || mutableAlias(pins.candidate.manifest.provider_revision)
            || !validId(pins.candidate.manifest.prompt_id)
            || !validDigest(pins.candidate.manifest.prompt_digest)) {
            addReason(reasons, 'candidate_manifest_invalid');
            candidateManifestValid = false;
        }
    }
    if (harnessValid && !validDigest(pins.harness.config_digest)) {
        addReason(reasons, 'harness_config_digest_invalid');
    }
    let campaignManifestValid = campaignValid;
    let expectedAttempts = [];
    if (campaignValid) {
        if (!exactKeys(pins.challenge_campaign.manifest, CAMPAIGN_MANIFEST_KEYS, reasons)
            || !validDigest(pins.challenge_campaign.manifest.challenge_set_digest)
            || !Array.isArray(pins.challenge_campaign.manifest.attempts)) {
            addReason(reasons, 'campaign_manifest_invalid');
            campaignManifestValid = false;
        }
        else {
            expectedAttempts = pins.challenge_campaign.manifest
                .attempts;
            if (expectedAttempts.length === 0
                || expectedAttempts.length > MAX_ATTEMPTS) {
                addReason(reasons, 'campaign_manifest_invalid');
                campaignManifestValid = false;
            }
            const attemptIds = new Set();
            const challengeIds = new Set();
            for (let index = 0; index < expectedAttempts.length; index += 1) {
                const attempt = expectedAttempts[index];
                if (!exactKeys(attempt, CAMPAIGN_ATTEMPT_KEYS, reasons)
                    || !validId(attempt.attempt_id)
                    || !validId(attempt.challenge_id)
                    || attempt.ordinal !== index + 1
                    || !validDigest(attempt.challenge_digest)) {
                    addReason(reasons, 'campaign_manifest_invalid');
                    campaignManifestValid = false;
                    continue;
                }
                if (attemptIds.has(attempt.attempt_id)) {
                    addReason(reasons, `duplicate_manifest_attempt_id:${attempt.attempt_id}`);
                    campaignManifestValid = false;
                }
                if (challengeIds.has(attempt.challenge_id)) {
                    addReason(reasons, `duplicate_manifest_challenge_id:${attempt.challenge_id}`);
                    campaignManifestValid = false;
                }
                attemptIds.add(attempt.attempt_id);
                challengeIds.add(attempt.challenge_id);
            }
            const challengeSetDigest = safeDigest(expectedAttempts, 'challenge_set_digest_mismatch', reasons);
            if (challengeSetDigest
                !== pins.challenge_campaign.manifest.challenge_set_digest) {
                addReason(reasons, 'challenge_set_digest_mismatch');
                campaignManifestValid = false;
            }
        }
    }
    let verifierValid = exactKeys(pins.verifier, VERIFIER_PIN_KEYS, reasons);
    if (!verifierValid
        || !validId(pins.verifier?.id)
        || !validDigest(pins.verifier?.trust_config_digest)) {
        addReason(reasons, 'invalid_pin:verifier');
        verifierValid = false;
    }
    if (verifierValid) {
        const trustDigest = safeDigest(pins.verifier.trust_config, 'verifier_trust_config_digest_mismatch', reasons);
        if (trustDigest !== pins.verifier.trust_config_digest) {
            addReason(reasons, 'verifier_trust_config_digest_mismatch');
        }
        if (!immutableRef('verifier-config', pins.verifier.id, pins.verifier.trust_config_digest, pins.verifier.immutable_ref)) {
            addReason(reasons, 'mutable_or_unpinned_ref:verifier');
        }
    }
    const actualArtifactDigest = safeDigest(artifact, 'artifact_not_canonicalizable', reasons);
    if (actualArtifactDigest !== pins.artifact_digest) {
        addReason(reasons, 'artifact_digest_mismatch');
    }
    if (!immutableRef('promptfoo-eval', pins.eval_id, pins.artifact_digest, pins.artifact_ref)) {
        addReason(reasons, 'mutable_or_unpinned_ref:artifact');
    }
    if (!exactKeys(artifact, OUTPUT_FILE_KEYS, reasons)) {
        addReason(reasons, 'artifact_schema_invalid');
        return { ok: false, reasons };
    }
    if (artifact.evalId !== pins.eval_id) {
        addReason(reasons, 'eval_id_mismatch');
    }
    if (artifact.shareableUrl !== null) {
        addReason(reasons, 'mutable_shareable_url_not_accepted');
    }
    if (!exactKeys(artifact.results, SUMMARY_KEYS, reasons)) {
        addReason(reasons, 'results_schema_invalid');
        return { ok: false, reasons };
    }
    const summary = artifact.results;
    if (summary.version !== pins.output_version || summary.version !== 3) {
        addReason(reasons, 'output_version_mismatch');
    }
    if (!Array.isArray(summary.prompts) || !Array.isArray(summary.results)) {
        addReason(reasons, 'results_schema_invalid');
        return { ok: false, reasons };
    }
    if (!exactKeys(summary.stats, STATS_KEYS, reasons)) {
        addReason(reasons, 'promptfoo_stats_invalid');
        return { ok: false, reasons };
    }
    const stats = summary.stats;
    const configDigest = safeDigest(artifact.config, 'harness_config_not_canonicalizable', reasons);
    if (!harnessValid || configDigest !== pins.harness.config_digest) {
        addReason(reasons, 'harness_config_digest_mismatch');
    }
    if (!exactKeys(artifact.metadata, METADATA_KEYS, reasons)
        || !exactKeys(artifact.metadata.emilia_gate_qualification_v2, RUN_METADATA_KEYS, reasons)) {
        addReason(reasons, 'run_metadata_invalid');
        return { ok: false, reasons };
    }
    const run = artifact.metadata.emilia_gate_qualification_v2;
    if (run['@version'] !== PROMPTFOO_QUALIFICATION_RUN_METADATA_VERSION) {
        addReason(reasons, 'run_metadata_version_mismatch');
    }
    if (run.promptfoo_version !== pins.promptfoo_version) {
        addReason(reasons, 'promptfoo_version_mismatch');
    }
    const runCandidate = runLineage(run, 'candidate', RUN_LINEAGE_KEYS, reasons);
    const runAssignment = runLineage(run, 'assignment', RUN_LINEAGE_KEYS, reasons);
    const runHarness = runLineage(run, 'harness', RUN_HARNESS_KEYS, reasons);
    const runEnvironment = runLineage(run, 'environment', RUN_LINEAGE_KEYS, reasons);
    const runCampaign = runLineage(run, 'challenge_campaign', RUN_LINEAGE_KEYS, reasons);
    const runVerifier = runLineage(run, 'verifier', RUN_VERIFIER_KEYS, reasons);
    compareRunLineage('candidate', runCandidate, candidateValid ? pins.candidate : null, reasons);
    compareRunLineage('assignment', runAssignment, assignmentValid ? pins.assignment : null, reasons);
    compareRunLineage('harness', runHarness, harnessValid ? pins.harness : null, reasons);
    compareRunLineage('environment', runEnvironment, environmentValid ? pins.environment : null, reasons);
    compareRunLineage('challenge_campaign', runCampaign, campaignValid ? pins.challenge_campaign : null, reasons);
    if (runHarness !== null && harnessValid
        && runHarness.config_digest !== pins.harness.config_digest) {
        addReason(reasons, 'run_lineage_mismatch:harness_config');
    }
    if (runVerifier !== null && verifierValid
        && (runVerifier.id !== pins.verifier.id
            || runVerifier.trust_config_digest
                !== pins.verifier.trust_config_digest)) {
        addReason(reasons, 'run_lineage_mismatch:verifier');
    }
    const started = instant(run.started_at);
    const completed = instant(run.completed_at);
    const expires = instant(run.expires_at);
    const trustedNow = instant(now);
    if (!Number.isFinite(trustedNow))
        addReason(reasons, 'trusted_now_invalid');
    if (!Number.isFinite(started)
        || !Number.isFinite(completed)
        || !Number.isFinite(expires)
        || started > completed
        || completed >= expires) {
        addReason(reasons, 'run_timestamp_order_invalid');
    }
    if (summary.timestamp !== run.completed_at
        || !Number.isFinite(instant(summary.timestamp))) {
        addReason(reasons, 'promptfoo_timestamp_mismatch');
    }
    if (Number.isFinite(completed) && Number.isFinite(trustedNow)) {
        if (completed > trustedNow)
            addReason(reasons, 'evidence_from_future');
        if (trustedNow - completed
            > pins.max_evidence_age_seconds * 1000) {
            addReason(reasons, 'evidence_stale');
        }
    }
    if (Number.isFinite(expires)
        && Number.isFinite(trustedNow)
        && trustedNow >= expires) {
        addReason(reasons, 'evidence_expired');
    }
    if (!candidateManifestValid
        || !assignmentValid
        || !harnessValid
        || !environmentValid
        || !campaignManifestValid
        || !verifierValid
        || !Array.isArray(pins.quality_metrics)) {
        return { ok: false, reasons };
    }
    const normalized = [];
    for (let index = 0; index < summary.results.length; index += 1) {
        const attempt = normalizeAttempt(summary.results[index], index, pins.eval_id, pins.candidate, pins.quality_metrics, started, completed, reasons);
        if (attempt !== null)
            normalized.push(attempt);
    }
    const seenAttempts = new Map();
    const seenChallenges = new Set();
    for (const attempt of normalized) {
        const attemptId = attempt.evidence.attempt_id;
        const challengeId = attempt.evidence.challenge_id;
        if (seenAttempts.has(attemptId)) {
            addReason(reasons, `duplicate_attempt_id:${attemptId}`);
        }
        else {
            seenAttempts.set(attemptId, attempt);
        }
        if (seenChallenges.has(challengeId)) {
            addReason(reasons, `duplicate_challenge_id:${challengeId}`);
        }
        seenChallenges.add(challengeId);
    }
    for (let index = 0; index < expectedAttempts.length; index += 1) {
        const expected = expectedAttempts[index];
        if (typeof expected.attempt_id !== 'string')
            continue;
        const observed = seenAttempts.get(expected.attempt_id);
        if (observed === undefined) {
            addReason(reasons, `selective_result_omission:${expected.attempt_id}`);
            continue;
        }
        if (normalized[index]?.evidence.attempt_id !== expected.attempt_id) {
            addReason(reasons, 'attempt_order_mismatch');
        }
        if (observed.evidence.challenge_id !== expected.challenge_id
            || observed.evidence.ordinal !== expected.ordinal
            || observed.evidence.challenge_digest !== expected.challenge_digest) {
            addReason(reasons, `attempt_manifest_mismatch:${expected.attempt_id}`);
        }
    }
    const expectedIds = new Set(expectedAttempts
        .map((attempt) => attempt.attempt_id)
        .filter((value) => typeof value === 'string'));
    for (const attempt of normalized) {
        if (!expectedIds.has(attempt.evidence.attempt_id)) {
            addReason(reasons, `unexpected_attempt:${attempt.evidence.attempt_id}`);
        }
    }
    const counts = statusCounts(normalized);
    const expectedCount = expectedAttempts.length;
    const observedCount = normalized.length;
    if (!exactKeys(run.attempt_counts, ATTEMPT_COUNT_KEYS, reasons)) {
        addReason(reasons, 'attempt_counts_invalid');
    }
    else {
        const declared = run.attempt_counts;
        if (!Object.values(declared).every(validCount)
            || declared.expected !== expectedCount
            || declared.observed !== observedCount
            || declared.passed !== counts.passed
            || declared.failed !== counts.failed
            || declared.errors !== counts.errors
            || declared.aborted !== counts.aborted
            || declared.expired !== counts.expired) {
            addReason(reasons, 'attempt_counts_mismatch');
        }
    }
    if (!validCount(stats.successes)
        || !validCount(stats.failures)
        || !validCount(stats.errors)
        || stats.successes !== counts.passed
        || stats.failures !== counts.failed
        || stats.errors !== counts.errors + counts.aborted + counts.expired) {
        addReason(reasons, 'promptfoo_stats_mismatch');
    }
    let tokenUsage = {
        total: 0,
        prompt: 0,
        completion: 0,
        cached: 0,
    };
    let costTotal = 0;
    let latencyTotal = 0;
    let scoreTotal = 0;
    const namedScoreTotals = Object.fromEntries(pins.quality_metrics.map((metric) => [metric, 0]));
    for (const attempt of normalized) {
        tokenUsage = addTokenUsage(tokenUsage, attempt.tokenUsage);
        costTotal += attempt.cost;
        latencyTotal += attempt.latencyMs;
        scoreTotal += attempt.score;
        for (const metric of pins.quality_metrics) {
            namedScoreTotals[metric] += attempt.namedScores[metric] ?? 0;
        }
    }
    if (!sameTokenUsage(stats.tokenUsage, tokenUsage)) {
        addReason(reasons, 'promptfoo_token_usage_mismatch');
    }
    for (const field of [
        'durationMs',
        'generationDurationMs',
        'evaluationDurationMs',
    ]) {
        if (stats[field] !== undefined
            && !validBoundedNumber(stats[field], 0, Number.MAX_SAFE_INTEGER)) {
            addReason(reasons, 'promptfoo_duration_invalid');
        }
    }
    if (Number.isFinite(started) && Number.isFinite(completed)) {
        const elapsed = completed - started;
        if (stats.durationMs !== undefined && stats.durationMs !== elapsed) {
            addReason(reasons, 'promptfoo_duration_mismatch');
        }
        if ((typeof stats.generationDurationMs === 'number'
            && stats.generationDurationMs > elapsed)
            || (typeof stats.evaluationDurationMs === 'number'
                && stats.evaluationDurationMs > elapsed)) {
            addReason(reasons, 'promptfoo_duration_mismatch');
        }
    }
    if (reasons.length > 0)
        return { ok: false, reasons };
    if (!assignmentValid || !harnessValid || !environmentValid
        || !campaignValid || !verifierValid) {
        return { ok: false, reasons: ['pins_schema_invalid'] };
    }
    const evidence = {
        '@version': PROMPTFOO_QUALIFICATION_EVIDENCE_VERSION,
        evidence_type: 'UPSTREAM_EVALUATION',
        authority: {
            classification: 'EVALUATION_ONLY',
            authorizes: false,
        },
        // Promptfoo's provider id and response metadata are unauthenticated claims.
        // This adapter has no authenticated provider receipt profile, so an exact-
        // looking revision string must never be upgraded to a pinned identity.
        provider_identity: {
            provider_id: pins.candidate.manifest.provider_id,
            claimed_revision: pins.candidate.manifest.provider_revision,
            authenticated_revision: null,
            pinning_strength: 'UNPINNABLE',
        },
        source: {
            system: 'promptfoo',
            adapter_version: PROMPTFOO_QUALIFICATION_ADAPTER_VERSION,
            promptfoo_version: pins.promptfoo_version,
            output_version: 3,
            eval_id: pins.eval_id,
            artifact_ref: pins.artifact_ref,
            artifact_digest: pins.artifact_digest,
        },
        lineage: {
            candidate: lineageOutput(pins.candidate),
            assignment: lineageOutput(pins.assignment),
            harness: {
                ...lineageOutput(pins.harness),
                config_digest: pins.harness.config_digest,
            },
            environment: lineageOutput(pins.environment),
            challenge_campaign: lineageOutput(pins.challenge_campaign),
        },
        timing: {
            started_at: run.started_at,
            completed_at: run.completed_at,
            expires_at: run.expires_at,
            evaluated_at: now,
        },
        coverage: {
            complete: true,
            expected: expectedCount,
            observed: observedCount,
            passed: counts.passed,
            failed: counts.failed,
            errors: counts.errors,
            aborted: counts.aborted,
            expired: counts.expired,
        },
        measurements: {
            cost_total: costTotal,
            latency_ms_total: latencyTotal,
            run_duration_ms: typeof stats.durationMs === 'number'
                ? stats.durationMs
                : null,
            generation_duration_ms: typeof stats.generationDurationMs === 'number'
                ? stats.generationDurationMs
                : null,
            evaluation_duration_ms: typeof stats.evaluationDurationMs === 'number'
                ? stats.evaluationDurationMs
                : null,
            mean_score: observedCount === 0 ? 0 : scoreTotal / observedCount,
            named_score_means: Object.fromEntries(Object.entries(namedScoreTotals).map(([metric, total]) => [
                metric,
                observedCount === 0 ? 0 : total / observedCount,
            ])),
            token_usage: tokenUsage,
        },
        attempts: normalized.map((attempt) => attempt.evidence),
        verifier: {
            id: pins.verifier.id,
            immutable_ref: pins.verifier.immutable_ref,
            trust_config: jsonClone(pins.verifier.trust_config),
            trust_config_digest: pins.verifier.trust_config_digest,
        },
    };
    return { ok: true, evidence: deepFreeze(evidence) };
}
//# sourceMappingURL=gate-qualification-promptfoo.js.map