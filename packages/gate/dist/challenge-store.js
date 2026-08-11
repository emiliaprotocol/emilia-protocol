// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
/**
 * Durable, body-bound lifecycle store for AE-CHALLENGE-v1.
 *
 * Registration is atomic insert-if-absent. Consumption is an atomic transition
 * from the digest of the exact registered body to a consumed state carrying
 * that same digest. A presenter that changes action, profile, expiry, or any
 * other challenge member cannot consume the original registration even when it
 * reuses the challenge id and nonce.
 */
import crypto from 'node:crypto';
import { canonicalize, hashCanonical } from './execution-binding.js';
export const DURABLE_CHALLENGE_STORE_VERSION = 'EP-DURABLE-CHALLENGE-STORE-v3';
export const AUTHORITATIVE_CHALLENGE_OWNER_VERSION = 'EP-AE-CHALLENGE-OWNER-v2';
export const AUTHORITATIVE_CHALLENGE_RECORD_VERSION = 'EP-AE-CHALLENGE-OWNER-RECORD-v2';
const OPEN_PREFIX = 'challenge-open:v3:';
const CONSUMED_PREFIX = 'challenge-consumed:v3:';
const LEGACY_SINGLE_ISSUER_IDENTITY = 'urn:emilia:challenge-issuer:legacy-single-store';
const AUTHORITATIVE_OWNER_STORES = new WeakSet();
const CAPACITY_KEY_RE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$/;
const DIGEST_RE = /^(?:sha256:)?[0-9a-f]{64}$/;
const CORE_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const DURABLE_NONCE_RE = /^[A-Za-z0-9_-]{22,128}$/;
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const REQUIREMENT_KEYS = new Set([
    'requirement_id', 'type', 'profiles', 'proof_predicates', 'max_age_sec', 'status',
]);
const HINT_KEYS = new Set(['requirement_id', 'mechanism', 'uri']);
const RETRY_KEYS = new Set(['not_before', 'jitter_sec']);
function compareCapacityKeys(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function tokenDigest(value) {
    return `sha256:${crypto.createHash('sha256').update(value, 'utf8').digest('hex')}`;
}
function strictTimestamp(value) {
    if (typeof value !== 'string')
        return NaN;
    const match = value.match(RFC3339_INSTANT);
    if (!match)
        return NaN;
    const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match;
    const local = `${year}-${month}-${day}T${hour}:${minute}:${second}`;
    const calendar = new Date(0);
    calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
    calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
    if (calendar.toISOString().slice(0, 19) !== local)
        return NaN;
    if (offsetHour !== undefined && (Number(offsetHour) > 23 || Number(offsetMinute) > 59))
        return NaN;
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : NaN;
}
function absoluteUri(value) {
    if (typeof value !== 'string' || !value || value.length > 1024
        || /[\u0000-\u0020\u007f]/.test(value))
        return false;
    try {
        return new URL(value).protocol.length > 1;
    }
    catch {
        return false;
    }
}
function nonEmptyString(value, max) {
    return typeof value === 'string' && value.length > 0 && value.length <= max
        && !/[\u0000-\u001f\u007f]/.test(value);
}
function uniqueStrings(value, { min = 0, max = 32, uri = false } = {}) {
    return Array.isArray(value) && value.length >= min && value.length <= max
        && new Set(value).size === value.length
        && value.every((entry) => nonEmptyString(entry, 1024) && (!uri || absoluteUri(entry)));
}
function onlyKeys(value, allowed) {
    return Object.keys(value).every((key) => allowed.has(key));
}
function assertAuthoritativeChallenge(challenge) {
    assertChallenge(challenge);
    let encoded;
    try {
        encoded = canonicalize(challenge);
    }
    catch {
        throw new Error('challenge is outside the canonical JSON domain');
    }
    if (Buffer.byteLength(encoded, 'utf8') > 65_536) {
        throw new Error('challenge exceeds the 65536-octet reference limit');
    }
    if (!nonEmptyString(challenge.challenge_id, 256))
        throw new Error('challenge_id is invalid');
    if (!DURABLE_NONCE_RE.test(challenge.nonce))
        throw new Error('challenge nonce syntax is invalid');
    try {
        const decoded = Buffer.from(challenge.nonce, 'base64url');
        if (decoded.length < 16 || decoded.toString('base64url') !== challenge.nonce)
            throw new Error('weak');
    }
    catch {
        throw new Error('challenge nonce is not canonical base64url with at least 16 octets');
    }
    if (!CORE_DIGEST_RE.test(challenge.action_digest))
        throw new Error('challenge action_digest is invalid');
    if (!absoluteUri(challenge.action_profile))
        throw new Error('challenge action_profile is not an absolute URI');
    if (!nonEmptyString(challenge.audience, 512))
        throw new Error('challenge audience is invalid');
    if (!absoluteUri(challenge.policy_id))
        throw new Error('challenge policy_id is not an absolute URI');
    if (!CORE_DIGEST_RE.test(challenge.policy_digest))
        throw new Error('challenge policy_digest is invalid');
    if (!uniqueStrings(challenge.present_as, { min: 1, max: 16, uri: true })) {
        throw new Error('challenge present_as is invalid');
    }
    if (!Array.isArray(challenge.required_evidence)
        || challenge.required_evidence.length < 1 || challenge.required_evidence.length > 64) {
        throw new Error('challenge required_evidence must contain 1-64 entries');
    }
    const requirementIds = new Set();
    for (const requirement of challenge.required_evidence) {
        if (!requirement || typeof requirement !== 'object' || Array.isArray(requirement)
            || !onlyKeys(requirement, REQUIREMENT_KEYS)
            || !nonEmptyString(requirement.requirement_id, 256)
            || requirementIds.has(requirement.requirement_id)
            || !absoluteUri(requirement.type)) {
            throw new Error('challenge required_evidence entry is invalid');
        }
        requirementIds.add(requirement.requirement_id);
        if (requirement.profiles !== undefined
            && !uniqueStrings(requirement.profiles, { min: 1, max: 16, uri: true })) {
            throw new Error('challenge evidence profiles are invalid');
        }
        if (requirement.proof_predicates !== undefined
            && !uniqueStrings(requirement.proof_predicates, { min: 1, max: 32, uri: true })) {
            throw new Error('challenge proof predicates are invalid');
        }
        if (requirement.max_age_sec !== undefined
            && (!Number.isSafeInteger(requirement.max_age_sec)
                || requirement.max_age_sec < 0 || requirement.max_age_sec > 2147483647)) {
            throw new Error('challenge max_age_sec is invalid');
        }
        if (requirement.status !== undefined && requirement.status !== 'current') {
            throw new Error('challenge status is unsupported by the reference owner');
        }
    }
    if (challenge.obtain_hints !== undefined) {
        if (!Array.isArray(challenge.obtain_hints) || challenge.obtain_hints.length > 64) {
            throw new Error('challenge obtain_hints is invalid');
        }
        for (const hint of challenge.obtain_hints) {
            if (!hint || typeof hint !== 'object' || Array.isArray(hint)
                || !onlyKeys(hint, HINT_KEYS)
                || !requirementIds.has(hint.requirement_id)
                || !absoluteUri(hint.mechanism) || !absoluteUri(hint.uri)) {
                throw new Error('challenge obtain hint is invalid');
            }
        }
    }
    const expiresAt = strictTimestamp(challenge.expires_at);
    if (Number.isNaN(expiresAt))
        throw new Error('challenge expires_at is invalid');
    if (challenge.retry_timing !== undefined) {
        const retry = challenge.retry_timing;
        if (!retry || typeof retry !== 'object' || Array.isArray(retry)
            || !onlyKeys(retry, RETRY_KEYS))
            throw new Error('challenge retry_timing is invalid');
        const notBefore = strictTimestamp(retry.not_before);
        const jitterSec = retry.jitter_sec ?? 0;
        if (Number.isNaN(notBefore) || !Number.isSafeInteger(jitterSec) || jitterSec < 0
            || jitterSec > 2147483647 || notBefore >= expiresAt
            || notBefore + jitterSec * 1000 >= expiresAt) {
            throw new Error('challenge retry_timing interval is invalid');
        }
    }
    if (challenge.critical !== undefined
        && !uniqueStrings(challenge.critical, { min: 1, max: 32 })) {
        throw new Error('challenge critical extensions are invalid');
    }
    if (challenge.critical !== undefined) {
        throw new Error('challenge critical extension is unsupported by the reference owner');
    }
    return challenge;
}
function defaultOwnerToken() {
    return crypto.randomBytes(32).toString('base64url');
}
function safeEpochMs(value, label) {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new Error(`${label} must be a non-negative safe-integer epoch millisecond`);
    }
    return value;
}
function normalizedBuckets(value) {
    if (!Array.isArray(value) || value.length === 0 || value.length > 32) {
        throw new Error('challenge capacity policy must return 1-32 buckets');
    }
    const seen = new Set();
    const buckets = value.map((entry) => {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)
            || typeof entry.key !== 'string' || !CAPACITY_KEY_RE.test(entry.key)
            || !Number.isSafeInteger(entry.limit) || entry.limit < 1) {
            throw new Error('challenge capacity bucket is invalid');
        }
        if (seen.has(entry.key))
            throw new Error('challenge capacity bucket is duplicated');
        seen.add(entry.key);
        return Object.freeze({ key: entry.key, limit: entry.limit });
    });
    return buckets.sort((a, b) => compareCapacityKeys(a.key, b.key));
}
function vectorFor(buckets, units) {
    return Object.fromEntries(buckets.map(({ key }) => [key, units]));
}
function addVectors(...vectors) {
    const out = {};
    for (const vector of vectors) {
        for (const [key, units] of Object.entries(vector)) {
            const current = Object.hasOwn(out, key) ? out[key] : 0;
            out[key] = current + units;
        }
    }
    return out;
}
function equalVectors(left, right) {
    const keys = new Set([...Object.keys(left), ...Object.keys(right)]);
    return [...keys].every((key) => ((Object.hasOwn(left, key) ? left[key] : 0)
        === (Object.hasOwn(right, key) ? right[key] : 0)));
}
function limitsFor(buckets) {
    return Object.fromEntries(buckets.map(({ key, limit }) => [key, limit]));
}
function mergeLimits(...limits) {
    const out = {};
    for (const vector of limits) {
        for (const [key, limit] of Object.entries(vector)) {
            if (!CAPACITY_KEY_RE.test(key) || !Number.isSafeInteger(limit) || limit < 1) {
                throw new Error('challenge capacity limit state is malformed');
            }
            if (Object.hasOwn(out, key) && out[key] !== limit) {
                throw new Error('challenge capacity policy changed a bucket limit');
            }
            out[key] = limit;
        }
    }
    return out;
}
function bucketsFromLimits(limits) {
    return Object.entries(limits)
        .map(([key, limit]) => Object.freeze({ key, limit }))
        .sort((a, b) => compareCapacityKeys(a.key, b.key));
}
function validateOwnerRecord(record) {
    if (!record || typeof record !== 'object'
        || Array.isArray(record)
        || record.record_version !== AUTHORITATIVE_CHALLENGE_RECORD_VERSION
        || !DIGEST_RE.test(record.body_digest)
        || !['open', 'reserved', 'finalized'].includes(record.state)
        || !Number.isSafeInteger(record.generation) || record.generation < 0
        || !record.units || typeof record.units !== 'object' || Array.isArray(record.units)
        || !record.retained_units || typeof record.retained_units !== 'object'
        || Array.isArray(record.retained_units)
        || !record.capacity_limits || typeof record.capacity_limits !== 'object'
        || Array.isArray(record.capacity_limits)
        || (record.authenticated_presenter !== null
            && !nonEmptyString(record.authenticated_presenter, 512))) {
        throw new Error('authoritative challenge owner returned a malformed record');
    }
    const limits = mergeLimits(record.capacity_limits);
    for (const vector of [record.units, record.retained_units]) {
        for (const [key, units] of Object.entries(vector)) {
            if (!CAPACITY_KEY_RE.test(key) || !Number.isSafeInteger(units) || units < 0
                || !Object.hasOwn(limits, key) || units > limits[key]) {
                throw new Error('authoritative challenge owner returned malformed capacity state');
            }
        }
    }
    for (const key of Object.keys(record.retained_units)) {
        if (record.retained_units[key] > (Object.hasOwn(record.units, key) ? record.units[key] : 0)) {
            throw new Error('authoritative challenge owner retained capacity exceeds current capacity');
        }
    }
    try {
        assertAuthoritativeChallenge(record.challenge);
        if (challengeBodyDigest(record.challenge) !== record.body_digest) {
            throw new Error('body digest mismatch');
        }
    }
    catch {
        throw new Error('authoritative challenge owner record body binding is invalid');
    }
    const sameUnits = equalVectors(record.units, record.retained_units);
    if (record.state === 'open'
        && (record.generation !== 0 || record.owner_token_digest !== null
            || record.reserved_at_ms !== null || record.outcome !== null || !sameUnits)) {
        throw new Error('authoritative challenge owner open-state invariants failed');
    }
    if (record.state === 'reserved'
        && (record.generation < 1 || !CORE_DIGEST_RE.test(record.owner_token_digest ?? '')
            || !Number.isSafeInteger(record.reserved_at_ms) || record.reserved_at_ms < 0
            || record.outcome !== null)) {
        throw new Error('authoritative challenge owner reserved-state invariants failed');
    }
    if (record.state === 'finalized'
        && (record.owner_token_digest !== null || record.reserved_at_ms !== null
            || typeof record.outcome !== 'string' || !record.outcome || !sameUnits)) {
        throw new Error('authoritative challenge owner finalized-state invariants failed');
    }
    return record;
}
function applyCapacity(locked, previous, next) {
    const result = {};
    const keys = new Set([...Object.keys(locked), ...Object.keys(previous), ...Object.keys(next)]);
    for (const key of keys) {
        const row = locked[key];
        if (!row || !Number.isSafeInteger(row.used) || !Number.isSafeInteger(row.limit)) {
            throw new Error('authoritative challenge capacity row is malformed');
        }
        const previousUnits = Object.hasOwn(previous, key) ? previous[key] : 0;
        const nextUnits = Object.hasOwn(next, key) ? next[key] : 0;
        const value = row.used - previousUnits + nextUnits;
        if (!Number.isSafeInteger(value) || value < 0 || value > row.limit)
            return null;
        result[key] = value;
    }
    return result;
}
function reservationHandle(key, record, ownerToken) {
    return Object.freeze({
        version: AUTHORITATIVE_CHALLENGE_OWNER_VERSION,
        replay_key: key,
        body_digest: record.body_digest,
        generation: record.generation,
        owner_token: ownerToken,
    });
}
function followupBindingDigest(challenge) {
    return hashCanonical({
        version: challenge?.['@version'],
        action_digest: challenge?.action_digest,
        action_profile: challenge?.action_profile,
        reliance_purpose: challenge?.reliance_purpose ?? null,
        policy_id: challenge?.policy_id ?? null,
        policy_digest: challenge?.policy_digest,
        required_evidence: challenge?.required_evidence,
        present_as: challenge?.present_as,
        audience: challenge?.audience ?? null,
    });
}
/**
 * Build the owner-side state machine required by AE-CHALLENGE -07.
 *
 * The injected backend supplies one serializable transaction, row locks, and
 * authoritative database time. The algorithm, capacity ordering, ownership
 * fence, and result grammar live here rather than in caller-provided booleans.
 */
export function createAuthoritativeChallengeOwnerStore(backend, { issuerIdentity, capacityPolicy, ownerTokenFactory = defaultOwnerToken, recoveryAuthorizer, recoveryAfterMs = 60_000, }) {
    if (!backend || typeof backend.transaction !== 'function') {
        throw new Error('authoritative challenge owner requires a transactional backend');
    }
    if (typeof capacityPolicy !== 'function') {
        throw new Error('authoritative challenge owner requires a constructor-pinned capacity policy');
    }
    if (typeof ownerTokenFactory !== 'function') {
        throw new Error('authoritative challenge owner requires an owner-token factory');
    }
    if (typeof recoveryAuthorizer !== 'function') {
        throw new Error('authoritative challenge owner requires a constructor-pinned recovery authorizer');
    }
    if (!Number.isSafeInteger(recoveryAfterMs) || recoveryAfterMs < 1) {
        throw new Error('authoritative challenge recoveryAfterMs is invalid');
    }
    const issuer = normalizedIssuerIdentity(issuerIdentity);
    function bucketsFor(challenge, authenticatedPresenter) {
        if (authenticatedPresenter !== undefined && !nonEmptyString(authenticatedPresenter, 512)) {
            throw new Error('authenticated presenter identity is invalid');
        }
        return normalizedBuckets(capacityPolicy(challenge, {
            authenticated_presenter: authenticatedPresenter,
        }));
    }
    function freshOwnerToken() {
        const token = ownerTokenFactory();
        if (typeof token !== 'string' || Buffer.byteLength(token, 'utf8') < 32
            || Buffer.byteLength(token, 'utf8') > 512) {
            throw new Error('challenge owner token must contain 32-512 UTF-8 octets');
        }
        return token;
    }
    async function registerOutstanding(challenge, context = {}) {
        assertAuthoritativeChallenge(challenge);
        const expiresAt = strictTimestamp(challenge.expires_at);
        const key = challengeStorageKey(challenge, issuer);
        const bodyDigest = challengeBodyDigest(challenge);
        const buckets = bucketsFor(challenge, context.authenticated_presenter);
        const capacityLimits = limitsFor(buckets);
        return backend.transaction(async (tx) => {
            await tx.lockChallenge(key);
            const nowMs = safeEpochMs(await tx.authoritativeNowMs(), 'authoritative challenge owner time');
            if (nowMs >= expiresAt)
                return false;
            if (await tx.readChallenge(key))
                return false;
            const locked = await tx.lockCapacity(buckets);
            const units = vectorFor(buckets, 1);
            const updated = applyCapacity(locked, {}, units);
            if (updated === null)
                return false;
            const inserted = await tx.insertChallenge(key, {
                record_version: AUTHORITATIVE_CHALLENGE_RECORD_VERSION,
                body_digest: bodyDigest,
                challenge,
                state: 'open',
                units,
                retained_units: units,
                capacity_limits: capacityLimits,
                authenticated_presenter: context.authenticated_presenter ?? null,
                owner_token_digest: null,
                generation: 0,
                reserved_at_ms: null,
                outcome: null,
            });
            if (!inserted)
                throw new Error('authoritative challenge insertion conflicted after lock');
            await tx.writeCapacity(updated);
            return true;
        });
    }
    async function compoundClaimAndCapacity(challenge, context = {}) {
        assertAuthoritativeChallenge(challenge);
        const expiresAt = strictTimestamp(challenge.expires_at);
        const key = challengeStorageKey(challenge, issuer);
        const bodyDigest = challengeBodyDigest(challenge);
        return backend.transaction(async (tx) => {
            await tx.lockChallenge(key);
            const record = await tx.readChallenge(key);
            if (record && ['reserved', 'finalized'].includes(validateOwnerRecord(record).state)) {
                return { result: record.body_digest === bodyDigest ? 'exact_body_replay' : 'nonce_body_collision' };
            }
            const nowMs = safeEpochMs(await tx.authoritativeNowMs(), 'authoritative challenge owner time');
            if (nowMs >= expiresAt)
                return { result: 'expired' };
            if (!record)
                return { result: 'owner_unavailable' };
            validateOwnerRecord(record);
            if (record.body_digest !== bodyDigest)
                return { result: 'nonce_body_collision' };
            if (record.authenticated_presenter !== null
                && record.authenticated_presenter !== context.authenticated_presenter) {
                return { result: 'owner_unavailable' };
            }
            const buckets = bucketsFor(challenge, context.authenticated_presenter);
            const capacityLimits = mergeLimits(record.capacity_limits, limitsFor(buckets));
            const locked = await tx.lockCapacity(bucketsFromLimits(capacityLimits));
            const target = addVectors(record.retained_units, vectorFor(buckets, 1));
            const updated = applyCapacity(locked, record.units, target);
            if (updated === null)
                return { result: 'capacity_refused' };
            const ownerToken = freshOwnerToken();
            const next = {
                ...record,
                state: 'reserved',
                units: target,
                capacity_limits: capacityLimits,
                authenticated_presenter: context.authenticated_presenter
                    ?? record.authenticated_presenter,
                owner_token_digest: tokenDigest(ownerToken),
                generation: record.generation + 1,
                reserved_at_ms: nowMs,
            };
            await tx.writeChallenge(key, next);
            await tx.writeCapacity(updated);
            return {
                result: 'claimed_with_capacity',
                reservation: reservationHandle(key, next, ownerToken),
                authoritative_at_ms: nowMs,
            };
        });
    }
    async function finalizeReservation(handle, { outcome, followup = null, }) {
        if (!handle || handle.version !== AUTHORITATIVE_CHALLENGE_OWNER_VERSION
            || typeof handle.replay_key !== 'string' || !DIGEST_RE.test(handle.body_digest)
            || !Number.isSafeInteger(handle.generation) || handle.generation < 1
            || typeof handle.owner_token !== 'string') {
            throw new Error('challenge reservation handle is invalid');
        }
        if (typeof outcome !== 'string' || !outcome.trim() || outcome.length > 128) {
            throw new Error('challenge reservation outcome is invalid');
        }
        if (followup !== null)
            assertAuthoritativeChallenge(followup);
        const followupKey = followup === null ? null : challengeStorageKey(followup, issuer);
        const followupDigest = followup === null ? null : challengeBodyDigest(followup);
        if (followupKey === handle.replay_key)
            throw new Error('follow-up challenge must use a fresh replay key');
        return backend.transaction(async (tx) => {
            await tx.lockChallenge(handle.replay_key);
            if (followupKey)
                await tx.lockChallenge(followupKey);
            const record = await tx.readChallenge(handle.replay_key);
            if (!record)
                throw new Error('challenge reservation is missing');
            validateOwnerRecord(record);
            if (record.state !== 'reserved' || record.body_digest !== handle.body_digest
                || record.generation !== handle.generation
                || record.owner_token_digest !== tokenDigest(handle.owner_token)) {
                throw new Error('challenge reservation ownership fence refused finalization');
            }
            if (followup !== null
                && followupBindingDigest(followup) !== followupBindingDigest(record.challenge)) {
                throw new Error('follow-up challenge changed the bound action, policy, requirements, audience, or presentation method');
            }
            const nowMs = safeEpochMs(await tx.authoritativeNowMs(), 'authoritative challenge owner time');
            let followupUnits = {};
            let followupRecord = null;
            let followupBuckets = [];
            if (followup !== null) {
                const expiresAt = strictTimestamp(followup.expires_at);
                if (nowMs >= expiresAt) {
                    throw new Error('follow-up challenge is already expired at authoritative owner time');
                }
                if (await tx.readChallenge(followupKey)) {
                    throw new Error('follow-up challenge replay key already exists');
                }
                followupBuckets = bucketsFor(followup, record.authenticated_presenter ?? undefined);
                followupUnits = vectorFor(followupBuckets, 1);
                followupRecord = {
                    record_version: AUTHORITATIVE_CHALLENGE_RECORD_VERSION,
                    body_digest: followupDigest,
                    challenge: followup,
                    state: 'open',
                    units: followupUnits,
                    retained_units: followupUnits,
                    capacity_limits: limitsFor(followupBuckets),
                    authenticated_presenter: record.authenticated_presenter,
                    owner_token_digest: null,
                    generation: 0,
                    reserved_at_ms: null,
                    outcome: null,
                };
            }
            const retainedUnits = record.retained_units;
            const target = addVectors(retainedUnits, followupUnits);
            const capacityLimits = mergeLimits(record.capacity_limits, limitsFor(followupBuckets));
            const locked = await tx.lockCapacity(bucketsFromLimits(capacityLimits));
            const updated = applyCapacity(locked, record.units, target);
            if (updated === null)
                throw new Error('reserved challenge capacity was insufficient for finalization');
            if (followupRecord && !(await tx.insertChallenge(followupKey, followupRecord))) {
                throw new Error('follow-up challenge insertion conflicted after lock');
            }
            await tx.writeChallenge(handle.replay_key, {
                ...record,
                state: 'finalized',
                units: retainedUnits,
                owner_token_digest: null,
                reserved_at_ms: null,
                outcome,
            });
            await tx.writeCapacity(updated);
            return { result: 'finalized', authoritative_at_ms: nowMs };
        });
    }
    async function recoverReservation(challenge, { authorization } = {}) {
        assertAuthoritativeChallenge(challenge);
        if (await recoveryAuthorizer(authorization) !== true) {
            return { result: 'recovery_unauthorized' };
        }
        const key = challengeStorageKey(challenge, issuer);
        return backend.transaction(async (tx) => {
            await tx.lockChallenge(key);
            const record = await tx.readChallenge(key);
            if (!record)
                return { result: 'not_found' };
            validateOwnerRecord(record);
            if (record.state !== 'reserved')
                return { result: 'not_reserved' };
            const nowMs = safeEpochMs(await tx.authoritativeNowMs(), 'authoritative challenge owner time');
            if (record.reserved_at_ms === null || nowMs < record.reserved_at_ms + recoveryAfterMs) {
                return { result: 'recovery_not_due' };
            }
            const ownerToken = freshOwnerToken();
            if (typeof ownerToken !== 'string' || Buffer.byteLength(ownerToken, 'utf8') < 32) {
                throw new Error('challenge recovery token is invalid');
            }
            const next = {
                ...record,
                generation: record.generation + 1,
                owner_token_digest: tokenDigest(ownerToken),
                reserved_at_ms: nowMs,
            };
            await tx.writeChallenge(key, next);
            return { result: 'recovered', reservation: reservationHandle(key, next, ownerToken) };
        });
    }
    const store = Object.freeze({
        version: AUTHORITATIVE_CHALLENGE_OWNER_VERSION,
        durable: backend.durable === true,
        issuerIdentity: issuer,
        register: registerOutstanding,
        registerOutstanding,
        compoundClaimAndCapacity,
        finalizeReservation,
        recoverReservation,
    });
    AUTHORITATIVE_OWNER_STORES.add(store);
    return store;
}
export function isAuthoritativeChallengeOwnerStore(store) {
    return !!store && typeof store === 'object'
        && AUTHORITATIVE_OWNER_STORES.has(store)
        && store.version === AUTHORITATIVE_CHALLENGE_OWNER_VERSION
        && store.durable === true;
}
/** Serialized in-memory backend for executable contract tests only. */
export function createMemoryChallengeOwnerBackend({ now = Date.now } = {}) {
    const records = new Map();
    const capacity = new Map();
    let tail = Promise.resolve();
    const clone = (value) => structuredClone(value);
    return {
        durable: false,
        records,
        capacity,
        async transaction(work) {
            const prior = tail;
            let release;
            tail = new Promise((resolve) => { release = resolve; });
            await prior;
            const recordSnapshot = clone([...records]);
            const capacitySnapshot = clone([...capacity]);
            try {
                return await work({
                    authoritativeNowMs: async () => safeEpochMs(typeof now === 'function' ? now() : now, 'memory owner time'),
                    lockChallenge: async () => { },
                    readChallenge: async (key) => records.has(key) ? clone(records.get(key)) : null,
                    insertChallenge: async (key, record) => {
                        if (records.has(key))
                            return false;
                        records.set(key, clone(record));
                        return true;
                    },
                    writeChallenge: async (key, record) => { records.set(key, clone(record)); },
                    lockCapacity: async (buckets) => {
                        for (const bucket of buckets) {
                            const current = capacity.get(bucket.key);
                            if (current && current.limit !== bucket.limit)
                                throw new Error('memory owner capacity limit changed');
                            if (!current)
                                capacity.set(bucket.key, { used: 0, limit: bucket.limit });
                        }
                        return Object.fromEntries(buckets.map(({ key }) => [key, clone(capacity.get(key))]));
                    },
                    writeCapacity: async (used) => {
                        for (const [key, value] of Object.entries(used)) {
                            const row = capacity.get(key);
                            if (!row)
                                throw new Error('memory owner capacity row is missing');
                            capacity.set(key, { ...row, used: value });
                        }
                    },
                });
            }
            catch (error) {
                records.clear();
                capacity.clear();
                for (const [key, value] of recordSnapshot)
                    records.set(key, value);
                for (const [key, value] of capacitySnapshot)
                    capacity.set(key, value);
                throw error;
            }
            finally {
                release();
            }
        },
    };
}
function assertChallenge(challenge) {
    if (!challenge || typeof challenge !== 'object' || Array.isArray(challenge)) {
        throw new Error('challenge must be an object');
    }
    if (challenge['@version'] !== 'AE-CHALLENGE-v1')
        throw new Error('unsupported challenge version');
    if (typeof challenge.challenge_id !== 'string' || !challenge.challenge_id.trim())
        throw new Error('challenge_id is required');
    if (typeof challenge.nonce !== 'string' || !challenge.nonce.trim())
        throw new Error('challenge nonce is required');
}
function normalizedIssuerIdentity(issuerIdentity) {
    if (issuerIdentity === undefined)
        return LEGACY_SINGLE_ISSUER_IDENTITY;
    if (!nonEmptyString(issuerIdentity, 512)) {
        throw new Error('authenticated issuer identity must be a non-empty string');
    }
    return issuerIdentity;
}
export function challengeStorageKey(challenge, issuerIdentity) {
    assertChallenge(challenge);
    // The authenticated issuer identity and nonce form the replay key. The
    // correlation-only challenge_id is intentionally excluded. The legacy
    // sentinel preserves source compatibility for explicitly single-issuer,
    // non-conforming callers; production -07 use requires issuerScoped=true.
    return `ae-challenge:v3:${hashCanonical({
        issuer: normalizedIssuerIdentity(issuerIdentity),
        nonce: challenge.nonce,
    })}`;
}
export function challengeBodyDigest(challenge) {
    assertChallenge(challenge);
    // Domain separation is part of the stored body identity. The same JSON
    // value used by another protocol domain must not have the same digest.
    return hashCanonical({
        domain: 'AE-CHALLENGE-BODY-v1',
        challenge,
    });
}
export function createDurableChallengeStore(backend, { issuerIdentity } = {}) {
    for (const method of ['addIfAbsent', 'compareAndSet', 'has']) {
        if (typeof backend?.[method] !== 'function') {
            throw new Error(`createDurableChallengeStore: backend must implement atomic async ${method}()`);
        }
    }
    const issuer = normalizedIssuerIdentity(issuerIdentity);
    const issuerScoped = issuerIdentity !== undefined;
    const canClassify = typeof backend.get === 'function';
    function keyFor(challenge) {
        return challengeStorageKey(challenge, issuer);
    }
    async function classify(challenge) {
        if (!canClassify) {
            throw new Error('challenge backend cannot authoritatively classify replay state');
        }
        const value = await backend.get(keyFor(challenge));
        if (value === undefined || value === null)
            return 'absent';
        const digest = challengeBodyDigest(challenge);
        if (typeof value !== 'string') {
            throw new Error('challenge store contains a malformed authoritative state value');
        }
        if (value.startsWith(OPEN_PREFIX)) {
            return value.slice(OPEN_PREFIX.length) === digest
                ? 'open-exact'
                : 'open-body-collision';
        }
        if (value.startsWith(CONSUMED_PREFIX)) {
            return value.slice(CONSUMED_PREFIX.length) === digest
                ? 'claimed-exact'
                : 'claimed-body-collision';
        }
        throw new Error('challenge store contains an unknown authoritative state value');
    }
    return {
        durable: backend.durable === true,
        atomicRegistration: true,
        bodyBound: true,
        permanentConsumption: true,
        authoritativeClassification: canClassify,
        issuerScoped,
        issuerIdentity: issuer,
        async register(challenge) {
            const key = keyFor(challenge);
            const digest = challengeBodyDigest(challenge);
            return (await backend.addIfAbsent(key, `${OPEN_PREFIX}${digest}`)) === true;
        },
        async consume(challenge) {
            const key = keyFor(challenge);
            const digest = challengeBodyDigest(challenge);
            return (await backend.compareAndSet(key, `${OPEN_PREFIX}${digest}`, `${CONSUMED_PREFIX}${digest}`)) === true;
        },
        ...(canClassify ? { classify } : {}),
        async has(challenge) {
            return (await backend.has(keyFor(challenge))) === true;
        },
    };
}
export default {
    createDurableChallengeStore,
    createAuthoritativeChallengeOwnerStore,
    createMemoryChallengeOwnerBackend,
    isAuthoritativeChallengeOwnerStore,
    challengeStorageKey,
    challengeBodyDigest,
    DURABLE_CHALLENGE_STORE_VERSION,
    AUTHORITATIVE_CHALLENGE_OWNER_VERSION,
};
//# sourceMappingURL=challenge-store.js.map