// SPDX-License-Identifier: Apache-2.0
// Generated from evidence-challenge.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * AE-CHALLENGE-v1 — the evidence negotiation loop (the missing live wire).
 *
 * THE VERB THIS DEFINES
 * ---------------------
 * The stack already has declaration (the action manifest), presentation (the
 * evidence graph), and decision (policy replay -> verdict). Nothing closes
 * the loop: when a relying party's verdict is "missing_evidence:
 * quorum_receipt, fresh<300s", no machine-readable message tells the agent
 * WHAT TO GO GET, how to re-present, or what the retry semantics are. This
 * module is that message and its lifecycle:
 *
 *   declare -> attempt -> CHALLENGE -> obtain -> present -> replay -> consume
 *
 * Framing: a transport-neutral evidence-negotiation object. It does not
 * replace OAuth Transaction Authorization Challenge or turn evidence into a
 * native OAuth grant. An explicit application profile can compose the two.
 *
 * TRUST BOUNDARIES
 * - The SERVER computes the action digest into the challenge. The agent
 *   obtains evidence against the server's canonical action, and the server
 *   recomputes at execution — a presentation whose graph binds a different
 *   action is refused outright (kills the time-of-check/time-of-use swap).
 * - Challenges are SINGLE-USE (nonce) and EXPIRE. A replayed or expired
 *   challenge fails closed before any policy evaluation runs.
 * - The challenge is not a commitment: satisfying it yields a verdict under
 *   the relying party's policy, never a promise to execute.
 */
import crypto from 'node:crypto';
import { artifactDigest, evaluateEvidenceGraph } from '../evidence/evidence-graph.js';
import { evaluateChainAdmissibility } from '../evidence/admissibility.js';
export const CHALLENGE_VERSION = 'AE-CHALLENGE-v1';
// draft-schrock-ae-challenge-03 separates the transport-neutral challenge
// from its HTTP carrier. HTTP reuses RFC 9457 Problem Details instead of
// defining a dedicated media type.
export const CHALLENGE_MEDIA_TYPE = 'application/problem+json';
export const CHALLENGE_HTTP_STATUS = 403;
export const CHALLENGE_PROBLEM_TYPE = 'https://iana.org/assignments/http-problem-types#ae-required';
export const CHALLENGE_PROBLEM_TITLE = 'Authorization Evidence Required';
export const CHALLENGE_PRESENTATION_METHOD = 'ep-aec-v1';
export const CHALLENGE_ACTION_PROFILE = 'https://emiliaprotocol.ai/profiles/artifact-digest-v1';
const CHALLENGE_PRESENTATION_DOCUMENT_VERSION = 'EP-AEC-v1';
const LEGACY_GRAPH_DOCUMENT_VERSION = 'EP-AEG-v1';
const SHA256_DIGEST_RE = /^sha256:[0-9a-f]{64}$/i;
const DURABLE_NONCE_RE = /^[A-Za-z0-9_-]{16,128}$/;
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const REQUIRED_PRODUCTION_STORE_CAPABILITIES = Object.freeze([
    'durable',
    'atomicRegistration',
    'bodyBound',
    'permanentConsumption',
]);
/**
 * Pure routing guard for integrations that support both mechanisms. The
 * caller derives these facts from native protocol state and local policy.
 * This helper never validates an OAuth challenge or evidence artifact.
 */
export function selectAuthorizationChallengeMechanism(input) {
    const nativeRequired = input?.native_transaction_authorization_required === true;
    const evidenceInsufficient = input?.independent_evidence_insufficient === true;
    if (nativeRequired) {
        return {
            primary: 'oauth-transaction-authorization',
            ae_challenge_allowed: evidenceInsufficient && input?.explicit_composition_profile === true,
            substitution_allowed: false,
        };
    }
    return {
        primary: evidenceInsufficient ? 'ae-challenge' : 'none',
        ae_challenge_allowed: evidenceInsufficient,
        substitution_allowed: false,
    };
}
function validSha256Digest(value) {
    return typeof value === 'string' && SHA256_DIGEST_RE.test(value);
}
function parseTimestamp(value) {
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
function digestPolicy(policy) {
    return artifactDigest(policy ?? null);
}
function policyMatchesChallenge(challenge, policy) {
    if (!validSha256Digest(challenge?.policy_digest))
        return false;
    try {
        return digestPolicy(policy) === challenge.policy_digest;
    }
    catch {
        return false;
    }
}
function mintChallengeForDigest(action_digest, policy, opts = {}) {
    const expiresAt = parseTimestamp(opts.expires_at);
    if (Number.isNaN(expiresAt))
        throw new Error('expires_at is required and MUST be a valid timestamp');
    if (!validSha256Digest(action_digest))
        throw new Error('action_digest MUST be a sha256 digest');
    const nonce = opts.nonce ?? crypto.randomBytes(18).toString('base64url');
    if (typeof nonce !== 'string' || !nonce.trim())
        throw new Error('nonce MUST be a non-empty string');
    const actionProfile = opts.action_profile ?? CHALLENGE_ACTION_PROFILE;
    if (typeof actionProfile !== 'string' || !actionProfile.trim() || actionProfile.length > 512) {
        throw new Error('action_profile MUST be a non-empty identifier of at most 512 characters');
    }
    if (opts.audience !== undefined
        && (typeof opts.audience !== 'string' || !opts.audience.trim() || opts.audience.length > 256)) {
        throw new Error('audience MUST be a non-empty string of at most 256 characters');
    }
    const presentAs = opts.present_as ?? [CHALLENGE_PRESENTATION_METHOD];
    if (!Array.isArray(presentAs) || presentAs.length === 0
        || new Set(presentAs).size !== presentAs.length
        || presentAs.some((method) => typeof method !== 'string' || !method.trim() || method.length > 128)) {
        throw new Error('present_as MUST contain unique non-empty method identifiers');
    }
    return {
        '@version': CHALLENGE_VERSION,
        challenge_id: opts.challenge_id ?? crypto.randomUUID(),
        nonce,
        action_digest,
        action_profile: actionProfile,
        reliance_purpose: policy?.reliance_purpose ?? null,
        policy_id: policy?.policy_id ?? null,
        policy_digest: digestPolicy(policy),
        required_evidence: deriveRequiredEvidence(policy, opts.prior ?? null),
        // draft-schrock-ae-challenge-00 uses AEC as its initial presentation
        // profile. The challenge remains only a request for evidence: presenting
        // an AEC object does not itself authorize or promise execution.
        present_as: [...presentAs],
        obtain_hints: opts.obtain_hints ?? [],
        expires_at: opts.expires_at,
        ...(opts.audience !== undefined ? { audience: opts.audience } : {}),
    };
}
function parseRequirementExpression(value) {
    const source = String(value ?? '').trim();
    if (!source)
        return null;
    const tokens = source.match(/\(|\)|AND|OR|[A-Za-z0-9_.:-]+/g) ?? [];
    if (tokens.join('') !== source.replace(/\s+/g, '')) {
        throw new Error('policy requirement contains an unknown token');
    }
    let cursor = 0;
    const peek = () => tokens[cursor];
    const take = () => tokens[cursor++];
    const atom = () => {
        const token = take();
        if (token === '(') {
            const nested = or();
            if (take() !== ')')
                throw new Error('policy requirement has unbalanced parentheses');
            return nested;
        }
        if (!token || token === 'AND' || token === 'OR' || token === ')') {
            throw new Error('policy requirement is malformed');
        }
        return { kind: 'type', value: token };
    };
    const and = () => {
        let left = atom();
        while (peek() === 'AND') {
            take();
            left = { kind: 'and', left, right: atom() };
        }
        return left;
    };
    const or = () => {
        let left = and();
        while (peek() === 'OR') {
            take();
            left = { kind: 'or', left, right: and() };
        }
        return left;
    };
    const parsed = or();
    if (cursor !== tokens.length)
        throw new Error('policy requirement has trailing tokens');
    return parsed;
}
function missingTypes(node, satisfied) {
    if (!node)
        return [];
    if (node.kind === 'type')
        return satisfied.has(node.value) ? [] : [node.value];
    const left = missingTypes(node.left, satisfied);
    const right = missingTypes(node.right, satisfied);
    if (node.kind === 'and')
        return [...new Set([...left, ...right])];
    // An OR is satisfied by one branch. Request the least-disclosing branch;
    // ties are stable and follow the relying party's written order.
    return left.length <= right.length ? left : right;
}
/**
 * Derive the evidence a policy requires, minus what an (optional) prior
 * evaluation already satisfied — the machine-readable "go get this" list.
 * @param {object} policy
 * @param {{satisfied_by?: string[]}|null} [priorResult]
 */
export function deriveRequiredEvidence(policy, priorResult = null) {
    const satisfied = new Set(priorResult?.satisfied_by ?? []);
    const tokens = missingTypes(parseRequirementExpression(policy?.requirement), satisfied);
    const assuranceByType = [policy?.required_assurance, policy?.assurance_class, policy?.assurance_classes]
        .find((v) => v && typeof v === 'object') ?? {};
    return [...new Set(tokens)].map((type) => ({
        requirement_id: type,
        type,
        ...(typeof assuranceByType[type] === 'string' ? { assurance_class: assuranceByType[type] } : {}),
        ...(Number.isFinite(policy?.freshness_sec?.[type]) ? {
            max_age_sec: policy.freshness_sec[type],
        } : {}),
        ...(policy?.revocation_required?.includes(type) ? {
            status: 'current',
        } : {}),
        ...(typeof policy?.profiles?.[type] === 'string' ? { profiles: [policy.profiles[type]] } : {}),
        ...(Array.isArray(policy?.proof_predicates?.[type])
            ? { proof_predicates: [...policy.proof_predicates[type]] }
            : {}),
    }));
}
/**
 * Server side: mint a challenge for an attempted action under a policy.
 * @param {object} action  the SERVER's canonical action object (never the client's)
 * @param {object} policy  the relying-party evidence policy (e.g. a policy pack)
 * @param {object} opts    {expires_at (REQUIRED, ISO), nonce?, obtain_hints?, prior?}
 */
export function createEvidenceChallenge(action, policy, opts = {}) {
    return mintChallengeForDigest(artifactDigest(action), policy, opts);
}
/**
 * RFC 9457 HTTP binding for the transport-neutral challenge core.
 * The challenge remains a refusal with information: wrapping it in a Problem
 * Details response does not authorize the action or promise a later effect.
 */
export function createEvidenceChallengeProblem(challenge, opts = {}) {
    if (challenge?.['@version'] !== CHALLENGE_VERSION) {
        throw new Error('unknown challenge version');
    }
    if (typeof challenge?.nonce !== 'string' || !challenge.nonce.trim()) {
        throw new Error('challenge nonce missing or invalid');
    }
    if (!validSha256Digest(challenge?.action_digest)) {
        throw new Error('challenge action_digest missing or invalid');
    }
    if (typeof challenge?.action_profile !== 'string' || !challenge.action_profile.trim()) {
        throw new Error('challenge action_profile missing or invalid');
    }
    if (Number.isNaN(parseTimestamp(challenge?.expires_at))) {
        throw new Error('challenge expires_at missing or invalid');
    }
    const body = {
        type: CHALLENGE_PROBLEM_TYPE,
        title: CHALLENGE_PROBLEM_TITLE,
        status: CHALLENGE_HTTP_STATUS,
        detail: opts.detail ?? 'The action was refused because required authorization evidence is unavailable.',
        ...(opts.instance !== undefined ? { instance: opts.instance } : {}),
        evidence_challenge: challenge,
    };
    return {
        status: CHALLENGE_HTTP_STATUS,
        headers: Object.freeze({
            'content-type': CHALLENGE_MEDIA_TYPE,
            'cache-control': 'no-store',
        }),
        body,
    };
}
/** Parse and validate the RFC 9457 binding without treating it as authority. */
export function parseEvidenceChallengeProblem(response) {
    const contentType = String(response?.headers?.['content-type']
        ?? response?.headers?.get?.('content-type')
        ?? '').split(';', 1)[0].trim().toLowerCase();
    const body = response?.body;
    if (response?.status !== CHALLENGE_HTTP_STATUS) {
        throw new Error('evidence challenge HTTP response MUST use status 403');
    }
    if (contentType !== CHALLENGE_MEDIA_TYPE) {
        throw new Error('evidence challenge HTTP response MUST use application/problem+json');
    }
    if (body?.type !== CHALLENGE_PROBLEM_TYPE
        || body?.title !== CHALLENGE_PROBLEM_TITLE
        || body?.status !== CHALLENGE_HTTP_STATUS) {
        throw new Error('evidence challenge Problem Details metadata is invalid');
    }
    const challenge = body?.evidence_challenge;
    if (challenge?.['@version'] !== CHALLENGE_VERSION
        || typeof challenge?.nonce !== 'string'
        || !challenge.nonce.trim()
        || !validSha256Digest(challenge?.action_digest)
        || typeof challenge?.action_profile !== 'string'
        || !challenge.action_profile.trim()
        || Number.isNaN(parseTimestamp(challenge?.expires_at))) {
        throw new Error('evidence_challenge extension is missing or invalid');
    }
    return challenge;
}
function requireChallengeStore(store, opts = {}) {
    if (typeof store?.register !== 'function' || typeof store?.consume !== 'function') {
        throw new Error('durable challengeStore with register() and consume() is required');
    }
    const production = opts.production ?? process.env.NODE_ENV === 'production';
    const testOnlyEphemeral = opts.test_only_ephemeral === true;
    if (testOnlyEphemeral && process.env.NODE_ENV !== 'test') {
        throw new Error('test_only_ephemeral challenge storage is allowed only under NODE_ENV=test');
    }
    if (production && !testOnlyEphemeral) {
        const missing = REQUIRED_PRODUCTION_STORE_CAPABILITIES.filter((capability) => store[capability] !== true);
        if (missing.length > 0) {
            throw new Error(`production challengeStore lacks required durable lifecycle capabilities: ${missing.join(', ')}`);
        }
    }
    return store;
}
/** Mint and atomically register a challenge before it is exposed to a caller. */
export async function createRegisteredEvidenceChallenge(action, policy, opts = {}) {
    const store = requireChallengeStore(opts.challengeStore, opts);
    const challenge = createEvidenceChallenge(action, policy, opts);
    if (!DURABLE_NONCE_RE.test(challenge.nonce)) {
        throw new Error('durable challenge nonce MUST be 16-128 base64url characters');
    }
    if (await store.register(challenge) !== true) {
        throw new Error('challenge registration collision or replay');
    }
    return challenge;
}
/**
 * Server side: mint the next challenge in an existing negotiation loop.
 * The action digest is copied from the original server-minted challenge; it is
 * never recomputed from the presented graph or any other presenter input.
 */
export function createFollowupEvidenceChallenge(challenge, policy, priorResult, opts = {}) {
    if (challenge?.['@version'] !== CHALLENGE_VERSION)
        throw new Error('unknown challenge version');
    if (!policyMatchesChallenge(challenge, policy))
        throw new Error('policy changed since the original challenge');
    const expires_at = opts.expires_at ?? challenge.expires_at;
    const nonce = opts.nonce === challenge.nonce ? undefined : opts.nonce;
    return mintChallengeForDigest(challenge.action_digest, policy, {
        ...opts,
        nonce,
        expires_at,
        prior: priorResult,
        audience: opts.audience ?? challenge.audience,
        action_profile: opts.action_profile ?? challenge.action_profile,
        present_as: opts.present_as ?? challenge.present_as,
    });
}
/** Mint and atomically register a follow-up before returning it to a presenter. */
export async function createRegisteredFollowupEvidenceChallenge(challenge, policy, priorResult, opts = {}) {
    const store = requireChallengeStore(opts.challengeStore, opts);
    const next = createFollowupEvidenceChallenge(challenge, policy, priorResult, opts);
    if (!DURABLE_NONCE_RE.test(next.nonce)) {
        throw new Error('durable challenge nonce MUST be 16-128 base64url characters');
    }
    if (await store.register(next) !== true) {
        throw new Error('follow-up challenge registration collision or replay');
    }
    return next;
}
function validateAudience(challenge, opts) {
    if (challenge?.audience === undefined && opts.expected_audience === undefined)
        return null;
    if (typeof challenge?.audience !== 'string' || !challenge.audience.trim()) {
        return 'challenge audience missing or invalid';
    }
    if (typeof opts.expected_audience !== 'string' || !opts.expected_audience.trim()) {
        return 'expected audience is required for an audience-bound challenge';
    }
    return challenge.audience === opts.expected_audience
        ? null
        : 'challenge audience does not match this relying party';
}
function validPresentationContract(challenge) {
    return Array.isArray(challenge?.present_as)
        && challenge.present_as.length === 1
        && challenge.present_as[0] === CHALLENGE_PRESENTATION_METHOD;
}
function evaluateEvidencePresentation(challenge, presentation, policy, opts) {
    // The active -00 AEC profile explicitly permits carrying the graph
    // serialization used by the earlier implementation. It remains one AEC
    // presentation profile, not a second satisfaction protocol.
    if (presentation?.['@version'] === LEGACY_GRAPH_DOCUMENT_VERSION) {
        return evaluateEvidenceGraph(presentation, policy, {
            verifiers: opts.verifiers,
            as_of: opts.as_of,
        });
    }
    return evaluateChainAdmissibility(presentation, policy, {
        verifiers: opts.verifiers,
        keysByType: opts.keysByType,
        policiesByType: opts.policiesByType,
        expectedActionDigest: challenge.action_digest,
        as_of: opts.as_of,
        verificationTime: opts.as_of,
    });
}
function presentedActionDigest(presentation) {
    if (presentation?.['@version'] === LEGACY_GRAPH_DOCUMENT_VERSION) {
        return validSha256Digest(presentation.action_digest)
            ? presentation.action_digest.toLowerCase()
            : null;
    }
    if (presentation?.['@version'] !== CHALLENGE_PRESENTATION_DOCUMENT_VERSION) {
        return null;
    }
    try {
        return artifactDigest(presentation.action);
    }
    catch {
        return null;
    }
}
function supportedPresentationDocument(presentation) {
    return presentation?.['@version'] === CHALLENGE_PRESENTATION_DOCUMENT_VERSION
        || presentation?.['@version'] === LEGACY_GRAPH_DOCUMENT_VERSION;
}
/**
 * Server side: evaluate a presentation against the challenge it answers.
 * FAIL-CLOSED, in order: version/structure -> expiry -> nonce single-use ->
 * action agreement (TOCTOU) -> policy replay. On a non-admissible verdict,
 * a follow-up challenge (same action, remaining evidence, fresh nonce) is
 * returned so the loop continues machine-readably.
 *
 * @param {object} challenge   the challenge previously minted
 * @param {object} graphDoc    the presented EP-AEC evidence object
 * @param {object} policy      the SAME relying-party policy (never from the wire)
 * @param {object} opts        {verifiers, as_of (REQUIRED), consumedNonces: Set,
 *                              next_expires_at?, nonce?}
 */
export function evaluatePresentation(challenge, graphDoc, policy, opts = {}) {
    const refuse = (reason) => ({ verdict: 'refused', reasons: [reason], next_challenge: null });
    if (challenge?.['@version'] !== CHALLENGE_VERSION)
        return refuse('unknown challenge version');
    if (typeof challenge?.nonce !== 'string' || !challenge.nonce.trim())
        return refuse('challenge nonce missing or invalid');
    if (!validSha256Digest(challenge.action_digest))
        return refuse('challenge action_digest missing or invalid');
    if (typeof challenge?.action_profile !== 'string' || !challenge.action_profile.trim()) {
        return refuse('challenge action_profile missing or invalid');
    }
    if (!policyMatchesChallenge(challenge, policy))
        return refuse('challenge policy_digest missing or policy changed');
    if (!validPresentationContract(challenge))
        return refuse('challenge presentation method is not the AE-CHALLENGE-v1 ep-aec-v1 profile');
    const audienceError = validateAudience(challenge, opts);
    if (audienceError)
        return refuse(audienceError);
    const expiresAt = parseTimestamp(challenge.expires_at);
    if (Number.isNaN(expiresAt))
        return refuse('challenge expires_at missing or invalid');
    const asOf = parseTimestamp(opts.as_of);
    if (Number.isNaN(asOf))
        return refuse('valid evaluation time (as_of) is required');
    if (asOf >= expiresAt)
        return refuse('challenge expired');
    const nonces = opts.consumedNonces;
    if (!(nonces instanceof Set))
        return refuse('nonce ledger required (consumedNonces)');
    if (nonces.has(challenge.nonce))
        return refuse('challenge nonce already consumed (replay)');
    nonces.add(challenge.nonce); // consumed on FIRST evaluation attempt, success or not
    if (!supportedPresentationDocument(graphDoc)) {
        return refuse('presented evidence uses a method not advertised by the challenge');
    }
    const presentationDigest = presentedActionDigest(graphDoc);
    if (presentationDigest === null) {
        return refuse('presented evidence action is missing or not canonicalizable');
    }
    if (presentationDigest !== challenge.action_digest) {
        return refuse('presented evidence binds a different action than the challenge (action swap)');
    }
    const result = evaluateEvidencePresentation(challenge, graphDoc, policy, opts);
    let next_challenge = null;
    if (result.verdict !== 'admissible') {
        next_challenge = createFollowupEvidenceChallenge(challenge, policy, result, {
            expires_at: opts.next_expires_at ?? challenge.expires_at,
            nonce: opts.nonce,
        });
    }
    return { verdict: result.verdict, reasons: result.reasons, replay_digest: result.replay_digest, result, next_challenge };
}
/**
 * Durable production evaluation path. Unlike evaluatePresentation's legacy
 * in-process Set contract, this function requires an atomically registered
 * challenge and consumes its exact body on the first evaluation attempt.
 * Backend errors propagate so an outage cannot become a freshness verdict.
 */
export async function evaluateRegisteredPresentation(challenge, graphDoc, policy, opts = {}) {
    const refuse = (reason) => ({ verdict: 'refused', reasons: [reason], next_challenge: null });
    const store = requireChallengeStore(opts.challengeStore, opts);
    if (challenge?.['@version'] !== CHALLENGE_VERSION)
        return refuse('unknown challenge version');
    if (typeof challenge?.nonce !== 'string' || !challenge.nonce.trim())
        return refuse('challenge nonce missing or invalid');
    if (!DURABLE_NONCE_RE.test(challenge.nonce))
        return refuse('durable challenge nonce missing or too weak');
    if (!validSha256Digest(challenge.action_digest))
        return refuse('challenge action_digest missing or invalid');
    if (!policyMatchesChallenge(challenge, policy))
        return refuse('challenge policy_digest missing or policy changed');
    if (!validPresentationContract(challenge))
        return refuse('challenge presentation method is not the AE-CHALLENGE-v1 ep-aec-v1 profile');
    const audienceError = validateAudience(challenge, opts);
    if (audienceError)
        return refuse(audienceError);
    const expiresAt = parseTimestamp(challenge.expires_at);
    if (Number.isNaN(expiresAt))
        return refuse('challenge expires_at missing or invalid');
    const asOf = parseTimestamp(opts.as_of);
    if (Number.isNaN(asOf))
        return refuse('valid evaluation time (as_of) is required');
    if (asOf >= expiresAt)
        return refuse('challenge expired');
    if (await store.consume(challenge) !== true) {
        return refuse('challenge is unregistered, tampered, or already consumed (replay)');
    }
    if (!supportedPresentationDocument(graphDoc)) {
        return refuse('presented evidence uses a method not advertised by the challenge');
    }
    const presentationDigest = presentedActionDigest(graphDoc);
    if (presentationDigest === null) {
        return refuse('presented evidence action is missing or not canonicalizable');
    }
    if (presentationDigest !== challenge.action_digest) {
        return refuse('presented evidence binds a different action than the challenge (action swap)');
    }
    const result = evaluateEvidencePresentation(challenge, graphDoc, policy, opts);
    let next_challenge = null;
    if (result.verdict !== 'admissible') {
        next_challenge = await createRegisteredFollowupEvidenceChallenge(challenge, policy, result, {
            ...opts,
            expires_at: opts.next_expires_at ?? challenge.expires_at,
            nonce: opts.nonce,
            challengeStore: store,
        });
    }
    return { verdict: result.verdict, reasons: result.reasons, replay_digest: result.replay_digest, result, next_challenge };
}
