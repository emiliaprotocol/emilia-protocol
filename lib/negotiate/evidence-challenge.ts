// SPDX-License-Identifier: Apache-2.0
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
 * Framing: RFC 9470 (OAuth step-up) generalized from authentication to
 * EVIDENCE. A confirmation-interaction flow (CHEQ-style) composes as one
 * obtain_hints entry, not a competitor.
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

export const CHALLENGE_VERSION = 'AE-CHALLENGE-v1';
export const CHALLENGE_MEDIA_TYPE = 'application/authorization-evidence-challenge+json';

const SHA256_DIGEST_RE = /^sha256:[0-9a-f]{64}$/i;
const RFC3339_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;

function validSha256Digest(value) {
  return typeof value === 'string' && SHA256_DIGEST_RE.test(value);
}

function parseTimestamp(value) {
  if (typeof value !== 'string') return NaN;
  const match = value.match(RFC3339_INSTANT);
  if (!match) return NaN;
  const [, year, month, day, hour, minute, second, , offsetHour, offsetMinute] = match;
  const local = `${year}-${month}-${day}T${hour}:${minute}:${second}`;
  const calendar = new Date(0);
  calendar.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  calendar.setUTCHours(Number(hour), Number(minute), Number(second), 0);
  if (calendar.toISOString().slice(0, 19) !== local) return NaN;
  if (offsetHour !== undefined && (Number(offsetHour) > 23 || Number(offsetMinute) > 59)) return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function digestPolicy(policy) {
  return artifactDigest(policy ?? null);
}

function policyMatchesChallenge(challenge, policy) {
  if (!validSha256Digest(challenge?.policy_digest)) return false;
  try {
    return digestPolicy(policy) === challenge.policy_digest;
  } catch {
    return false;
  }
}

/**
 * Shared options bag threaded through the challenge mint / register / evaluate
 * lifecycle below. Every field is optional because each function only reads
 * the subset it needs; the type lives here once so `opts` can be spread from
 * one stage into the next (createFollowupEvidenceChallenge, evaluateRegisteredPresentation)
 * without losing fields.
 */
type EvidenceChallengeOpts = {
  expires_at?: string;
  nonce?: string;
  challenge_id?: string;
  prior?: { satisfied_by?: string[] } | null;
  obtain_hints?: any[];
  challengeStore?: {
    register: (challenge: any) => boolean | Promise<boolean>;
    consume: (challenge: any) => boolean | Promise<boolean>;
  };
  verifiers?: Record<string, any>;
  as_of?: string;
  consumedNonces?: Set<string>;
  next_expires_at?: string;
};

function mintChallengeForDigest(action_digest, policy, opts: EvidenceChallengeOpts = {}) {
  const expiresAt = parseTimestamp(opts.expires_at);
  if (Number.isNaN(expiresAt)) throw new Error('expires_at is required and MUST be a valid timestamp');
  if (!validSha256Digest(action_digest)) throw new Error('action_digest MUST be a sha256 digest');
  const nonce = opts.nonce ?? crypto.randomBytes(18).toString('base64url');
  if (typeof nonce !== 'string' || !nonce.trim()) throw new Error('nonce MUST be a non-empty string');
  return {
    '@version': CHALLENGE_VERSION,
    challenge_id: opts.challenge_id ?? crypto.randomUUID(),
    nonce,
    action_digest,
    reliance_purpose: policy?.reliance_purpose ?? null,
    policy_id: policy?.policy_id ?? null,
    policy_digest: digestPolicy(policy),
    required_evidence: deriveRequiredEvidence(policy, opts.prior ?? null),
    present_as: ['EP-AEG-v1'],
    obtain_hints: opts.obtain_hints ?? [],
    expires_at: opts.expires_at,
  };
}

/**
 * Derive the evidence a policy requires, minus what an (optional) prior
 * evaluation already satisfied — the machine-readable "go get this" list.
 * @param {object} policy
 * @param {{satisfied_by?: string[]}|null} [priorResult]
 */
export function deriveRequiredEvidence(policy, priorResult: { satisfied_by?: string[] } | null = null) {
  const tokens = String(policy?.requirement ?? '')
    .match(/[A-Za-z0-9_.:-]+/g)?.filter((t) => !['AND', 'OR'].includes(t.toUpperCase())) ?? [];
  const satisfied = new Set(priorResult?.satisfied_by ?? []);
  const assuranceByType = [policy?.required_assurance, policy?.assurance_class, policy?.assurance_classes]
    .find((v) => v && typeof v === 'object') ?? {};
  return [...new Set(tokens)].filter((t) => !satisfied.has(t)).map((type) => ({
    type,
    ...(typeof assuranceByType[type] === 'string' ? { assurance_class: assuranceByType[type] } : {}),
    ...(Number.isFinite(policy?.freshness_sec?.[type]) ? { fresh_max_sec: policy.freshness_sec[type] } : {}),
    ...(policy?.revocation_required?.includes(type) ? { revocation_checked: true } : {}),
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

function requireChallengeStore(store) {
  if (typeof store?.register !== 'function' || typeof store?.consume !== 'function') {
    throw new Error('durable challengeStore with register() and consume() is required');
  }
  return store;
}

/** Mint and atomically register a challenge before it is exposed to a caller. */
export async function createRegisteredEvidenceChallenge(action, policy, opts: EvidenceChallengeOpts = {}) {
  const store = requireChallengeStore(opts.challengeStore);
  const challenge = createEvidenceChallenge(action, policy, opts);
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
export function createFollowupEvidenceChallenge(challenge, policy, priorResult, opts: EvidenceChallengeOpts = {}) {
  if (challenge?.['@version'] !== CHALLENGE_VERSION) throw new Error('unknown challenge version');
  if (!policyMatchesChallenge(challenge, policy)) throw new Error('policy changed since the original challenge');
  const expires_at = opts.expires_at ?? challenge.expires_at;
  const nonce = opts.nonce === challenge.nonce ? undefined : opts.nonce;
  return mintChallengeForDigest(challenge.action_digest, policy, {
    ...opts,
    nonce,
    expires_at,
    prior: priorResult,
  });
}

/** Mint and atomically register a follow-up before returning it to a presenter. */
export async function createRegisteredFollowupEvidenceChallenge(challenge, policy, priorResult, opts: EvidenceChallengeOpts = {}) {
  const store = requireChallengeStore(opts.challengeStore);
  const next = createFollowupEvidenceChallenge(challenge, policy, priorResult, opts);
  if (await store.register(next) !== true) {
    throw new Error('follow-up challenge registration collision or replay');
  }
  return next;
}

/**
 * Server side: evaluate a presentation against the challenge it answers.
 * FAIL-CLOSED, in order: version/structure -> expiry -> nonce single-use ->
 * action agreement (TOCTOU) -> policy replay. On a non-admissible verdict,
 * a follow-up challenge (same action, remaining evidence, fresh nonce) is
 * returned so the loop continues machine-readably.
 *
 * @param {object} challenge   the challenge previously minted
 * @param {object} graphDoc    the presented EP-AEG evidence graph
 * @param {object} policy      the SAME relying-party policy (never from the wire)
 * @param {object} opts        {verifiers, as_of (REQUIRED), consumedNonces: Set,
 *                              next_expires_at?, nonce?}
 */
export function evaluatePresentation(challenge, graphDoc, policy, opts: EvidenceChallengeOpts = {}) {
  const refuse = (reason) => ({ verdict: 'refused', reasons: [reason], next_challenge: null });

  if (challenge?.['@version'] !== CHALLENGE_VERSION) return refuse('unknown challenge version');
  if (typeof challenge?.nonce !== 'string' || !challenge.nonce.trim()) return refuse('challenge nonce missing or invalid');
  if (!validSha256Digest(challenge.action_digest)) return refuse('challenge action_digest missing or invalid');
  if (!policyMatchesChallenge(challenge, policy)) return refuse('challenge policy_digest missing or policy changed');
  const expiresAt = parseTimestamp(challenge.expires_at);
  if (Number.isNaN(expiresAt)) return refuse('challenge expires_at missing or invalid');
  const asOf = parseTimestamp(opts.as_of);
  if (Number.isNaN(asOf)) return refuse('valid evaluation time (as_of) is required');
  if (asOf >= expiresAt) return refuse('challenge expired');
  const nonces = opts.consumedNonces;
  if (!(nonces instanceof Set)) return refuse('nonce ledger required (consumedNonces)');
  if (nonces.has(challenge.nonce)) return refuse('challenge nonce already consumed (replay)');
  nonces.add(challenge.nonce); // consumed on FIRST evaluation attempt, success or not

  if (graphDoc?.action_digest !== challenge.action_digest) {
    return refuse('presented graph binds a different action than the challenge (action swap)');
  }

  const result = evaluateEvidenceGraph(graphDoc, policy, { verifiers: opts.verifiers, as_of: opts.as_of });
  let next_challenge: ReturnType<typeof createFollowupEvidenceChallenge> | null = null;
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
export async function evaluateRegisteredPresentation(challenge, graphDoc, policy, opts: EvidenceChallengeOpts = {}) {
  const refuse = (reason) => ({ verdict: 'refused', reasons: [reason], next_challenge: null });

  if (challenge?.['@version'] !== CHALLENGE_VERSION) return refuse('unknown challenge version');
  if (typeof challenge?.nonce !== 'string' || !challenge.nonce.trim()) return refuse('challenge nonce missing or invalid');
  if (!validSha256Digest(challenge.action_digest)) return refuse('challenge action_digest missing or invalid');
  if (!policyMatchesChallenge(challenge, policy)) return refuse('challenge policy_digest missing or policy changed');
  const expiresAt = parseTimestamp(challenge.expires_at);
  if (Number.isNaN(expiresAt)) return refuse('challenge expires_at missing or invalid');
  const asOf = parseTimestamp(opts.as_of);
  if (Number.isNaN(asOf)) return refuse('valid evaluation time (as_of) is required');
  if (asOf >= expiresAt) return refuse('challenge expired');

  const store = requireChallengeStore(opts.challengeStore);
  if (await store.consume(challenge) !== true) {
    return refuse('challenge is unregistered, tampered, or already consumed (replay)');
  }
  if (graphDoc?.action_digest !== challenge.action_digest) {
    return refuse('presented graph binds a different action than the challenge (action swap)');
  }

  const result = evaluateEvidenceGraph(graphDoc, policy, { verifiers: opts.verifiers, as_of: opts.as_of });
  let next_challenge: Awaited<ReturnType<typeof createRegisteredFollowupEvidenceChallenge>> | null = null;
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
