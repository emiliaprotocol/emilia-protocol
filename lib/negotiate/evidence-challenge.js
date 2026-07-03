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

/**
 * Derive the evidence a policy requires, minus what an (optional) prior
 * evaluation already satisfied — the machine-readable "go get this" list.
 */
export function deriveRequiredEvidence(policy, priorResult = null) {
  const tokens = String(policy?.requirement ?? '')
    .match(/[A-Za-z0-9_.:-]+/g)?.filter((t) => t !== 'AND' && t !== 'OR') ?? [];
  const satisfied = new Set(priorResult?.satisfied_by ?? []);
  return [...new Set(tokens)].filter((t) => !satisfied.has(t)).map((type) => ({
    type,
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
  if (!opts.expires_at) throw new Error('expires_at is required — challenges MUST expire');
  return {
    '@version': CHALLENGE_VERSION,
    challenge_id: opts.challenge_id ?? crypto.randomUUID(),
    nonce: opts.nonce ?? crypto.randomBytes(18).toString('base64url'),
    action_digest: artifactDigest(action),
    reliance_purpose: policy?.reliance_purpose ?? null,
    policy_id: policy?.policy_id ?? null,
    required_evidence: deriveRequiredEvidence(policy, opts.prior ?? null),
    present_as: ['EP-AEG-v1'],
    obtain_hints: opts.obtain_hints ?? [],
    expires_at: opts.expires_at,
  };
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
export function evaluatePresentation(challenge, graphDoc, policy, opts = {}) {
  const refuse = (reason) => ({ verdict: 'refused', reasons: [reason], next_challenge: null });

  if (challenge?.['@version'] !== CHALLENGE_VERSION) return refuse('unknown challenge version');
  if (!opts.as_of) return refuse('evaluation time (as_of) is required');
  if (Date.parse(opts.as_of) >= Date.parse(challenge.expires_at)) return refuse('challenge expired');
  const nonces = opts.consumedNonces;
  if (!(nonces instanceof Set)) return refuse('nonce ledger required (consumedNonces)');
  if (nonces.has(challenge.nonce)) return refuse('challenge nonce already consumed (replay)');
  nonces.add(challenge.nonce); // consumed on FIRST evaluation attempt, success or not

  if (graphDoc?.action_digest !== challenge.action_digest) {
    return refuse('presented graph binds a different action than the challenge (action swap)');
  }

  const result = evaluateEvidenceGraph(graphDoc, policy, { verifiers: opts.verifiers, as_of: opts.as_of });
  let next_challenge = null;
  if (result.verdict !== 'admissible') {
    next_challenge = createEvidenceChallenge(
      { __digest_passthrough: true }, policy,
      { expires_at: opts.next_expires_at ?? challenge.expires_at, nonce: opts.nonce, prior: result },
    );
    // same action as the original challenge — never recomputed from client input
    next_challenge.action_digest = challenge.action_digest;
  }
  return { verdict: result.verdict, reasons: result.reasons, replay_digest: result.replay_digest, result, next_challenge };
}
