// SPDX-License-Identifier: Apache-2.0
/**
 * EP multi-party signoff orchestration — the "trail of signatories" engine.
 *
 * Pure, stateless logic over the attestations collected for a quorum-gated
 * action. Two responsibilities:
 *
 *   canAccept()  — incremental, server-side enforcement: when a new approver
 *                  attests, decide whether to ACCEPT it into the trail. Rejects
 *                  a wrong action, an ineligible role, a duplicate human, an
 *                  out-of-order signer (ordered mode), a stale signature
 *                  (outside the window), or a bad signature — *at attest time*,
 *                  so a bad signer never enters the trail.
 *   quorumGate() — is the accumulated trail a SATISFIED quorum? Composes the
 *                  frozen, cross-language-verified verifyQuorum (the same
 *                  fail-closed predicate JS/Python/Go agree on). An action may
 *                  only consume the signoff once this returns satisfied:true.
 *
 * This is the deployment-agnostic core. The fielded flow (persist the quorum
 * policy on a challenge; store each accepted attestation; gate consume on
 * quorumGate) wires DB + API routes to these functions — that layer is the
 * next increment; this module is what it enforces with.
 */
import { verifyQuorum, verifyWebAuthnSignoff } from '../../packages/verify/index.js';

const ctxOf = (m) => m?.signoff?.context ?? {};
const slotKey = (role, approver) => `${role} ${approver}`;

/**
 * Should an incoming attestation be admitted into the trail?
 * @returns {{ ok: boolean, reason?: string }}
 */
export function canAccept(policy, actionHash, existing, incoming, opts = {}) {
  if (!policy || typeof actionHash !== 'string' || !actionHash) return { ok: false, reason: 'no_policy' };
  const eligible = Array.isArray(policy.approvers) ? policy.approvers : [];
  if (eligible.length === 0) return { ok: false, reason: 'no_eligible_approvers' };
  const distinctHumans = policy.distinct_humans !== false;
  const windowSec = Number.isFinite(policy.window_sec) ? policy.window_sec : 900;
  const ordered = policy.mode === 'ordered';
  const cx = ctxOf(incoming);

  // 1. Action binding — must be signing the exact action this quorum authorizes.
  if (cx.action_hash !== actionHash) return { ok: false, reason: 'action_mismatch' };

  // 2. Role eligibility — (role, approver) must be a slot on the roster.
  const eligibleSet = new Set(eligible.map((e) => slotKey(e.role, e.approver)));
  if (!eligibleSet.has(slotKey(incoming?.role, cx.approver))) return { ok: false, reason: 'ineligible_role' };

  // 3. Separation of duties — no human fills two slots.
  if (distinctHumans && existing.some((m) => ctxOf(m).approver === cx.approver)) {
    return { ok: false, reason: 'duplicate_human' };
  }

  // 4. Order — in ordered mode the next signer must be the next roster slot.
  if (ordered) {
    const expected = eligible[existing.length];
    if (!expected || incoming?.role !== expected.role || cx.approver !== expected.approver) {
      return { ok: false, reason: 'out_of_order' };
    }
  }

  // 5. Window — within window_sec of the first accepted signature.
  if (existing.length > 0) {
    const t0 = Date.parse(ctxOf(existing[0]).issued_at ?? '');
    const ti = Date.parse(cx.issued_at ?? '');
    if (Number.isNaN(t0) || Number.isNaN(ti) || Math.abs(ti - t0) > windowSec * 1000) {
      return { ok: false, reason: 'window_exceeded' };
    }
    if (ordered && !(ti > Date.parse(ctxOf(existing[existing.length - 1]).issued_at ?? ''))) {
      return { ok: false, reason: 'non_increasing_time' };
    }
  }

  // 6. Signature — the device assertion must actually verify.
  if (!verifyWebAuthnSignoff(incoming?.signoff, incoming?.approver_public_key, opts).valid) {
    return { ok: false, reason: 'invalid_signature' };
  }

  return { ok: true };
}

/**
 * Is the accumulated trail a satisfied quorum? Composes verifyQuorum (the
 * frozen, tri-language-verified predicate). An action may consume only when
 * satisfied === true.
 * @returns {{ satisfied: boolean, checks: object, members: Array }}
 */
export function quorumGate(policy, actionHash, members, opts = {}) {
  const r = verifyQuorum({ '@type': 'ep.quorum', action_hash: actionHash, policy, members }, opts);
  return { satisfied: r.valid, checks: r.checks, members: r.members };
}

/**
 * Convenience: fold a stream of candidate attestations through canAccept, then
 * gate. Returns the accepted trail, any rejections (with reasons), and whether
 * the quorum is satisfied. Pure — does no I/O.
 */
export function evaluateTrail(policy, actionHash, candidates, opts = {}) {
  const accepted = [];
  const rejected = [];
  for (const c of candidates || []) {
    const r = canAccept(policy, actionHash, accepted, c, opts);
    if (r.ok) accepted.push(c);
    else rejected.push({ approver: ctxOf(c).approver ?? null, role: c?.role ?? null, reason: r.reason });
  }
  const gate = quorumGate(policy, actionHash, accepted, opts);
  return { accepted, rejected, ...gate };
}
