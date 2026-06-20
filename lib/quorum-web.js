// SPDX-License-Identifier: Apache-2.0
/**
 * EP-QUORUM-v1 — in-browser (Web Crypto) multi-party approval verifier.
 *
 * The async mirror of packages/verify/quorum.js: it composes the in-browser
 * verifyWebAuthnSignoff (lib/verify-web.js) once per member, then applies the
 * SAME fail-closed quorum predicate. Used by the /try multi-party demo so the
 * quorum verifies entirely client-side, nothing uploaded. Keep this in lockstep
 * with packages/verify/quorum.js — same predicates, same fail-closed semantics.
 */
import { verifyWebAuthnSignoff } from './verify-web.js';

export async function verifyQuorum(quorum, opts = {}) {
  const checks = {
    all_signatures_valid: false,
    action_binding: false,
    distinct_humans: false,
    roles_admitted: false,
    threshold_met: false,
    order_satisfied: false,
    within_window: false,
  };
  const members = Array.isArray(quorum?.members) ? quorum.members : null;
  const memberResults = [];

  try {
    const policy = quorum?.policy;
    const actionHash = quorum?.action_hash;
    if (!policy || !members || members.length === 0 || typeof actionHash !== 'string' || !actionHash) {
      return { valid: false, checks, members: memberResults };
    }

    const mode = policy.mode === 'ordered' ? 'ordered' : 'threshold';
    const distinctHumans = policy.distinct_humans !== false;
    const windowSec = Number.isFinite(policy.window_sec) ? policy.window_sec : 900;
    const eligible = Array.isArray(policy.approvers) ? policy.approvers : [];
    const required = mode === 'ordered'
      ? eligible.length
      : (Number.isInteger(policy.required) && policy.required > 0 ? policy.required : NaN);
    if (!Number.isInteger(required) || required <= 0 || eligible.length === 0) {
      return { valid: false, checks, members: memberResults };
    }

    let allSigsValid = true;
    let allBound = true;
    const issuedAts = [];
    for (const m of members) {
      const r = await verifyWebAuthnSignoff(m?.signoff, m?.approver_public_key, opts);
      memberResults.push({ approver: m?.signoff?.context?.approver ?? null, role: m?.role ?? null, valid: !!r.valid });
      if (!r.valid) allSigsValid = false;
      if (m?.signoff?.context?.action_hash !== actionHash) allBound = false;
      const t = Date.parse(m?.signoff?.context?.issued_at ?? '');
      issuedAts.push(Number.isNaN(t) ? null : t);
    }
    checks.all_signatures_valid = allSigsValid;
    checks.action_binding = allBound;

    const counted = members
      .map((m, i) => ({ m, i, ok: memberResults[i].valid && m?.signoff?.context?.action_hash === actionHash }))
      .filter((x) => x.ok);

    const countedApprovers = counted.map((x) => x.m?.signoff?.context?.approver);
    checks.distinct_humans = distinctHumans
      ? new Set(countedApprovers).size === countedApprovers.length
      : true;

    const eligibleSet = new Set(eligible.map((e) => `${e.role} ${e.approver}`));
    checks.roles_admitted = counted.length > 0 && counted.every((x) =>
      eligibleSet.has(`${x.m?.role} ${x.m?.signoff?.context?.approver}`));

    const distinctEligible = new Set(
      counted
        .filter((x) => eligibleSet.has(`${x.m?.role} ${x.m?.signoff?.context?.approver}`))
        .map((x) => x.m?.signoff?.context?.approver),
    );
    checks.threshold_met = distinctEligible.size >= required;

    if (mode === 'ordered') {
      const seqRolesOk = eligible.every((e, idx) => members[idx]?.role === e.role
        && members[idx]?.signoff?.context?.approver === e.approver);
      const times = issuedAts.slice(0, eligible.length);
      const timesOk = times.every((t, idx) => t !== null && (idx === 0 || t > times[idx - 1]));
      checks.order_satisfied = members.length >= eligible.length && seqRolesOk && timesOk;
    } else {
      checks.order_satisfied = true;
    }

    const ts = counted.map((x) => issuedAts[x.i]).filter((t) => t !== null);
    checks.within_window = ts.length === counted.length && counted.length > 0
      && (Math.max(...ts) - Math.min(...ts)) <= windowSec * 1000;
  } catch {
    return { valid: false, checks, members: memberResults };
  }

  const valid = checks.all_signatures_valid
    && checks.action_binding
    && checks.distinct_humans
    && checks.roles_admitted
    && checks.threshold_met
    && checks.order_satisfied
    && checks.within_window;
  return { valid, checks, members: memberResults };
}
