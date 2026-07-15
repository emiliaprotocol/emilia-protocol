// SPDX-License-Identifier: Apache-2.0
/**
 * EP-QUORUM-v1 — in-browser (Web Crypto) multi-party approval verifier.
 *
 * The async mirror of packages/verify/quorum.js: it composes the in-browser
 * verifyWebAuthnSignoff (lib/verify-web.js) once per member, then applies the
 * SAME fail-closed quorum predicate. Used by the /try multi-party demo so the
 * quorum verifies entirely client-side, nothing uploaded. Keep this in lockstep
 * with packages/verify/quorum.js — same predicates, same fail-closed semantics.
 *
 * SECURITY BOUNDARY: member keys are carried inside the quorum document. This
 * proves internal cryptographic consistency only. Organizational acceptance
 * additionally requires an out-of-band approver directory and pinned policy.
 */
import { canonicalize, verifyWebAuthnSignoff } from './verify-web.js';

const utf8 = (value) => new TextEncoder().encode(value);

async function contextChainHash(context) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(canonicalize(context))));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function canonicalKeyFingerprint(spkiB64u) {
  try {
    if (typeof spkiB64u !== 'string' || !spkiB64u) return null;
    const b64 = spkiB64u.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    const binary = atob(padded);
    const input = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    const key = await crypto.subtle.importKey(
      'spki', input, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'],
    );
    const canonical = new Uint8Array(await crypto.subtle.exportKey('spki', key));
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', canonical));
    return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return null;
  }
}

export async function verifyQuorum(quorum, opts = {}) {
  const checks = {
    all_signatures_valid: false,
    action_binding: false,
    distinct_humans: false,
    distinct_keys: false,
    initiator_excluded: false,
    roles_admitted: false,
    threshold_met: false,
    order_satisfied: false,
    chain_linked: false,
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

    const mode = policy.mode;
    if (mode !== 'ordered' && mode !== 'threshold') {
      return { valid: false, checks, members: memberResults };
    }
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

    // Distinct device keys: cryptographic floor, unconditional (independent of
    // distinct_humans). One public key in two counted seats is one signer.
    const countedKeys = await Promise.all(counted.map((x) => canonicalKeyFingerprint(x.m?.approver_public_key)));
    checks.distinct_keys = countedKeys.every(Boolean)
      && new Set(countedKeys).size === countedKeys.length;

    // Initiator excluded (SoD): the action's initiator must not also approve it.
    // Require a single agreed initiator across counted members, present, and
    // absent from the counted approver set. Mirrors packages/verify/quorum.js.
    const countedInitiators = counted.map((x) => x.m?.signoff?.context?.initiator);
    const initiator = countedInitiators[0];
    checks.initiator_excluded = counted.length > 0
      && typeof initiator === 'string' && initiator.length > 0
      && countedInitiators.every((v) => v === initiator)
      && !countedApprovers.includes(initiator);

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

    if (mode === 'ordered' && policy.ordered_chain === true) {
      const sequence = members.slice(0, eligible.length);
      let linked = sequence.length === eligible.length;
      for (let index = 0; index < sequence.length; index++) {
        const predecessor = sequence[index]?.signoff?.context?.prev_context_hash;
        if (index === 0) {
          if (predecessor !== undefined && predecessor !== null) linked = false;
        } else if (predecessor !== await contextChainHash(sequence[index - 1]?.signoff?.context ?? {})) {
          linked = false;
        }
      }
      checks.chain_linked = linked;
    } else {
      checks.chain_linked = true;
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
    && checks.distinct_keys
    && checks.initiator_excluded
    && checks.roles_admitted
    && checks.threshold_met
    && checks.order_satisfied
    && checks.chain_linked
    && checks.within_window;
  return { valid, checks, members: memberResults };
}
