// SPDX-License-Identifier: Apache-2.0
/**
 * EP-QUORUM-v1 — multi-party (M-of-N / ordered) approval verification.
 *
 * The "two-person rule," generalized and made offline-verifiable. For the
 * highest-stakes irreversible actions, a single named-human signoff is not
 * enough: policy can require a QUORUM of named humans, each cryptographically
 * binding their own device assertion to the SAME exact action, optionally in a
 * fixed order, all within a time window.
 *
 * This is ADDITIVE over EP-SIGNOFF-v1: it composes the frozen single-signoff
 * verifier (verifyWebAuthnSignoff) once per member and then applies the quorum
 * predicate. No new cryptography and no new trust primitive are introduced —
 * which keeps the existing formal-verification and conformance story intact.
 *
 * FAIL-CLOSED by construction: the quorum is `valid: true` only when EVERY
 * predicate holds. Any missing field, parse error, or unmet predicate yields
 * `valid: false`. A partial quorum is a positive "not authorized" signal.
 *
 * VERIFIED ≠ AUTHORIZED-BY-ORG — the policy is an INPUT, not a trust anchor
 * (mirroring federation.js's verified-vs-accepted discipline). `valid: true`
 * means the members are internally consistent with the `policy` and
 * `approver_public_key`s THIS FUNCTION WAS HANDED — threshold met, distinct
 * humans, roster admitted, window, ordering, signatures. It says NOTHING about
 * whether that policy is the one the organization actually requires. A weaker
 * policy (`required: 1`, a hand-picked roster, a long window) will `valid` just
 * as cleanly as the org's true 2-of-3. Therefore the caller MUST source both
 * inputs OUT OF BAND from trusted material, not from the receipt creator:
 *   - the `policy` from an org-pinned template keyed by (org, action_type)
 *     — see lib/guard-quorum-template.js (evaluateQuorumAgainstTemplate); and
 *   - each `approver_public_key` from server-side enrollment
 *     (approver_credentials), never from the receipt/quorum document.
 * Verifying a creator-declared policy against creator-declared keys proves only
 * internal consistency — it is not authorization.
 */
import crypto from 'node:crypto';
import { verifyWebAuthnSignoff, contextChainHash } from './index.js';

function rosterSlotKey(role, approver) {
  return JSON.stringify([role, approver]);
}

function spkiFingerprint(value) {
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(value, 'base64url'),
      format: 'der',
      type: 'spki',
    });
    const der = key.export({ type: 'spki', format: 'der' });
    return crypto.createHash('sha256').update(der).digest('hex');
  } catch {
    return null;
  }
}

/**
 * @param {object} quorum  EP-QUORUM-v1 document:
 *   {
 *     "@type": "ep.quorum",
 *     action_hash: string,                  // the action the whole quorum authorizes
 *     policy: {
 *       mode: "threshold" | "ordered",
 *       required: number,                   // M (threshold mode); ordered requires all listed
 *       approvers: [{ role: string, approver: string }],  // N eligible (role -> named human)
 *       distinct_humans?: boolean,          // default true
 *       window_sec?: number,                // default 900; max span across signatures
 *     },
 *     members: [{ role: string, approver_public_key: string, signoff: {context, webauthn} }],
 *   }
 * @param {object} [opts]  Passed through to each per-signer verify (e.g. { rpId }).
 * @returns {{ valid: boolean, checks: object, members: Array<{approver:string|null, role:string|null, valid:boolean}> }}
 */
export function verifyQuorum(quorum, opts = {}) {
  const checks = {
    all_signatures_valid: false, // every member's device assertion verifies
    action_binding: false,       // every member signed the SAME quorum action_hash
    distinct_humans: false,      // no human fills two slots (separation of duties)
    distinct_keys: false,        // no single device key fills two slots
    initiator_excluded: false,   // the action's initiator is not one of the approvers (SoD)
    roles_admitted: false,       // each (role, approver) is an eligible policy slot
    threshold_met: false,        // >= required distinct valid approvers
    order_satisfied: false,      // ordered mode: signed in policy sequence, increasing time
    chain_linked: false,         // ordered mode: each signoff cryptographically chains to its predecessor
    within_window: false,        // all signatures within window_sec
  };
  const memberResults = [];

  try {
    const policy = quorum?.policy;
    const members = Array.isArray(quorum?.members) ? quorum.members : null;
    const actionHash = quorum?.action_hash;
    if (!policy || !members || members.length === 0 || typeof actionHash !== 'string' || !actionHash) {
      return { valid: false, checks, members: memberResults };
    }

    const mode = policy.mode;
    if (mode !== 'ordered' && mode !== 'threshold') {
      return { valid: false, checks, members: memberResults };
    }
    const distinctHumans = policy.distinct_humans !== false; // default true
    const windowSec = Number.isFinite(policy.window_sec) ? policy.window_sec : 900;
    const eligible = Array.isArray(policy.approvers) ? policy.approvers : [];
    const required = mode === 'ordered'
      ? eligible.length
      : (Number.isInteger(policy.required) && policy.required > 0 ? policy.required : NaN);
    if (!Number.isInteger(required) || required <= 0 || eligible.length === 0) {
      return { valid: false, checks, members: memberResults };
    }

    // 1. Per-member device-assertion verification (compose the frozen verifier).
    let allSigsValid = true;
    let allBound = true;
    const approverIds = [];
    const issuedAts = [];
    for (const m of members) {
      const r = verifyWebAuthnSignoff(m?.signoff, m?.approver_public_key, opts);
      const approver = m?.signoff?.context?.approver ?? null;
      const role = m?.role ?? null;
      memberResults.push({ approver, role, valid: !!r.valid });
      if (!r.valid) allSigsValid = false;
      // 2. Action binding: each member must have signed the quorum's action_hash.
      if (m?.signoff?.context?.action_hash !== actionHash) allBound = false;
      approverIds.push(approver);
      const t = Date.parse(m?.signoff?.context?.issued_at ?? '');
      issuedAts.push(Number.isNaN(t) ? null : t);
    }
    checks.all_signatures_valid = allSigsValid;
    checks.action_binding = allBound;

    // Only members whose assertion verified AND is bound count toward the quorum.
    const counted = members
      .map((m, i) => ({ m, i, ok: memberResults[i].valid && m?.signoff?.context?.action_hash === actionHash }))
      .filter((x) => x.ok);

    // 3. Distinct humans (separation of duties).
    const countedApprovers = counted.map((x) => x.m?.signoff?.context?.approver);
    checks.distinct_humans = distinctHumans
      ? new Set(countedApprovers).size === countedApprovers.length
      : true;

    // 3b. Distinct device keys: no single public key may fill two counted slots.
    //     Defends against one device key enrolled under two approver identities
    //     (which would pass distinct_humans by name while being one signer).
    //     Key-uniqueness is a cryptographic floor, NOT a separation-of-duties
    //     preference: it holds unconditionally, even when distinct_humans is
    //     disabled. One key in two counted seats is one signer, never a quorum.
    const countedKeys = counted.map((x) => spkiFingerprint(x.m?.approver_public_key));
    checks.distinct_keys = countedKeys.every(Boolean)
      && new Set(countedKeys).size === countedKeys.length;

    // 3c. Initiator excluded (separation of duties): the human/agent that
    //     INITIATED the action must never also approve it. Every signed member
    //     context carries context.initiator; require it to be present, to be the
    //     SAME initiator across all counted members, and to differ from every
    //     counted member's own approver identity. Mirrors verifyTrustReceipt's
    //     `initiator && approvers.includes(initiator)` SoD check (index.js).
    const countedInitiators = counted.map((x) => x.m?.signoff?.context?.initiator);
    const initiator = countedInitiators[0];
    checks.initiator_excluded = counted.length > 0
      && typeof initiator === 'string' && initiator.length > 0
      && countedInitiators.every((v) => v === initiator)
      && !countedApprovers.includes(initiator);

    // 4. Roles admitted: each counted member's (role, approver) is an eligible slot.
    const eligibleSet = new Set(eligible.map((e) => rosterSlotKey(e.role, e.approver)));
    checks.roles_admitted = counted.length > 0 && counted.every((x) =>
      eligibleSet.has(rosterSlotKey(x.m?.role, x.m?.signoff?.context?.approver)));

    // 5. Threshold: enough distinct, valid, eligible approvers.
    const distinctEligible = new Set(
      counted
        .filter((x) => eligibleSet.has(rosterSlotKey(x.m?.role, x.m?.signoff?.context?.approver)))
        .map((x) => x.m?.signoff?.context?.approver),
    );
    checks.threshold_met = distinctEligible.size >= required;

    // 6. Order (ordered mode): member roles, in delivery order, match the policy
    //    sequence for the first `required` slots, and signature times strictly increase.
    if (mode === 'ordered') {
      const seqRolesOk = eligible.every((e, idx) => members[idx]?.role === e.role
        && members[idx]?.signoff?.context?.approver === e.approver);
      const times = issuedAts.slice(0, eligible.length);
      // Array.prototype.every only invokes this callback for `idx` once every
      // prior callback (0..idx-1) returned truthy — so for idx > 0, the
      // `t !== null` check at idx-1 already guaranteed times[idx - 1] is a
      // number. The compiler can't see across that sequential guarantee.
      const timesOk = times.every((t, idx) => t !== null
        && (idx === 0 || t > /** @type {number} */ (times[idx - 1])));
      checks.order_satisfied = members.length >= eligible.length && seqRolesOk && timesOk;
    } else {
      checks.order_satisfied = true; // not applicable in threshold mode
    }

    // 6b. Cryptographic ordering chain (STRONG ordered mode, policy.ordered_chain
    //     === true): each signoff after the first commits, INSIDE its own signed
    //     context, to the hash of its predecessor's context (prev_context_hash).
    //     Order is then proven by the signatures themselves, not by operator-
    //     asserted timestamps. The first signoff MUST carry no predecessor. When
    //     the policy does not request it, this is not applicable (true).
    if (mode === 'ordered' && policy.ordered_chain === true) {
      const seq = members.slice(0, eligible.length);
      let linked = seq.length === eligible.length;
      for (let idx = 0; idx < seq.length; idx++) {
        const prev = seq[idx]?.signoff?.context?.prev_context_hash;
        if (idx === 0) {
          if (prev !== undefined && prev !== null) linked = false;
        } else if (prev !== contextChainHash(seq[idx - 1]?.signoff?.context ?? {})) {
          linked = false;
        }
      }
      checks.chain_linked = linked;
    } else {
      checks.chain_linked = true; // not requested / not applicable
    }

    // 7. Window: all counted signatures fall within window_sec of each other.
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
