// SPDX-License-Identifier: Apache-2.0
/**
 * EP-RELIANCE-KERNEL-v1 — the reliance verdict.
 *
 * THE PRIMITIVE
 * -------------
 * Authority proves the approver was allowed. RELIANCE proves the whole evidence
 * packet is good enough for someone ELSE to act on — to release money, execute
 * an irreversible action, underwrite a control, accept an audit exhibit, or
 * settle a liability. That is the commercial control point: a bank relies before
 * wiring; an insurer relies before underwriting; an auditor relies before
 * accepting; a tool platform relies before allowing an irreversible action.
 *
 * THE UPGRADE
 * -----------
 * Authority is NOT an internal boolean here. It is one admissibility INPUT. The
 * relying party pins its OWN reliance profile (EP-RELIANCE-PROFILE-v1) — the
 * assurance it demands, the registry/issuer keys it trusts, the policy hashes it
 * accepts, the revocation freshness it needs, the evidence it requires — and the
 * kernel MECHANICALLY decides whether the evidence is admissible under THAT rule.
 * EMILIA never asks the relying party to trust its receipt; it lets the relying
 * party pin its own rule and returns a closed, portable verdict.
 *
 * PURE. OFFLINE. FAIL-CLOSED. No DB, no network, no operator trust. Every leg is
 * delegated to the frozen offline verifiers (verifyTrustReceipt, verifyQuorum,
 * verifyRevocation, verifyConsumptionProof, verifyAuthorityProof) — the kernel
 * composes their results into ONE verdict from a fixed, closed set.
 */
import crypto from 'node:crypto';
import { verifyTrustReceipt, verifyQuorum, canonicalize } from './index.js';
import { verifyRevocation } from './revocation.js';
import { verifyConsumptionProof } from './consumption-proof.js';
import { verifyAuthorityProof } from './authority-proof.js';

export const RELIANCE_KERNEL_VERSION = 'EP-RELIANCE-KERNEL-v1';
export const RELIANCE_PROFILE_VERSION = 'EP-RELIANCE-PROFILE-v1';

/** The CLOSED reliance verdict set. `rely` is the only success. */
export const RELIANCE_VERDICTS = Object.freeze([
  'rely',
  'do_not_rely_no_profile',
  'do_not_rely_unsigned',
  'do_not_rely_untrusted_issuer',
  'do_not_rely_no_class_a',
  'do_not_rely_quorum_unsatisfied',
  'do_not_rely_authority_missing',
  'do_not_rely_authority_subject_mismatch',
  'do_not_rely_authority_revoked',
  'do_not_rely_authority_expired',
  'do_not_rely_scope_mismatch',
  'do_not_rely_amount_exceeded',
  'do_not_rely_policy_mismatch',
  'do_not_rely_stale_revocation',
  'do_not_rely_already_consumed',
  'do_not_rely_registry_unavailable',
]);

const ASSURANCE_LEVELS = Object.freeze(['signed', 'class_a', 'quorum']);

function toMs(t) {
  if (t == null) return Date.now();
  if (typeof t === 'number') return t;
  const ms = Date.parse(t);
  return Number.isNaN(ms) ? Date.now() : ms;
}

function pubKeyB64u(pub) {
  // Accept a raw base64url SPKI string or a { public_key } object.
  if (typeof pub === 'string') return pub;
  if (pub && typeof pub.public_key === 'string') return pub.public_key;
  return null;
}

/**
 * Evaluate whether a relying party may rely on an evidence packet under its own
 * pinned profile. Returns a single closed verdict, fail-closed, deterministic.
 *
 * @param {object} input
 * @param {object} input.action               { action_type, amount?, currency?, policy_hash?, action_hash? }
 * @param {object} input.receipt              the EP trust receipt (verifyTrustReceipt input)
 * @param {object} [input.quorum]             EP-QUORUM-v1 doc (required when required_assurance==='quorum')
 * @param {object} [input.authority_proof]    EP-AUTHORITY-PROOF-v1
 * @param {object} [input.revocation_state]   { checked_at, statement?, target? } freshness attestation
 * @param {object} [input.consumption]        { consumed:boolean, proof?:<EP-SMT-CONSUME bundle> }
 * @param {object} input.relying_party_profile EP-RELIANCE-PROFILE-v1 (the pins)
 * @param {number|string|Date} [input.now]
 * @param {object} [opts]                     { approverKeys, logPublicKey, rpId, revokerKeys }
 * @returns {{ verdict:string, rely:boolean, reasons:string[], checks:object, profile:object }}
 */
export function evaluateReliance(input = {}, opts = {}) {
  // The `= {}` default only fires for undefined; a literal null (e.g. JSON.parse('null'))
  // would reach the destructure and throw. Normalize any non-object to {} so the
  // SDK entry point fails closed to a refusal, matching the gate wrappers.
  if (input === null || typeof input !== 'object') input = {};
  const {
    action = {}, receipt, quorum, authority_proof: authorityProof,
    revocation_state: revocationState, consumption, relying_party_profile: profile,
  } = input;
  const now = toMs(input.now);
  const reasons = [];
  const checks = {
    receipt: false, issuer: null, assurance: null, authority: null,
    policy: null, revocation: null, consumption: null,
  };

  const prof = profile && typeof profile === 'object' ? profile : {};

  // ── 0. PINNED PROFILE — no rule, no reliance ───────────────────────────────
  // Verification can pass without a profile; RELIANCE cannot. A relying party
  // must pin its OWN EP-RELIANCE-PROFILE-v1 before the kernel will ever say
  // `rely`. An absent or unrecognized profile is a fail-closed refusal, never a
  // default-permissive pass.
  if (prof['@type'] !== RELIANCE_PROFILE_VERSION) {
    reasons.push('no pinned EP-RELIANCE-PROFILE-v1 supplied; verification can pass but reliance cannot');
    return { verdict: 'do_not_rely_no_profile', rely: false, reasons, checks, profile: { id: RELIANCE_PROFILE_VERSION, pinned: false } };
  }

  const requiredEvidence = new Set(Array.isArray(prof.required_evidence) ? prof.required_evidence : []);
  const requiredAssurance = ASSURANCE_LEVELS.includes(prof.required_assurance) ? prof.required_assurance : 'signed';
  const acceptedIssuerKeys = Array.isArray(prof.accepted_issuer_keys) ? prof.accepted_issuer_keys.map(pubKeyB64u).filter(Boolean) : [];
  const acceptedRegistryKeys = Array.isArray(prof.accepted_registry_keys) ? prof.accepted_registry_keys : [];
  const acceptedPolicyHashes = Array.isArray(prof.accepted_policy_hashes) ? prof.accepted_policy_hashes : [];
  const maxRevStaleSec = Number.isFinite(prof.max_revocation_staleness_sec) ? prof.max_revocation_staleness_sec : null;

  const profileMeta = { id: RELIANCE_PROFILE_VERSION, required_assurance: requiredAssurance, required_authority: prof.required_authority === true };
  const deny = (verdict, reason) => {
    reasons.push(reason);
    return { verdict, rely: false, reasons, checks, profile: profileMeta };
  };

  // ── 1. RECEIPT — cryptographically valid and bound to THIS action ──────────
  if (!receipt || typeof receipt !== 'object') return deny('do_not_rely_unsigned', 'no receipt supplied');
  const rc = verifyTrustReceipt(receipt, opts);
  checks.receipt = rc.valid === true;
  if (!rc.valid) return deny('do_not_rely_unsigned', `receipt did not verify: ${(rc.errors || []).join('; ') || 'invalid'}`);
  if (action.action_hash && receipt.action_hash && action.action_hash !== receipt.action_hash) {
    return deny('do_not_rely_unsigned', 'receipt does not attest the action being relied on (action_hash mismatch)');
  }

  // Verified approvers — the human↔ceremony join. Because the receipt is valid,
  // every signoff verified; map each back to the approver of its context and the
  // pinned class of the key that signed. This is what lets authority be bound to
  // the human who ACTUALLY approved, not merely to some approver on the receipt.
  const approverKeys = opts.approverKeys || {};
  const contexts = Array.isArray(receipt.contexts) ? receipt.contexts : [];
  // Join signoffs to contexts on NORMALIZED hex, exactly as verifyTrustReceipt
  // does (hexOf: strip any "sha256:" prefix, lowercase). Keying on a fixed
  // "sha256:"-prefixed form would miss a bare-hex or upper-case context_hash that
  // the base verifier accepts, silently emptying verifiedApprovers and denying
  // reliance on a receipt that actually verified.
  const hexOf = (h) => String(h || '').replace(/^sha256:/i, '').toLowerCase();
  const ctxByHash = new Map();
  for (const c of contexts) {
    try { ctxByHash.set(crypto.createHash('sha256').update(canonicalize(c), 'utf8').digest('hex'), c); } catch { /* skip uncanonicalizable */ }
  }
  const verifiedApprovers = [];
  for (const s of (Array.isArray(receipt.signoffs) ? receipt.signoffs : [])) {
    const ctx = ctxByHash.get(hexOf(s?.context_hash));
    if (!ctx?.approver) continue;
    verifiedApprovers.push({ approver: ctx.approver, key_class: approverKeys[s?.approver_key_id]?.key_class || s?.key_class || 'B' });
  }
  const classASigners = verifiedApprovers.filter((a) => a.key_class === 'A').map((a) => a.approver);
  const allSigners = verifiedApprovers.map((a) => a.approver);

  // ── 2. ISSUER TRUST — the checkpoint key must be one the RP pinned ─────────
  // A receipt without a transparency checkpoint is trusted only through the
  // pinned approver keys (already enforced by verifyTrustReceipt); when a
  // checkpoint IS present and the RP pinned issuer keys, the log key used must
  // be among them, or the issuer is untrusted.
  const hasCheckpoint = Boolean(receipt?.log_proof?.checkpoint);
  if (acceptedIssuerKeys.length > 0 && hasCheckpoint) {
    const logKey = pubKeyB64u(opts.logPublicKey);
    const issuerOk = logKey !== null && acceptedIssuerKeys.includes(logKey);
    checks.issuer = issuerOk;
    if (!issuerOk) return deny('do_not_rely_untrusted_issuer', 'transparency checkpoint was not signed by a pinned issuer key');
  } else {
    checks.issuer = true;
  }

  // ── 3. ASSURANCE — the ceremony the RP demands ─────────────────────────────
  let quorumMembers = []; // verified quorum members, for authority subject binding
  if (requiredAssurance === 'class_a') {
    const hasClassA = classASigners.length > 0;
    checks.assurance = hasClassA ? 'class_a' : false;
    if (!hasClassA) return deny('do_not_rely_no_class_a', 'a valid Class-A device-bound signoff is required and none is present');
  } else if (requiredAssurance === 'quorum') {
    const q = quorum && verifyQuorum(quorum, opts);
    const quorumOk = Boolean(q?.valid) && quorum?.action_hash === receipt.action_hash;
    checks.assurance = quorumOk ? 'quorum' : false;
    if (!quorumOk) return deny('do_not_rely_quorum_unsatisfied', 'a satisfied EP-QUORUM-v1 bound to this action is required');
    quorumMembers = (Array.isArray(q.members) ? q.members : []).filter((m) => m?.valid && m?.approver).map((m) => m.approver);
  } else {
    checks.assurance = 'signed';
  }

  // ── 4. AUTHORITY — an admissibility INPUT, checked against the pinned registry
  if (prof.required_authority === true || requiredEvidence.has('authority_proof')) {
    if (!authorityProof || typeof authorityProof !== 'object') {
      return deny('do_not_rely_authority_missing', 'scoped authority is required but no EP-AUTHORITY-PROOF-v1 was supplied');
    }
    const ap = verifyAuthorityProof(authorityProof, { pinnedRegistryKeys: acceptedRegistryKeys });
    if (!ap.accepted) {
      const registryReasons = new Set(['registry_key_not_pinned', 'pin_mismatched_issuer', 'stale_registry', 'registry_head_mismatch']);
      checks.authority = { accepted: false, reason: ap.reason };
      if (registryReasons.has(ap.reason)) {
        return deny('do_not_rely_registry_unavailable', `authority registry could not be relied on: ${ap.reason}`);
      }
      return deny('do_not_rely_authority_missing', `authority proof did not verify: ${ap.reason}`);
    }
    // Accepted: now judge the SNAPSHOT against the action, offline.
    const p = authorityProof;
    if (!p.authority_id) return deny('do_not_rely_authority_missing', 'authority proof carries no authority_id');
    if (p.revocation?.status === 'revoked') return deny('do_not_rely_authority_revoked', 'authority was revoked as of the proof check');
    const from = p.validity?.from ? Date.parse(p.validity.from) : null;
    const to = p.validity?.to ? Date.parse(p.validity.to) : null;
    if ((to !== null && now > to) || (from !== null && now < from)) {
      return deny('do_not_rely_authority_expired', 'authority is outside its validity window at reliance time');
    }
    if (Array.isArray(p.scope) && action.action_type && !p.scope.includes(action.action_type)) {
      return deny('do_not_rely_scope_mismatch', 'the action is not within the authority scope');
    }
    if (typeof action.amount === 'number' && typeof p.limits?.max_amount_usd === 'number') {
      const ceilingCur = p.limits.currency || 'USD';
      const amtCur = action.currency || ceilingCur;
      if (amtCur !== ceilingCur || action.amount > p.limits.max_amount_usd) {
        return deny('do_not_rely_amount_exceeded', 'the amount exceeds the authority ceiling (or is in an unprovable currency)');
      }
    }
    // Authority pinned to a policy must match the action's policy.
    if (p.policy_hash && action.policy_hash && p.policy_hash !== action.policy_hash) {
      return deny('do_not_rely_policy_mismatch', 'authority is pinned to a different policy than the action');
    }
    // SUBJECT BINDING — the authority proof must belong to the human who ACTUALLY
    // approved this action, not merely ride alongside someone else's signoff.
    // Otherwise Alice's valid Class-A signoff + Bob-CFO's valid authority proof
    // would compose to `rely` though Bob never approved. Under class_a the subject
    // MUST be the Class-A signer; under quorum it MUST be a verified quorum
    // member; under signed it must be a verified approver on the receipt.
    const eligibleSubjects = requiredAssurance === 'quorum' ? quorumMembers
      : requiredAssurance === 'class_a' ? classASigners
        : allSigners;
    if (!p.subject || !eligibleSubjects.includes(p.subject)) {
      return deny('do_not_rely_authority_subject_mismatch', 'the authority proof subject is not the verified approver of this action');
    }
    checks.authority = { accepted: true, authority_id: p.authority_id, subject: p.subject, bound_to: requiredAssurance };
  } else {
    checks.authority = 'not_required';
  }

  // ── 5. POLICY — the action's policy must be one the RP accepts ─────────────
  if (acceptedPolicyHashes.length > 0) {
    const policyOk = Boolean(action.policy_hash) && acceptedPolicyHashes.includes(action.policy_hash);
    checks.policy = policyOk;
    if (!policyOk) return deny('do_not_rely_policy_mismatch', 'the action policy hash is not on the accepted list');
  } else {
    checks.policy = 'not_pinned';
  }

  // ── 6. REVOCATION FRESHNESS — a recent not-revoked check the RP demands ────
  if (requiredEvidence.has('revocation_freshness')) {
    if (!revocationState || typeof revocationState !== 'object') {
      return deny('do_not_rely_stale_revocation', 'a fresh revocation check is required but none was supplied');
    }
    // A validly-presented revocation statement that binds this target means the
    // authorization IS revoked — not merely stale.
    if (revocationState.statement && revocationState.target) {
      const rv = verifyRevocation(revocationState.target, revocationState.statement, { revokerKeys: opts.revokerKeys, now });
      if (rv.valid) return deny('do_not_rely_authority_revoked', 'a valid revocation statement binds this authorization');
    }
    const checkedAt = revocationState.checked_at ? Date.parse(revocationState.checked_at) : NaN;
    const fresh = !Number.isNaN(checkedAt)
      && (maxRevStaleSec === null || (now - checkedAt) <= maxRevStaleSec * 1000)
      && checkedAt <= now;
    checks.revocation = fresh ? 'fresh' : 'stale';
    if (!fresh) return deny('do_not_rely_stale_revocation', 'the revocation check is older than the pinned freshness bound');
  } else {
    checks.revocation = 'not_required';
  }

  // ── 7. ONE-TIME CONSUMPTION — the authorization must be UNCONSUMED ─────────
  if (requiredEvidence.has('consumption_proof')) {
    if (!consumption || typeof consumption !== 'object') {
      return deny('do_not_rely_already_consumed', 'proof of an unconsumed authorization is required but none was supplied');
    }
    // A valid EP-SMT-CONSUME bundle is EVIDENCE a consumption event occurred, so
    // it fails the "still unconsumed" gate; a malformed bundle cannot establish
    // state, so it also fails closed.
    let consumed = consumption.consumed === true;
    if (consumption.proof) {
      const cp = verifyConsumptionProof(consumption.proof);
      if (!cp.valid) return deny('do_not_rely_already_consumed', `consumption evidence did not verify: ${cp.reason || 'invalid'}`);
      consumed = true;
    }
    checks.consumption = consumed ? 'consumed' : 'unconsumed';
    if (consumed) return deny('do_not_rely_already_consumed', 'the authorization has already been consumed');
  } else {
    checks.consumption = 'not_required';
  }

  reasons.push('all pinned reliance requirements are satisfied');
  return { verdict: 'rely', rely: true, reasons, checks, profile: profileMeta };
}

/** Structural validation of an EP-RELIANCE-PROFILE-v1. Advisory (does not gate). */
export function validateRelianceProfile(profile) {
  const issues = [];
  if (!profile || typeof profile !== 'object') return { ok: false, issues: ['profile is not an object'] };
  if (profile['@type'] !== RELIANCE_PROFILE_VERSION) issues.push(`@type must be ${RELIANCE_PROFILE_VERSION}`);
  if (profile.required_assurance !== undefined && !ASSURANCE_LEVELS.includes(profile.required_assurance)) {
    issues.push(`required_assurance must be one of ${ASSURANCE_LEVELS.join(', ')}`);
  }
  if (profile.required_evidence !== undefined && !Array.isArray(profile.required_evidence)) {
    issues.push('required_evidence must be an array');
  }
  return { ok: issues.length === 0, issues };
}
