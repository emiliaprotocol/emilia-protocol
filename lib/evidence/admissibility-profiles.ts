// SPDX-License-Identifier: Apache-2.0
//
// EP-ADMISSIBILITY-PROFILE — a PINNABLE, per-requirement admissibility bar.
//
// WHO DEFINES THE BAR
// -------------------
// The RELYING PARTY. Not EMILIA. A profile is authored by whoever relies on the
// action, is content-addressed by its own `profile_hash`, and is pinned by that
// hash at evaluation time. EMILIA neither hosts an authoritative registry of
// profiles nor adjudicates any verdict. We publish (1) this interoperable schema
// and (2) clearly-labeled REFERENCE/EXAMPLE profiles a relying party may fork,
// on identical terms to everyone. If a relying party pins profile_hash X, only a
// profile that recomputes to X may set the bar; anything else fails closed.
//
// RELATION TO admissibility.js
// ----------------------------
// admissibility.js owns the CLOSED verdict set and its precedence
// (unverifiable > conflicted > stale > missing_evidence > admissible) over a
// boolean type-expression EvidencePolicy. This module is a richer, per-entry
// surface (min_assurance, revocation/other checks, optional entries, params) for
// authoring that bar. It DOES NOT reimplement the precedence: it resolves each
// requirement into an admissibility fact + a derived boolean requirement string,
// then delegates the classified verdict to evaluateAdmissibility(). The profile
// layer only decides which facts to hand down; the worst-outcome precedence is
// entirely admissibility.js's.
//
// HONESTY. An `admissible` verdict means "this evidence bundle clears the bar
// THIS relying party pinned, at the evaluation time supplied" — NOT that the
// action is correct, safe, or currently valid beyond the freshness bounds
// evaluated. Offline verification never establishes current validity.
//
// FAIL CLOSED. Missing / invalid / unrecognized evidence, or a profile_hash
// mismatch, yields a non-admissible verdict or a refusal. A default is the
// weakest outcome, never admissible.

import crypto from 'node:crypto';
import { canonicalize } from '../canonical-json.js';
import { evaluateAdmissibility, ADMISSIBILITY_VERDICTS } from './admissibility.js';

export const ADMISSIBILITY_PROFILE_VERSION = 'ep:admissibility-profile:v1';

const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

/** JCS(obj) -> sha256, prefixed, exactly as the rest of EP hashes. */
function hashObject(obj) {
  return `sha256:${sha256hex(canonicalize(obj))}`;
}

/**
 * @typedef {Object} ProfileRequirement
 * @property {string}  evidence            component type token, e.g. 'authorization_receipt'
 * @property {string}  [min_assurance]     minimum assurance class the item must meet (ordered, see ASSURANCE_ORDER)
 * @property {number}  [max_staleness_sec] max age (seconds) relative to `now`; absent => no freshness bound
 * @property {string[]}[checks]            per-item checks that MUST pass, e.g. ['revocation_checked','signature_valid']
 * @property {boolean} [optional]          absent => no downgrade; present-but-invalid => contributes a conflict
 * @property {Object}  [params]            opaque, relying-party-defined; hashed into the profile, not interpreted here
 */

/**
 * @typedef {Object} AdmissibilityProfile
 * @property {string} id                   'ep:admissibility:<name>:v<N>'
 * @property {number} version
 * @property {string} authored_by          the RELYING PARTY (free string). EMILIA is never this.
 * @property {ProfileRequirement[]} requires
 * @property {string[]} verdicts           the closed set (must equal ADMISSIBILITY_VERDICTS)
 * @property {string} profile_hash         'sha256:<hex>' over JCS(profile) with profile_hash removed
 */

// Assurance ordering. A requirement's min_assurance is met iff the item's
// assurance class is at or above it in this order. Unknown classes are the
// weakest possible (fail closed): they satisfy no non-empty min_assurance.
export const ASSURANCE_ORDER = Object.freeze([
  'self_asserted', 'basic', 'verified', 'high', 'very_high',
]);
function assuranceRank(cls) {
  const i = ASSURANCE_ORDER.indexOf(cls);
  return i === -1 ? -1 : i;
}
function meetsAssurance(itemAssurance, minAssurance) {
  if (!minAssurance) return true; // no floor set
  const need = assuranceRank(minAssurance);
  if (need === -1) return false; // profile names an unknown floor -> unsatisfiable (fail closed)
  return assuranceRank(itemAssurance) >= need;
}

/**
 * Compute a profile's content hash over its JCS-canonical form with the
 * `profile_hash` field removed. Deterministic and reproducible by anyone.
 * @param {Omit<AdmissibilityProfile,'profile_hash'> & {profile_hash?: string}} profile
 * @returns {string} 'sha256:<hex>'
 */
export function computeProfileHash(profile) {
  if (!profile || typeof profile !== 'object') throw new Error('profile must be an object');
  const { profile_hash: _omit, ...rest } = profile;
  return hashObject(rest);
}

/**
 * Author a profile object and stamp its self-verifying profile_hash. The bar is
 * authored by the relying party; `authored_by` is required and must not be EMILIA
 * (this is a schema, we do not gate the string, but the axiom is: EMILIA is not
 * the author). The returned object is frozen so the pinned hash cannot drift.
 * @param {Omit<AdmissibilityProfile,'verdicts'|'profile_hash'> & {verdicts?:string[]}} spec
 */
export function defineAdmissibilityProfile(spec) {
  if (!spec || typeof spec !== 'object') throw new Error('profile spec must be an object');
  if (typeof spec.id !== 'string' || !spec.id.trim()) throw new Error('profile id is required');
  if (typeof spec.authored_by !== 'string' || !spec.authored_by.trim()) {
    throw new Error('authored_by (the relying party) is required — EMILIA does not author the bar');
  }
  if (!Array.isArray(spec.requires) || spec.requires.length === 0) {
    throw new Error('profile must declare at least one requirement');
  }
  for (const r of spec.requires) {
    if (!r || typeof r.evidence !== 'string' || !r.evidence.trim()) {
      throw new Error('each requirement needs a non-empty `evidence` type');
    }
  }
  const base = {
    id: spec.id,
    version: Number.isFinite(spec.version) ? spec.version : 1,
    authored_by: spec.authored_by,
    requires: spec.requires.map((r) => ({
      evidence: r.evidence,
      ...(r.min_assurance ? { min_assurance: r.min_assurance } : {}),
      ...(Number.isFinite(r.max_staleness_sec) ? { max_staleness_sec: r.max_staleness_sec } : {}),
      ...(Array.isArray(r.checks) && r.checks.length ? { checks: [...r.checks] } : {}),
      ...(r.optional === true ? { optional: true } : {}),
      ...(r.params && typeof r.params === 'object' ? { params: r.params } : {}),
    })),
    verdicts: [...ADMISSIBILITY_VERDICTS],
  };
  const profile = { ...base, profile_hash: computeProfileHash(base) };
  return Object.freeze(profile);
}

/** True iff the profile's stamped profile_hash matches its recomputed content hash. */
export function verifyProfileHash(profile) {
  try {
    return typeof profile?.profile_hash === 'string' && profile.profile_hash === computeProfileHash(profile);
  } catch {
    return false;
  }
}

// Stable identifier for a bundle item that was actually consulted. Prefer an
// explicit content digest; else the item's id; else a JCS digest of the
// decision-relevant fields. This is what goes into the replay digest, so it must
// be presenter-independent and deterministic.
function itemIdentifier(item) {
  if (typeof item?.digest === 'string' && item.digest) return item.digest;
  if (typeof item?.id === 'string' && item.id) return item.id;
  return hashObject({
    evidence: item?.evidence ?? item?.type ?? null,
    issued_at: item?.issued_at ?? null,
    assurance: item?.assurance ?? null,
    outcome: item?.outcome ?? null,
    revoked: item?.revoked ?? null,
    signature_valid: item?.signature_valid ?? null,
  });
}

// Find the bundle item that answers a requirement. A bundle item declares its
// component type under `evidence` (preferred) or `type`.
function findItem(bundle, evidenceType) {
  const items = Array.isArray(bundle?.items) ? bundle.items
    : Array.isArray(bundle?.components) ? bundle.components
      : Array.isArray(bundle) ? bundle : [];
  return items.find((it) => (it?.evidence ?? it?.type) === evidenceType) ?? null;
}

// Resolve ONE requirement against the bundle into an admissibility fact plus a
// human reason. `satisfied` here means "present and clears every per-item gate";
// the OVERALL verdict is still computed by admissibility.js precedence, this
// only classifies the single item's contribution.
function resolveRequirement(req, item, nowMs) {
  const type = req.evidence;
  const result = { evidence: type, satisfied: false, reason: '', consulted: item ? itemIdentifier(item) : null };

  // ABSENT.
  if (!item) {
    if (req.optional) {
      result.satisfied = true;
      result.reason = 'optional requirement absent (no downgrade)';
      return { result, fact: null, optionalAbsent: true };
    }
    result.reason = 'required evidence absent';
    // Absent mandatory -> a fact the requirement expression will not find.
    return { result, fact: null, optionalAbsent: false };
  }

  // Per-item gates. Each failure maps to a fact field admissibility.js reads.
  const signatureValid = item.signature_valid !== false && item.verified !== false;
  const ageSec = (item.issued_at != null && Number.isFinite(nowMs))
    ? Math.floor((nowMs - Date.parse(item.issued_at)) / 1000) : null;
  const stale = Number.isFinite(req.max_staleness_sec) && ageSec !== null && ageSec > req.max_staleness_sec;
  const assuranceOk = meetsAssurance(item.assurance, req.min_assurance);
  const checks = Array.isArray(req.checks) ? req.checks : [];
  const revocationRequired = checks.includes('revocation_checked');
  // revocation_checked FAILS when the item is revoked OR its revocation state was
  // never established (unknown revocation cannot be treated as "not revoked").
  const revocationFailed = revocationRequired && (item.revoked === true || item.revoked == null);
  const otherChecksFailed = checks.filter((c) => c !== 'revocation_checked')
    .some((c) => item.checks?.[c] !== true);

  // Fact handed to admissibility.js. `verified:false` => unverifiable class;
  // outcome 'deny' => conflicted class; stale => stale class; assurance/other-check
  // failures are unverifiability of THIS item's sufficiency (fail closed).
  const fact = {
    type,
    label: item.label ?? type,
    verified: signatureValid && assuranceOk && !revocationFailed && !otherChecksFailed,
    action_digest: item.action_digest ?? null,
    outcome: item.outcome ?? null,
    revoked: revocationRequired ? item.revoked === true : false,
    issued_at: item.issued_at,
  };

  const problems = [];
  if (!signatureValid) problems.push('signature invalid');
  if (!assuranceOk) problems.push(`assurance below ${req.min_assurance}`);
  if (revocationFailed) problems.push(item.revoked === true ? 'revoked' : 'revocation state unknown');
  if (otherChecksFailed) problems.push('required check failed');
  if (stale) problems.push(`staler than ${req.max_staleness_sec}s`);
  if (fact.outcome === 'deny' || fact.outcome === 'denied' || fact.outcome === 'refused') problems.push('item is a denial');

  result.satisfied = problems.length === 0;
  result.reason = problems.length === 0 ? 'present and clears the bar' : problems.join('; ');

  return { result, fact, freshness: { type, max: req.max_staleness_sec }, revocation: revocationRequired };
}

/**
 * Evaluate an evidence bundle against a PINNED admissibility profile.
 *
 * @param {AdmissibilityProfile} profile   the relying-party-authored, hash-pinned bar
 * @param {{items?:object[], components?:object[]}} evidenceBundle   presented evidence
 * @param {{ now?:string|number, expectedProfileHash?:string }} [ctx]
 *        now                 evaluation time (ISO string or epoch ms). Not in the digest input as wall-clock; it enters only via each item's derived staleness which is a property of (now, issued_at, profile).
 *        expectedProfileHash if supplied, the profile MUST recompute to it or the call REFUSES ('unverifiable', 'profile_hash_mismatch').
 * @returns {{ verdict:string, profile_hash:string|null, replay_digest:string,
 *             requirement_results:{evidence:string|null,satisfied:boolean,reason:string}[],
 *             evaluated_at:string, refused?:boolean, reason?:string }}
 */
export function evaluateAdmissibilityProfile(profile, evidenceBundle, ctx = {}) {
  const nowMs = typeof ctx.now === 'number' ? ctx.now : Date.parse(/** @type {string} */ (ctx.now));
  const evaluated_at = new Date(Number.isFinite(nowMs) ? nowMs : Date.now()).toISOString();

  // Recompute the bar's hash. This is the ONLY thing allowed to define the bar.
  let recomputed;
  try {
    recomputed = computeProfileHash(profile);
  } catch {
    // A profile we cannot even canonicalize is not a bar. Fail closed.
    return refuse(null, 'profile_uncanonicalizable', evaluated_at);
  }

  // PIN CHECK — nobody may swap the bar. A mismatch is unverifiable, full stop.
  if (typeof ctx.expectedProfileHash === 'string' && ctx.expectedProfileHash !== recomputed) {
    return refuse(recomputed, 'profile_hash_mismatch', evaluated_at);
  }
  // A profile that carries a self-hash which does not match its own content is
  // tampered; refuse rather than evaluate against a lie.
  if (typeof profile?.profile_hash === 'string' && profile.profile_hash !== recomputed) {
    return refuse(recomputed, 'profile_self_hash_mismatch', evaluated_at);
  }

  if (!Array.isArray(profile?.requires) || profile.requires.length === 0) {
    return refuse(recomputed, 'profile_has_no_requirements', evaluated_at);
  }

  // Resolve every requirement into a fact + a per-requirement result.
  const requirement_results = [];
  const facts = [];
  /** @type {Object<string,number>} */
  const freshnessSec = {};
  const revocationRequired = [];
  const mandatoryTokens = [];

  for (const req of profile.requires) {
    const item = findItem(evidenceBundle, req.evidence);
    const { result, fact, optionalAbsent } = resolveRequirement(req, item, nowMs);
    requirement_results.push({ evidence: result.evidence, satisfied: result.satisfied, reason: result.reason, consulted: result.consulted });

    if (!req.optional) mandatoryTokens.push(req.evidence);

    if (optionalAbsent) continue; // absent-optional: nothing enters the fact set.

    if (fact) {
      facts.push(fact);
      if (Number.isFinite(req.max_staleness_sec)) freshnessSec[req.evidence] = /** @type {number} */ (req.max_staleness_sec);
      if (Array.isArray(req.checks) && req.checks.includes('revocation_checked')) revocationRequired.push(req.evidence);
    }
    // mandatory-absent: no fact added; the requirement expression will miss it -> missing_evidence.
  }

  // Derive the boolean requirement expression admissibility.js consumes: the AND
  // of all MANDATORY evidence types. Optional types never enter the expression
  // (their absence must not downgrade), but an optional item that is PRESENT and
  // INVALID still enters `facts` and is caught by the unverifiable/conflicted
  // precedence in admissibility.js.
  const requirement = mandatoryTokens.length ? mandatoryTokens.join(' AND ') : '';

  // A profile with only-optional requirements and none present: there is no
  // mandatory bar to clear. That is vacuously admissible ONLY if no present item
  // is invalid; admissibility.js handles the invalid-present case via `facts`.
  const derivedPolicy = {
    policy_id: profile.id,
    reliance_purpose: `profile:${profile.id}`,
    requirement: requirement || 'true',
    freshness_sec: freshnessSec,
    revocation_required: revocationRequired,
    require_action_agreement: false, // profile requirements are per-type, not a single bound action
  };

  // If the derived requirement is the vacuous 'true' token, admissibility.js's
  // expression evaluator has no such literal; short-circuit to an all-facts check.
  let inner;
  if (requirement) {
    inner = evaluateAdmissibility({ components: facts }, derivedPolicy, { as_of: evaluated_at });
  } else {
    // No mandatory requirements. Build the verdict purely from present facts:
    // any invalid present item -> unverifiable/conflicted via a throwaway policy
    // that requires nothing, so only the precedence over `facts` speaks.
    inner = evaluateAdmissibility(
      { components: facts },
      { ...derivedPolicy, requirement: facts.map((f) => f.type).join(' AND ') || 'authorization_receipt' },
      { as_of: evaluated_at },
    );
    // With zero facts and zero mandatory requirements, the bundle vacuously
    // clears an empty bar: admissible. (Only reachable when every requirement is
    // optional-and-absent.)
    if (facts.length === 0) inner = { ...inner, verdict: 'admissible' };
  }

  const verdict = inner.verdict;

  // REPLAY DIGEST — deterministic, presenter-independent, bit-identical across
  // parties. Inputs (sorted for stability):
  //   profile_hash       — WHICH bar
  //   evidence           — sorted stable identifiers of the bundle items actually consulted
  //   verdict            — the classified outcome
  //   requirement_results — per-requirement {evidence,satisfied,reason} (consulted id stripped; it is already in `evidence`)
  // NO wall-clock: evaluated_at is OUTSIDE the digest. The only time influence is
  // staleness, which is a deterministic function of (now, issued_at, profile) and
  // is already reflected in `verdict` + `requirement_results`.
  const consultedEvidence = requirement_results
    .map((r) => r.consulted)
    .filter((x) => typeof x === 'string' && x)
    .sort();
  const digestInput = {
    profile_hash: recomputed,
    evidence: consultedEvidence,
    verdict,
    requirement_results: requirement_results.map((r) => ({
      evidence: r.evidence, satisfied: r.satisfied, reason: r.reason,
    })),
  };
  const replay_digest = hashObject(digestInput);

  return {
    verdict,
    profile_hash: recomputed,
    replay_digest,
    requirement_results: requirement_results.map((r) => ({
      evidence: r.evidence, satisfied: r.satisfied, reason: r.reason,
    })),
    evaluated_at,
  };
}

// Fail-closed refusal. A refusal is unverifiable by construction: we could not
// establish the bar, so we cannot say the bundle clears it. The replay_digest
// still binds WHAT we refused and WHY so the refusal is itself reproducible.
function refuse(profile_hash, reason, evaluated_at) {
  const requirement_results = [{ evidence: null, satisfied: false, reason }];
  const digestInput = {
    profile_hash: profile_hash ?? null,
    evidence: [],
    verdict: 'unverifiable',
    requirement_results,
  };
  return {
    verdict: 'unverifiable',
    profile_hash: profile_hash ?? null,
    replay_digest: hashObject(digestInput),
    requirement_results,
    evaluated_at,
    refused: true,
    reason,
  };
}
