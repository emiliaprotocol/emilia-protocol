// SPDX-License-Identifier: Apache-2.0
//
// EP-ADMISSIBILITY — decision-grade evidence: is this bundle ENOUGH to rely on,
// for THIS reliance purpose?
//
// Receipts prove facts. This layer decides which facts are sufficient to trust,
// settle, reverse, insure, or prosecute an action. It is the classified verdict
// over a heterogeneous evidence bundle (identity, delegation, policy permit,
// named-human/quorum authorization, execution attestation, transparency
// inclusion, recourse reference, ...), evaluated against a RELYING-PARTY-SUPPLIED
// evidence policy.
//
// Three things this adds over EP-AEC (verifyAuthorizationChain), which returns a
// binary allow over a bundle-supplied requirement:
//   1. a CLASSIFIED verdict — admissible | missing_evidence | stale | conflicted
//      | unverifiable — so a relying party knows WHY and what to do next;
//   2. the sufficiency policy is supplied by the RELYING PARTY, never read from
//      the bundle (a presenter must not choose its own sufficiency bar — same
//      trust-boundary discipline as quorum-policy pinning and federation);
//   3. a deterministic replay_digest so the verdict is reproducible from
//      (policy, component facts) — policy replay for agent actions.
//
// This module is the PURE policy layer. It consumes per-component VERIFICATION
// RESULTS (produced by the real type verifiers — packages/verify, the recourse
// verifier, etc.) and returns the sufficiency verdict. Crypto is delegated; the
// novel primitive is the classified, purpose-parameterized, replayable decision.

import crypto from 'node:crypto';

export const ADMISSIBILITY_VERDICTS = Object.freeze([
  'admissible', 'missing_evidence', 'stale', 'conflicted', 'unverifiable',
]);

// Deterministic JCS-style canonicalization (I-JSON subset; no floats).
function canon(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`;
}
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

/**
 * @typedef {Object} Component
 * @property {string} type            e.g. 'authorization_receipt' | 'delegation' | 'policy_permit' | 'execution_attestation' | 'transparency' | 'recourse_reference'
 * @property {boolean} verified       did the component's OWN type verifier accept it (signature + action binding)?
 * @property {string}  action_digest  the action this component binds (must agree across the bundle)
 * @property {string} [issued_at]     ISO timestamp, for freshness
 * @property {string} [outcome]       'allow' | 'deny' | ... — for conflict detection (e.g. a human-auth denial)
 * @property {boolean}[revoked]       live revocation state, when the policy requires a revocation check
 * @property {string} [label]
 */

/**
 * @typedef {Object} EvidencePolicy   RELYING-PARTY-supplied. Never read from the bundle.
 * @property {string}  policy_id
 * @property {string}  reliance_purpose        e.g. 'money_movement' | 'audit' | 'insurance_claim' | 'reversal'
 * @property {string}  requirement             boolean expression over required component TYPES, e.g. "authorization_receipt AND policy_permit"
 * @property {Object<string,number>} [freshness_sec]  max age per component type (seconds); absent => no freshness bound
 * @property {string[]} [revocation_required]  component types whose `revoked` MUST be false
 * @property {boolean} [require_action_agreement=true]  all present components must bind the same action
 */

/**
 * Evaluate whether a bundle is admissible for a reliance purpose.
 * @param {{ action_digest?:string, components: Component[] }} bundle
 * @param {EvidencePolicy} policy   supplied by the RELYING PARTY
 * @param {{ as_of?: string }} [opts]  evaluation time (ISO); defaults to the bundle's own — pass explicitly for replay
 * @returns {{ verdict:string, policy_id:string, reliance_purpose:string, action_digest:string|null,
 *            requirement:string, satisfied_by:string[], per_component:object[], reasons:string[], replay_digest:string }}
 */
export function evaluateAdmissibility(bundle, policy, opts = {}) {
  const reasons = [];
  const components = Array.isArray(bundle?.components) ? bundle.components : [];
  const asOf = opts.as_of ? Date.parse(opts.as_of) : NaN;
  const requireAgreement = policy?.require_action_agreement !== false;
  const freshness = policy?.freshness_sec || {};
  const revReq = new Set(policy?.revocation_required || []);

  // Normalize component facts (the replay-stable view — only decision-relevant fields).
  const facts = components.map((c) => {
    const ageSec = (c.issued_at && !Number.isNaN(asOf))
      ? Math.floor((asOf - Date.parse(c.issued_at)) / 1000) : null;
    const maxAge = freshness[c.type];
    const stale = Number.isFinite(maxAge) && ageSec !== null && ageSec > maxAge;
    return {
      type: c.type,
      label: c.label ?? null,
      verified: c.verified === true,
      action_digest: c.action_digest ?? null,
      outcome: c.outcome ?? null,
      revoked: c.revoked === true,
      age_sec: ageSec,
      stale,
      rev_checked_required: revReq.has(c.type),
    };
  });

  // Replay digest: deterministic over (policy, normalized facts, as_of). Same
  // inputs -> same verdict + same digest. This is the policy-replay property.
  const replay_digest = `sha256:${sha256hex(canon({ policy, facts, as_of: opts.as_of ?? null }))}`;

  const out = (verdict) => ({
    verdict,
    policy_id: policy?.policy_id ?? null,
    reliance_purpose: policy?.reliance_purpose ?? null,
    action_digest: bundle?.action_digest ?? (facts.find((f) => f.action_digest)?.action_digest ?? null),
    requirement: policy?.requirement ?? null,
    satisfied_by: facts.filter((f) => f.verified && !f.stale && !(f.rev_checked_required && f.revoked)).map((f) => f.type),
    per_component: facts,
    reasons,
    replay_digest,
  });

  if (!policy || typeof policy.requirement !== 'string' || !policy.requirement.trim()) {
    reasons.push('no relying-party evidence policy supplied (sufficiency is never read from the bundle)');
    return out('unverifiable');
  }

  // ── Precedence: unverifiable > conflicted > (missing | stale) > admissible ──

  // 1. UNVERIFIABLE — any present component that fails its own verification.
  const broken = facts.filter((f) => !f.verified);
  if (broken.length) {
    reasons.push(`component(s) failed verification: ${broken.map((f) => f.type).join(', ')}`);
    return out('unverifiable');
  }

  // 2. CONFLICTED — verified components that contradict.
  if (requireAgreement) {
    const digests = new Set(facts.filter((f) => f.action_digest).map((f) => f.action_digest));
    if (digests.size > 1) {
      reasons.push(`components bind different actions: {${[...digests].join(', ')}}`);
      return out('conflicted');
    }
  }
  const denial = facts.find((f) => f.outcome === 'deny' || f.outcome === 'denied' || f.outcome === 'refused');
  if (denial) {
    reasons.push(`a verified component is a refusal (${denial.type}) — the bundle contains a denial, not an authorization`);
    return out('conflicted');
  }

  // 3. Requirement satisfaction. Evaluate the boolean type-expression twice:
  //    over ALL verified types (ignoring freshness/revocation) and over FRESH+
  //    non-revoked types. If the former satisfies but the latter does not, the
  //    evidence exists but is stale/revoked -> 'stale'; if neither -> missing.
  const verifiedTypes = new Set(facts.filter((f) => f.verified).map((f) => f.type));
  const liveTypes = new Set(
    facts.filter((f) => f.verified && !f.stale && !(f.rev_checked_required && f.revoked)).map((f) => f.type),
  );
  const satisfiedIgnoringFreshness = evalRequirement(policy.requirement, verifiedTypes, reasons, false);
  const satisfiedLive = evalRequirement(policy.requirement, liveTypes, reasons, true);

  if (satisfiedLive) return out('admissible');
  if (satisfiedIgnoringFreshness) {
    const staleOnes = facts.filter((f) => f.verified && (f.stale || (f.rev_checked_required && f.revoked)));
    reasons.push(`requirement met but by stale/revoked evidence: ${staleOnes.map((f) => f.type).join(', ')}`);
    return out('stale');
  }
  reasons.push(`requirement not satisfied by present evidence: "${policy.requirement}" over {${[...verifiedTypes].join(', ') || '∅'}}`);
  return out('missing_evidence');
}

// Tiny boolean expression evaluator over a SET of present component types.
// Grammar: TYPE | ( expr ) | expr AND expr | expr OR expr. Fail-closed on parse error.
export function evalRequirement(expr, presentTypes, reasons = [], record = false) {
  const tokens = String(expr).match(/\(|\)|AND|OR|[a-zA-Z0-9_]+/g) || [];
  let i = 0;
  const peek = () => tokens[i];
  const next = () => tokens[i++];
  function parseOr() { let l = parseAnd(); while (peek() === 'OR') { next(); const r = parseAnd(); l = l || r; } return l; }
  function parseAnd() { let l = parseAtom(); while (peek() === 'AND') { next(); const r = parseAtom(); l = l && r; } return l; }
  function parseAtom() {
    const t = next();
    if (t === '(') { const v = parseOr(); if (next() !== ')') throw new Error('unbalanced'); return v; }
    if (t === 'AND' || t === 'OR' || t === ')' || t === undefined) throw new Error(`unexpected "${t}"`);
    return presentTypes.has(t);
  }
  try {
    const v = parseOr();
    if (i !== tokens.length) throw new Error('trailing tokens');
    return !!v;
  } catch (e) {
    if (record) reasons.push(`malformed requirement expression: ${e.message}`);
    return false; // fail closed
  }
}
