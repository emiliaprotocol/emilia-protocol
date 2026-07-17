// SPDX-License-Identifier: Apache-2.0
/**
 * EP-ASSURANCE-PACKAGE-v1 — the reliance assurance layer.
 *
 * The layer above the reliance kernel. The kernel answers "may this party rely on
 * this action?" The assurance package answers the question an INDEPENDENT assurer
 * (an audit firm, a regulator, an insurer) asks: "can I reproduce, test, and
 * attest that an organization's automated actions were governed by admissible
 * evidence under the organization's OWN pinned rule?"
 *
 * Two halves, mirroring the re-performance discipline of reperform.js:
 *   buildAssurancePackage(decisions, ...)      the organization bundles its
 *      automated decisions + the evidence each relied on into ONE portable,
 *      content-addressed package (action, receipt, profile, authority proof,
 *      revocation check, consumption, denial/exception history, policy hash).
 *   reperformAssurancePackage(pkg, ...)         the assurer RE-PERFORMS every
 *      reliance verdict offline from that evidence, TRUSTING NOTHING the package
 *      asserts: it recomputes each verdict with evaluateReliance, compares to the
 *      verdict the org's runtime CLAIMED (drift = a control failure the assurer
 *      caught), maps every verdict to a control objective, and emits an
 *      auditor-style workpaper. It does not conclude; the assurer concludes.
 *
 * PCAOB AS 1105 alignment (why this is audit evidence): the source is
 * cryptographic, the decision trail is immutable and content-addressed, the rule
 * is a pinned profile, and the verdict is re-performable directly. This module
 * SUPPORTS a re-performance procedure; it never issues an opinion.
 */
import { hashCanonical } from '../execution-binding.js';
import { evaluateReliance, RELIANCE_VERDICTS } from '@emilia-protocol/verify/reliance';

export const ASSURANCE_PACKAGE_VERSION = 'EP-ASSURANCE-PACKAGE-v1';
export const ASSURANCE_REPERFORMANCE_VERSION = 'EP-ASSURANCE-REPERFORMANCE-v1';

export { RELIANCE_VERDICTS };

/**
 * The reliance control catalog: every reliance verdict maps to the control
 * objective it exercises. A `rely` shows the control PASSING; every do_not_rely_*
 * shows the control OPERATING (it refused a non-admissible action). Denials are
 * the control working, not the control failing.
 */
export const RELIANCE_CONTROL_CATALOG = Object.freeze({
  'RC-1': { objective: 'Only a human with valid organization-bound, scoped authority for THIS exact action may authorize it', verdicts: ['do_not_rely_authority_missing', 'do_not_rely_authority_subject_mismatch', 'do_not_rely_authority_organization_mismatch', 'do_not_rely_authority_revoked', 'do_not_rely_authority_expired', 'do_not_rely_scope_mismatch', 'do_not_rely_amount_exceeded', 'do_not_rely_registry_unavailable'] },
  'RC-2': { objective: 'Authorization uses a device-bound named-human ceremony (Class-A or quorum)', verdicts: ['do_not_rely_no_class_a', 'do_not_rely_quorum_unsatisfied'] },
  'RC-3': { objective: 'The action conforms to a pinned, accepted policy', verdicts: ['do_not_rely_policy_mismatch'] },
  'RC-4': { objective: 'Authorization is consumed exactly once (no replay)', verdicts: ['do_not_rely_already_consumed'] },
  'RC-5': { objective: 'Reliance is evaluated against fresh revocation state', verdicts: ['do_not_rely_stale_revocation'] },
  'RC-6': { objective: 'Evidence is signed by a trusted issuer and evaluated under a pinned rule', verdicts: ['do_not_rely_unsigned', 'do_not_rely_untrusted_issuer', 'do_not_rely_no_profile'] },
});

const VERDICT_TO_CONTROL = Object.freeze(
  Object.entries(RELIANCE_CONTROL_CATALOG).reduce((m, [cid, c]) => {
    for (const v of c.verdicts) m[v] = cid;
    return m;
  }, {}),
);

/** Which control objective a verdict exercises (rely passes ALL, so returns null). */
function controlForVerdict(verdict) {
  if (verdict === 'rely') return null;
  return VERDICT_TO_CONTROL[verdict] || null;
}

function toIso(now) {
  const ms = typeof now === 'function' ? now() : now;
  return new Date(ms == null ? 0 : ms).toISOString();
}

function portableJsonCopy(value, active = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new TypeError('assurance-package: value is not canonical JSON');
    }
    return value;
  }
  if (typeof value !== 'object') {
    throw new TypeError('assurance-package: value is not JSON');
  }
  if (active.has(value)) throw new TypeError('assurance-package: cyclic value');
  active.add(value);
  try {
    if (Array.isArray(value)) return value.map((entry) => portableJsonCopy(entry, active));
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('assurance-package: value must use plain JSON objects');
    }
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, portableJsonCopy(entry, active)]),
    );
  } finally {
    active.delete(value);
  }
}

/**
 * Bundle N automated reliance decisions + the evidence each relied on into one
 * portable, content-addressed assurance package. Does NOT re-perform (that is the
 * assurer's independent step); it packages faithfully, including the verdict the
 * org's runtime CLAIMED, so drift is checkable later.
 *
 * @param {Array<object>} decisions  each: { decision_id, action, receipt, quorum?,
 *   authority_proof?, revocation_state?, consumption?, stated_verdict? }
 * @param {object} opts
 * @param {object} opts.profile       the pinned EP-RELIANCE-PROFILE-v1 the org operated under
 * @param {object} [opts.organization] { id, name } (no PHI)
 * @param {number|function} [opts.now]
 * @returns {object} EP-ASSURANCE-PACKAGE-v1
 */
export function buildAssurancePackage(decisions = [], { profile, organization = null, now = 0 } = {}) {
  if (!Array.isArray(decisions)) throw new Error('assurance-package: decisions must be an array');
  const items = decisions.map((d, i) => {
    const source = portableJsonCopy(d ?? {});
    const decision_id = source.decision_id ?? `decision-${i}`;
    return {
      decision_id,
      action: source.action ?? null,
      policy_hash: source.action?.policy_hash ?? null,
      stated_verdict: typeof source.stated_verdict === 'string' ? source.stated_verdict : null,
      evidence: {
        receipt: source.receipt ?? null,
        quorum: source.quorum ?? null,
        authority_proof: source.authority_proof ?? null,
        revocation_state: source.revocation_state ?? null,
        consumption: source.consumption ?? null,
      },
    };
  });
  // Denial/exception history = the decisions the org itself recorded as refused.
  const exceptions = items.filter((it) => it.stated_verdict && it.stated_verdict !== 'rely')
    .map((it) => ({ decision_id: it.decision_id, stated_verdict: it.stated_verdict, control_id: controlForVerdict(it.stated_verdict) }));

  const profileCopy = profile == null ? null : portableJsonCopy(profile);
  const body = {
    '@version': ASSURANCE_PACKAGE_VERSION,
    organization: organization == null ? null : portableJsonCopy(organization),
    reliance_profile: profileCopy,
    profile_hash: profileCopy ? hashCanonical(profileCopy) : null,
    control_catalog: RELIANCE_CONTROL_CATALOG,
    decisions: items,
    exception_history: exceptions,
    counts: {
      decisions: items.length,
      stated_admissible: items.filter((it) => it.stated_verdict === 'rely').length,
      stated_refused: items.filter((it) => it.stated_verdict && it.stated_verdict !== 'rely').length,
      stated_unknown: items.filter((it) => !it.stated_verdict).length,
    },
    assembled_at: toIso(now),
  };
  // Content address over everything EXCEPT the timestamp (so the same evidence
  // yields the same digest regardless of when it was packaged).
  const { assembled_at: _t, ...digestScope } = body;
  return { ...body, package_digest: hashCanonical(digestScope) };
}

/**
 * INDEPENDENT re-performance. Recompute every reliance verdict offline from the
 * packaged evidence under the package's pinned profile and AUDITOR-supplied keys,
 * trusting nothing the package asserts. Detect drift (recomputed ≠ stated), map
 * to control objectives, and emit an auditor-style workpaper. Conclusion fields
 * are ALWAYS null: the assurer concludes, not this tool.
 *
 * @param {object} pkg  an EP-ASSURANCE-PACKAGE-v1
 * @param {object} opts
 * @param {object} [opts.approverKeys]  auditor-pinned approver keys (out of band)
 * @param {string} [opts.logPublicKey]  auditor-pinned transparency-log key
 * @param {string} [opts.rpId]
 * @param {string[]} [opts.allowedOrigins]
 * @param {object} [opts.revokerKeys]
 * @param {(key:object)=>boolean} [opts.isConsumed] auditor-owned consumption lookup
 * @param {number|string|Date} [opts.now]  reliance-evaluation clock (pin for determinism)
 * @returns {object} EP-ASSURANCE-REPERFORMANCE-v1
 */
export function reperformAssurancePackage(pkg, { approverKeys = {}, logPublicKey = null, rpId = null, allowedOrigins = [], revokerKeys = {}, isConsumed, now = 0 } = {}) {
  if (!pkg || pkg['@version'] !== ASSURANCE_PACKAGE_VERSION) throw new Error('assurance-reperform: not an EP-ASSURANCE-PACKAGE-v1');
  const profile = pkg.reliance_profile;
  const evalOpts = { approverKeys, logPublicKey, rpId, allowedOrigins, revokerKeys, ...(typeof isConsumed === 'function' ? { isConsumed } : {}) };
  const relianceNow = typeof now === 'function' ? now() : now;

  const results = (Array.isArray(pkg.decisions) ? pkg.decisions : []).map((it) => {
    const ev = it.evidence || {};
    const input = {
      action: it.action || {},
      receipt: ev.receipt,
      quorum: ev.quorum || undefined,
      authority_proof: ev.authority_proof || undefined,
      revocation_state: ev.revocation_state || undefined,
      consumption: ev.consumption || undefined,
      relying_party_profile: profile,
      now: relianceNow,
    };
    let recomputed;
    try {
      recomputed = evaluateReliance(input, evalOpts);
    } catch (err) {
      recomputed = { verdict: 'do_not_rely_unsigned', rely: false, reasons: [`reperform_error:${err?.message || 'threw'}`] };
    }
    const recomputed_verdict = recomputed.verdict;
    const stated_verdict = it.stated_verdict ?? null;
    // Drift: the org's runtime claimed one outcome, independent re-performance
    // computed another. A claimed `rely` that recomputes to a refusal is the
    // material finding — the org relied on evidence that does not support reliance.
    const drift = stated_verdict !== null && stated_verdict !== recomputed_verdict;
    return {
      decision_id: it.decision_id,
      action_type: it.action?.action_type ?? null,
      stated_verdict,
      recomputed_verdict,
      admissible: recomputed_verdict === 'rely',
      drift,
      drift_severity: drift ? (stated_verdict === 'rely' ? 'relied_on_inadmissible_evidence' : 'refused_admissible_or_reclassified') : null,
      control_id: controlForVerdict(recomputed_verdict),
      reasons: recomputed.reasons || [],
    };
  });

  const byVerdict = Object.create(null);
  const byControl = Object.create(null);
  let admissible = 0;
  let refused = 0;
  let drift = 0;
  for (const r of results) {
    byVerdict[r.recomputed_verdict] = (byVerdict[r.recomputed_verdict] || 0) + 1;
    if (r.admissible) admissible += 1; else refused += 1;
    if (r.drift) drift += 1;
    if (r.control_id) byControl[r.control_id] = (byControl[r.control_id] || 0) + 1;
  }

  // Recompute the package digest from the package's OWN contents rather than
  // trusting pkg.package_digest. "No value the package asserts is trusted" has to
  // include the digest: copying the stated one verbatim would let a tampered
  // package carry a lying content-address through re-performance unchecked. Mirror
  // buildAssurancePackage's digestScope exactly (body minus assembled_at and the
  // digest field itself), then compare.
  const { assembled_at: _statedAt, package_digest: _statedDigest, ...digestScope } = pkg;
  const recomputedPackageDigest = hashCanonical(digestScope);
  const packageDigestVerified = pkg.package_digest != null && recomputedPackageDigest === pkg.package_digest;

  const doc = {
    '@version': ASSURANCE_REPERFORMANCE_VERSION,
    product: 'EMILIA Reliance Assurance',
    package_digest: recomputedPackageDigest,
    stated_package_digest: pkg.package_digest ?? null,
    package_digest_verified: packageDigestVerified,
    profile_hash: pkg.profile_hash ?? null,
    generated_at: toIso(now),
    honesty: {
      reperforms:
        'Independent recomputation of every reliance verdict from the packaged evidence, under the package\'s pinned '
        + 'EP-RELIANCE-PROFILE-v1 and auditor-supplied keys, using the offline reliance kernel. No value the package '
        + 'asserts (including the stated verdict) is trusted; the stated verdict is compared, never relied on.',
      does_not_establish: [
        'Completeness of the decision population: decisions withheld before packaging are not detectable from the package alone. Bind the population to an externally anchored count to close this.',
        'Runtime freshness or one-time consumption AT THE MOMENT OF DECISION: those were live properties; re-performance checks the evidence as packaged, not the runtime state that existed then.',
        'Issuer, approver, and registrar key custody, enrollment, or identity proofing, which remain external trust roots the auditor supplies out of band.',
        'The business correctness or wisdom of any authorized action.',
      ],
      status: 'Support for an audit re-performance procedure. This document does not conclude, opine, or certify; any conclusion is the auditor\'s.',
    },
    population: {
      decisions: results.length,
      admissible,
      refused,
      drift,
      relied_on_inadmissible_evidence: results.filter((r) => r.drift_severity === 'relied_on_inadmissible_evidence').length,
      by_recomputed_verdict: byVerdict,
      by_control: byControl,
    },
    control_catalog: RELIANCE_CONTROL_CATALOG,
    results,
    reperformance_digest: null, // filled below
    // Conclusion fields are ALWAYS null: a machine may support re-performance, it
    // may never fill in the auditor's sign-off. A renderer must refuse to print a
    // non-null conclusion here.
    conclusion: { supportable: null, opinion: null, signed_off_by: null },
  };
  // Deterministic re-performance digest over the recomputed results + population
  // (excludes timestamps), so a second assurer reproduces it byte-for-byte.
  doc.reperformance_digest = hashCanonical({ package_digest: doc.package_digest, population: doc.population, results });
  return doc;
}

/** Render a plain-text auditor workpaper. Refuses to print a filled conclusion. */
export function renderAssuranceWorkpaper(doc) {
  if (!doc || doc['@version'] !== ASSURANCE_REPERFORMANCE_VERSION) throw new Error('render: not an EP-ASSURANCE-REPERFORMANCE-v1');
  if (doc.conclusion && (doc.conclusion.supportable !== null || doc.conclusion.opinion !== null || doc.conclusion.signed_off_by !== null)) {
    throw new Error('render refused: conclusion fields must be null (the auditor concludes, not the tool)');
  }
  const p = doc.population;
  const lines = [];
  lines.push(`EMILIA Reliance Assurance — re-performance workpaper (${doc['@version']})`);
  lines.push(`package_digest:       ${doc.package_digest} (recomputed)`);
  lines.push(`package_digest match: ${doc.package_digest_verified ? 'YES — recomputed digest equals the package\'s stated digest' : 'NO — stated digest does NOT match recomputed contents (tamper or drift)'}`);
  lines.push(`reperformance_digest: ${doc.reperformance_digest}`);
  lines.push('');
  lines.push(`Population: ${p.decisions} decisions | admissible(rely): ${p.admissible} | refused: ${p.refused} | drift: ${p.drift}`);
  lines.push(`Relied on INADMISSIBLE evidence (claimed rely, recomputed refusal): ${p.relied_on_inadmissible_evidence}`);
  lines.push('');
  lines.push('By recomputed verdict:');
  for (const [v, n] of Object.entries(p.by_recomputed_verdict)) lines.push(`  ${v}: ${n}`);
  lines.push('');
  lines.push('Control objectives exercised (denials are the control operating):');
  for (const [cid, n] of Object.entries(p.by_control)) lines.push(`  ${cid} (${RELIANCE_CONTROL_CATALOG[cid].objective}): ${n}`);
  lines.push('');
  const drifts = doc.results.filter((r) => r.drift);
  if (drifts.length) {
    lines.push('DRIFT (independent re-performance disagrees with the runtime\'s stated verdict):');
    for (const r of drifts) lines.push(`  ${r.decision_id}: stated=${r.stated_verdict} recomputed=${r.recomputed_verdict} [${r.drift_severity}]`);
    lines.push('');
  }
  lines.push('Conclusion: NULL by construction. The auditor concludes; this workpaper only supports the procedure.');
  return lines.join('\n');
}
