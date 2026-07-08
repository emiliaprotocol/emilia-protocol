// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AEG-v1 — Action Evidence Graph + Evidence Policy Replay.
 *
 * THE LAYER THIS IS
 * -----------------
 * Every standards effort in the 2026 landscape produces a signed artifact
 * about an agent action (identity, delegation, permit, human authorization,
 * execution record, attestation, transparency receipt). None of them decides.
 * The unowned layer is the one that answers, deterministically and offline:
 * "given all these artifacts, is this action evidence SUFFICIENT for THIS
 * reliance purpose?" This module is that layer:
 *
 *   1. EVIDENCE GRAPH — a portable, content-addressed graph of REFERENCES to
 *      signed artifacts. Nodes are digests (artifacts optionally inlined);
 *      edges are typed relations. The graph's identity is its structure, not
 *      its disclosure: the digest is the same whether or not artifact bytes
 *      travel with it, so disclosure-constrained relying parties can hold the
 *      shape without the contents (unresolved required nodes fail CLOSED).
 *
 *   2. EVIDENCE POLICY REPLAY — a deterministic evaluation of (graph, policy,
 *      as_of) -> verdict, where the policy is RELYING-PARTY-supplied, never
 *      read from the presented graph. Same inputs -> same verdict + same
 *      replay_digest, so any third party can recompute the decision.
 *
 *   3. RELIANCE RESULT — the verdict as a signed, portable artifact
 *      (EP-RELIANCE-RESULT-v1), so the reliance decision itself becomes
 *      auditable evidence. The signature adds accountability, never authority:
 *      the embedded replay_digest lets anyone recompute the verdict rather
 *      than trust the signer.
 *
 * TRUST BOUNDARIES (each one is load-bearing)
 * - Edges are PRESENTER CLAIMS. An edge only counts when the referenced
 *   binding exists in the source artifact's own bytes (digest containment or
 *   a caller-supplied checker). A claimed-but-unbacked edge poisons the
 *   verdict (unverifiable) — a graph that lies is worse than a sparse one.
 * - The policy comes from the relying party. There is no policy field in the
 *   graph document, by construction.
 * - Verdicts are evidence, not adjudication: "admissible" means the bundle
 *   meets THIS policy for THIS purpose at THIS time — nothing more.
 */
import crypto from 'node:crypto';
import { evaluateAdmissibility } from './admissibility.js';
import { evaluatePredictedEffects, predictedEffectsDigest } from './effect-predicates.js';

export const EVIDENCE_GRAPH_VERSION = 'EP-AEG-v1';
export const RELIANCE_RESULT_VERSION = 'EP-RELIANCE-RESULT-v1';

/** Edge relation registry (v1). Unknown rels are structural errors. */
export const EDGE_RELS = Object.freeze([
  'authorizes',        // human authorization -> action / execution
  'permits',           // policy permit -> action / execution
  'delegates',         // delegation -> the authority it conveys
  'executes',          // execution record -> the authorization it acted under
  'records',           // transparency entry -> the artifact it logged
  'attests_runtime',   // attestation -> the workload it vouches for
  'revokes',           // revocation statement -> the artifact it revokes
  'provides_recourse', // recourse reference -> the authorization it covers
  'supersedes',        // newer artifact -> the one it replaces
]);

/** Machine-readable reason codes carried in reasons[] alongside prose. */
export const REASON_CODES = Object.freeze([
  'missing_human_approval', 'untrusted_workload', 'contradicted_outcome',
  'stale_evidence', 'unresolved_required_node', 'unbacked_edge_claim',
  'revoked_artifact', 'action_digest_mismatch', 'malformed_graph',
  // Step 6 node types:
  'rubber_stamped_ceremony',    // ceremony_evidence: approval below the review-latency floor
  'effect_divergence',          // effect_attestation: executed effect != approved effect (exact digest OR out-of-bounds predicate)
  'ceremony_telemetry_missing', // ceremony_evidence: required latency floor set but telemetry absent/unusable
  'effect_commitment_missing',  // effect_attestation: no approved effect to compare the observed effect against
  'effect_incomparable',        // effect_attestation: predicted effects present but the observed effects are missing/malformed/ambiguous for a predicate — a refusal, never a pass
]);

/**
 * Node types this module gives first-class evidence treatment. The base set is
 * open (any string type routes through its registered verifier); these two get
 * ADDITIONAL offline evidence rules below, beyond signature verification:
 *
 *   ceremony_evidence  — signing-ceremony telemetry (challenge issued_at /
 *     viewed_at / approved_at + approver id). Enables a review-latency floor:
 *     an approval whose (approved_at - viewed_at) is below the policy floor is
 *     evidence of RUBBER-STAMPING, and downgrades the verdict to 'conflicted'
 *     (the recorded human review contradicts a genuine one). The verifier still
 *     proves the ceremony record is authentic; this rule judges what it says.
 *
 *   effect_attestation — the executor signs {receipt_id, observed_effect_digest}
 *     AFTER execution. It closes the "approved X, executed Y" gap: if the
 *     observed_effect_digest diverges from the approved action's committed
 *     effect digest, that divergence is offline-checkable and downgrades the
 *     verdict to 'conflicted'. FAIL-CLOSED: an effect_attestation whose
 *     signature does not verify, or whose executor key is not pinned, is
 *     `valid:false` at the verifier and therefore inadmissible ('unverifiable')
 *     — it is not weighed as effect evidence at all.
 *
 *     OUTCOME BINDING (EP-OUTCOME-BINDING-v1, additive): when the approved
 *     receipt payload carries predicted_effects — [{effect_type, target,
 *     predicate}] with tolerance bounds (see effect-predicates.js) — the
 *     attestation carries observed_effects and each predicate is evaluated
 *     deterministically. 'divergent' OR 'incomparable' (missing/malformed
 *     observation — a refusal, never a pass) downgrades to 'conflicted'
 *     exactly like the exact-digest path, which remains the degenerate
 *     {op:"eq"}-over-one-digest case and keeps working unchanged.
 */
export const CEREMONY_EVIDENCE_TYPE = 'ceremony_evidence';
export const EFFECT_ATTESTATION_TYPE = 'effect_attestation';

// Deterministic JCS-style canonicalization (I-JSON subset; no floats) —
// byte-identical to lib/evidence/admissibility.js canon().
function canon(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`;
}
const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
const normDigest = (d) => (typeof d === 'string' ? d.replace(/^sha256:/i, '').toLowerCase() : null);

/** Content digest of an artifact: sha256 over its canonical bytes. */
export function artifactDigest(artifact) {
  return `sha256:${sha256hex(canon(artifact))}`;
}

/**
 * Graph identity = structure only (node ids/types + edges + action digest),
 * INDEPENDENT of whether artifact bytes are inlined. Disclosure does not
 * change what graph you are talking about.
 */
export function graphDigest(graph) {
  const nodes = (graph?.nodes || []).map((n) => ({ id: normDigest(n.id), type: n.type ?? null }))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const edges = (graph?.edges || []).map((e) => ({ from: normDigest(e.from), rel: e.rel ?? null, to: normDigest(e.to) }))
    .sort((a, b) => canon(a) < canon(b) ? -1 : 1);
  return `sha256:${sha256hex(canon({ v: EVIDENCE_GRAPH_VERSION, action_digest: normDigest(graph?.action_digest), nodes, edges }))}`;
}

/**
 * Default edge-backing check: the source artifact's canonical bytes must
 * contain the target's bare digest as a string value somewhere. Byte-grounded
 * and type-agnostic; per-rel checkers in opts.edgeCheckers can be stricter.
 */
function edgeBackedByBytes(fromArtifact, toDigestBare) {
  if (!fromArtifact || !toDigestBare) return false;
  return canon(fromArtifact).toLowerCase().includes(toDigestBare);
}

/**
 * Raise a 'conflicted'-class finding into the closed verdict set WITHOUT
 * violating precedence (unverifiable > conflicted > stale > missing_evidence >
 * admissible). 'unverifiable' is strictly worse and is never softened to
 * 'conflicted'; every other verdict (including a fresh 'conflicted') resolves to
 * 'conflicted'. This never moves a verdict toward 'admissible'.
 */
function downgradeToConflicted(verdict) {
  return verdict === 'unverifiable' ? 'unverifiable' : 'conflicted';
}

/**
 * Evaluate an Action Evidence Graph against a relying-party policy.
 * FAIL-CLOSED: anything malformed, unresolved-but-required, unbacked, or
 * conflicting degrades the verdict; nothing degrades toward "admissible".
 *
 * @param {object} graphDoc {'@version', action_digest, nodes:[{id,type,artifact?}], edges:[{from,rel,to}]}
 * @param {object} policy   EvidencePolicy (see admissibility.js) + optional
 *                          {required_edges:[{from_type,rel,to_type}],
 *                           ceremony_min_review_sec?: number,  // review-latency floor for ceremony_evidence
 *                           expected_effect_digest?: string,   // relying-party-pinned approved effect for effect_attestation
 *                           predicted_effects?: object[]}      // relying-party-pinned approved predicted effects (EP-OUTCOME-BINDING-v1)
 * @param {object} [opts]   {verifiers?: {[type]:(artifact)=>({valid,action_digest,issued_at?,outcome?,revoked?,
 *                             // ceremony_evidence verifiers additionally return: approver?, viewed_at?, approved_at?
 *                             // effect_attestation verifiers additionally return: receipt_id?, observed_effect_digest?, committed_effect_digest?,
 *                             //   and (EP-OUTCOME-BINDING-v1) observed_effects?, predicted_effects?, predicted_effects_digest? — predicted_effects
 *                             //   is read by the verifier out of the referenced APPROVED payload, never from presenter claim
 *                           })},
 *                           edgeCheckers?: {[rel]:(fromArtifact,toArtifact,edge)=>boolean},
 *                           as_of?: string}
 */
export function evaluateEvidenceGraph(graphDoc, policy, opts = {}) {
  const reasons = [];
  const g_digest = graphDigest(graphDoc);
  const structuralFail = (why, code) => {
    reasons.push(code ? `${code}: ${why}` : why);
    const res = evaluateAdmissibility({ components: [{ type: 'evidence_graph', verified: false }] }, policy, { as_of: opts.as_of });
    res.reasons = [...reasons, ...res.reasons];
    res.graph = { graph_digest: g_digest, nodes: 0, edges: 0 };
    return res;
  };

  if (!graphDoc || typeof graphDoc !== 'object') return structuralFail('graph is not an object', 'malformed_graph');
  if (graphDoc['@version'] !== EVIDENCE_GRAPH_VERSION) return structuralFail(`unexpected @version (want ${EVIDENCE_GRAPH_VERSION})`, 'malformed_graph');
  if (!policy || typeof policy !== 'object') return structuralFail('no relying-party policy supplied', 'malformed_graph');
  const nodes = Array.isArray(graphDoc.nodes) ? graphDoc.nodes : null;
  const edges = Array.isArray(graphDoc.edges) ? graphDoc.edges : [];
  if (!nodes || nodes.length === 0) return structuralFail('graph has no nodes', 'malformed_graph');
  for (const e of edges) {
    if (!EDGE_RELS.includes(e?.rel)) return structuralFail(`unknown edge rel "${e?.rel}"`, 'malformed_graph');
  }

  const verifiers = opts.verifiers || {};
  const byId = new Map();

  // 1) Resolve + verify nodes into admissibility facts.
  const facts = nodes.map((n, idx) => {
    const id = normDigest(n.id);
    const row = {
      type: n.type, label: n.label ?? `#${idx}`, verified: false,
      action_digest: null, issued_at: undefined, outcome: undefined, revoked: undefined,
    };
    const rec = { node: n, id, artifact: null, verified: false, fact: row };
    byId.set(id, rec);
    if (!id) { reasons.push(`malformed_graph: node ${row.label} has no digest id`); return row; }
    if (n.artifact == null) return row; // unresolved: shape-only disclosure — fails closed if required
    if (normDigest(artifactDigest(n.artifact)) !== id) {
      reasons.push(`action_digest_mismatch: node ${row.label} inline artifact does not hash to its id`);
      return row;
    }
    rec.artifact = n.artifact;
    const v = verifiers[n.type];
    if (typeof v !== 'function') { reasons.push(`no verifier registered for node type "${n.type}"`); return row; }
    let res;
    try { res = v(n.artifact) || {}; } catch (e) { reasons.push(`verifier threw for ${row.label}: ${e.message}`); return row; }
    row.verified = res.valid === true;
    row.action_digest = res.action_digest ?? null;
    row.issued_at = res.issued_at;
    row.outcome = res.outcome;
    row.revoked = res.revoked;
    // Step 6 telemetry, surfaced by the type verifier alongside signature state.
    // ceremony_evidence: the signing-ceremony timeline + approver id.
    if (n.type === CEREMONY_EVIDENCE_TYPE) {
      row.ceremony = {
        approver: res.approver ?? null,
        issued_at: res.issued_at ?? null,
        viewed_at: res.viewed_at ?? null,
        approved_at: res.approved_at ?? null,
      };
    }
    // effect_attestation: the executor-signed observed effect + the receipt it
    // attests. committed_effect_digest is the APPROVED effect the verifier read
    // out of the referenced authorization (never presenter-chosen here).
    if (n.type === EFFECT_ATTESTATION_TYPE) {
      row.effect = {
        receipt_id: res.receipt_id ?? null,
        observed_effect_digest: normDigest(res.observed_effect_digest),
        committed_effect_digest: normDigest(res.committed_effect_digest),
        // EP-OUTCOME-BINDING-v1: observed effects the executor attested, plus
        // the predicted effects the verifier read out of the APPROVED payload
        // (never presenter-chosen) and the digest the payload bound them under.
        observed_effects: Array.isArray(res.observed_effects) ? res.observed_effects : null,
        predicted_effects: Array.isArray(res.predicted_effects) ? res.predicted_effects : null,
        predicted_effects_digest: normDigest(res.predicted_effects_digest),
      };
    }
    rec.verified = row.verified;
    return row;
  });

  // 2) Edges: presenter claims, checked against the source artifact's bytes.
  let unbacked = 0;
  const edgeRows = edges.map((e) => {
    const from = byId.get(normDigest(e.from));
    const to = byId.get(normDigest(e.to));
    const row = { from_type: from?.node?.type ?? null, rel: e.rel, to_type: to?.node?.type ?? null, backed: false };
    if (!from || !to) { reasons.push(`unbacked_edge_claim: edge ${e.rel} references a node not in the graph`); unbacked++; return row; }
    if (!from.verified || !to.verified) return row; // unresolved endpoints: edge simply doesn't count
    const checker = opts.edgeCheckers?.[e.rel];
    row.backed = checker
      ? checker(from.artifact, to.artifact, e) === true
      : edgeBackedByBytes(from.artifact, to.id);
    if (!row.backed) { reasons.push(`unbacked_edge_claim: "${from.node.type}" -${e.rel}-> "${to.node.type}" is not present in the source artifact's bytes`); unbacked++; }
    return row;
  });

  // 3) Required edges (policy): required-but-absent/unbacked => the FROM type
  //    is REMOVED from the fact set. An artifact whose required binding is
  //    absent contributes nothing — that is missing evidence, not a lie
  //    (unbacked CLAIMED edges are handled separately, and harsher, above).
  const strippedTypes = new Set();
  for (const req of policy.required_edges || []) {
    const ok = edgeRows.some((r) => r.backed && r.from_type === req.from_type && r.rel === req.rel && r.to_type === req.to_type);
    if (!ok) {
      strippedTypes.add(req.from_type);
      reasons.push(`required edge missing: "${req.from_type}" -${req.rel}-> "${req.to_type}"`);
    }
  }
  const effectiveFacts = facts.filter((f) => !strippedTypes.has(f.type));

  // 4) Classify via the admissibility layer (purpose-relative, replayable).
  const result = evaluateAdmissibility(
    { action_digest: graphDoc.action_digest, components: effectiveFacts },
    policy,
    { as_of: opts.as_of },
  );

  // 5) A lying graph is unverifiable regardless of what else passed.
  if (unbacked > 0 && result.verdict === 'admissible') result.verdict = 'unverifiable';

  // 6a) CEREMONY LATENCY FLOOR. A verified ceremony_evidence node whose
  //     (approved_at - viewed_at) is below the policy floor is evidence of
  //     RUBBER-STAMPING: the recorded human review contradicts a genuine one.
  //     This is a 'conflicted'-class finding (like a denial): it never moves
  //     the verdict toward admissible, and never overrides an already-worse
  //     'unverifiable'. Fail closed: if a floor is set but the telemetry is
  //     absent or unparseable on a verified node, we cannot show real review,
  //     so that too is 'conflicted' (never a silent pass).
  const floorSec = Number.isFinite(policy?.ceremony_min_review_sec) ? policy.ceremony_min_review_sec : null;
  if (floorSec !== null) {
    for (const f of effectiveFacts) {
      if (f.type !== CEREMONY_EVIDENCE_TYPE || !f.verified) continue;
      const cer = f.ceremony || {};
      const viewed = Date.parse(cer.viewed_at);
      const approved = Date.parse(cer.approved_at);
      if (Number.isNaN(viewed) || Number.isNaN(approved) || approved < viewed) {
        reasons.push(`ceremony_telemetry_missing: ceremony_evidence "${f.label}" has a review-latency floor (${floorSec}s) but no usable viewed_at/approved_at`);
        result.verdict = downgradeToConflicted(result.verdict);
        continue;
      }
      const reviewSec = Math.floor((approved - viewed) / 1000);
      if (reviewSec < floorSec) {
        reasons.push(`rubber_stamped_ceremony: ceremony_evidence "${f.label}" approved in ${reviewSec}s, below the ${floorSec}s review-latency floor (approver ${cer.approver ?? 'unknown'})`);
        result.verdict = downgradeToConflicted(result.verdict);
      }
    }
  }

  // 6b) EFFECT DIVERGENCE. A verified effect_attestation binds the executor's
  //     observed_effect_digest. If it diverges from the APPROVED committed
  //     effect digest, "approved X, executed Y" is proven offline — a
  //     'conflicted'-class finding. The committed digest is relying-party
  //     pinned (policy.expected_effect_digest) or read by the verifier from the
  //     authorization it references; it is NEVER taken from presenter claim.
  //     Fail closed: a verified effect_attestation with no committed effect to
  //     compare against is 'conflicted' (we cannot show the effect was
  //     approved), never admissible.
  const pinnedEffect = normDigest(policy?.expected_effect_digest);
  const pinnedPredicted = Array.isArray(policy?.predicted_effects) ? policy.predicted_effects : null;
  for (const f of effectiveFacts) {
    if (f.type !== EFFECT_ATTESTATION_TYPE || !f.verified) continue;
    const eff = f.effect || {};
    const observed = eff.observed_effect_digest;
    const committed = pinnedEffect ?? eff.committed_effect_digest ?? null;
    // 6b-i) PREDICTED EFFECTS (EP-OUTCOME-BINDING-v1). The predictions are the
    //       relying-party-pinned array (policy.predicted_effects) or the array
    //       the verifier read out of the APPROVED payload — never presenter
    //       claim. Each predicate is evaluated deterministically against the
    //       executor-attested observed_effects. 'divergent' and 'incomparable'
    //       (missing/malformed observation — a refusal, never a pass) both
    //       downgrade to 'conflicted', exactly like the exact-digest path.
    const predicted = pinnedPredicted ?? eff.predicted_effects ?? null;
    if (predicted !== null) {
      if (eff.predicted_effects_digest
          && normDigest(predictedEffectsDigest(predicted)) !== eff.predicted_effects_digest) {
        reasons.push(`effect_incomparable: effect_attestation "${f.label}" predicted effects do not hash to the bound predicted_effects_digest`);
        result.verdict = downgradeToConflicted(result.verdict);
      } else {
        const ev = evaluatePredictedEffects(predicted, eff.observed_effects);
        if (ev.outcome === 'divergent') {
          reasons.push(`effect_divergence: effect_attestation "${f.label}" observed effects diverge from the approved predicted effects: ${ev.reasons.join('; ')}`);
          result.verdict = downgradeToConflicted(result.verdict);
        } else if (ev.outcome === 'incomparable') {
          reasons.push(`effect_incomparable: effect_attestation "${f.label}" cannot be compared to the approved predicted effects (refusal, never a pass): ${ev.reasons.join('; ')}`);
          result.verdict = downgradeToConflicted(result.verdict);
        }
      }
      // If the attestation ALSO carries the exact digests, they must agree too
      // (the degenerate case never weakens the predicate result).
      if (observed && committed && observed !== committed) {
        reasons.push(`effect_divergence: effect_attestation "${f.label}" observed ${observed} but the approved committed effect is ${committed} ("approved X, executed Y")`);
        result.verdict = downgradeToConflicted(result.verdict);
      }
      continue;
    }
    // 6b-ii) EXACT DIGEST (the pre-existing path; the degenerate {op:"eq"}
    //        case over one digest). Unchanged behavior when no predictions.
    if (!observed) {
      reasons.push(`effect_divergence: effect_attestation "${f.label}" carries no observed_effect_digest`);
      result.verdict = downgradeToConflicted(result.verdict);
      continue;
    }
    if (!committed) {
      reasons.push(`effect_commitment_missing: effect_attestation "${f.label}" has an observed effect but no approved committed effect to compare against`);
      result.verdict = downgradeToConflicted(result.verdict);
      continue;
    }
    if (observed !== committed) {
      reasons.push(`effect_divergence: effect_attestation "${f.label}" observed ${observed} but the approved committed effect is ${committed} ("approved X, executed Y")`);
      result.verdict = downgradeToConflicted(result.verdict);
    }
  }

  result.reasons = [...reasons, ...result.reasons];
  result.graph = { graph_digest: g_digest, nodes: nodes.length, edges: edges.length, edge_rows: edgeRows };
  // Graph replay digest binds the graph identity into the replay property.
  result.replay_digest = `sha256:${sha256hex(canon({ base: result.replay_digest, graph: g_digest }))}`;
  return result;
}

/**
 * EP-RELIANCE-RESULT-v1 — the verdict as a signed, portable artifact.
 * Accountability, not authority: verify the signature to know WHO decided;
 * recompute the replay_digest to know the decision was honest.
 */
export function signRelianceResult(result, policy, privateKey, opts = {}) {
  const payload = {
    '@version': RELIANCE_RESULT_VERSION,
    verdict: result.verdict,
    reasons: result.reasons,
    action_digest: result.action_digest,
    graph_digest: result.graph?.graph_digest ?? null,
    policy_digest: `sha256:${sha256hex(canon(policy))}`,
    policy_id: policy?.policy_id ?? null,
    reliance_purpose: policy?.reliance_purpose ?? null,
    replay_digest: result.replay_digest,
    evaluated_at: opts.evaluated_at ?? null,
  };
  const sig = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey);
  const pub = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  return { payload, sig: sig.toString('base64url'), verifier_key: pub.toString('base64url') };
}

/**
 * Verified vs accepted, as everywhere in EP: `verified` = the signature holds
 * over the canonical payload; `accepted` additionally requires the verifier
 * key to be PINNED by the caller (out-of-band trust in who decided).
 */
export function verifyRelianceResult(doc, pinnedVerifierKeys = []) {
  const checks = { structure: false, signature: false, issuer_pinned: false };
  if (!doc?.payload || doc.payload['@version'] !== RELIANCE_RESULT_VERSION || typeof doc.sig !== 'string' || typeof doc.verifier_key !== 'string') {
    return { verified: false, accepted: false, checks };
  }
  checks.structure = true;
  let key;
  try { key = crypto.createPublicKey({ key: Buffer.from(doc.verifier_key, 'base64url'), type: 'spki', format: 'der' }); }
  catch { return { verified: false, accepted: false, checks }; }
  try {
    checks.signature = crypto.verify(null, Buffer.from(canon(doc.payload), 'utf8'), key, Buffer.from(doc.sig, 'base64url'));
  } catch { checks.signature = false; }
  checks.issuer_pinned = pinnedVerifierKeys.includes(doc.verifier_key);
  const verified = checks.structure && checks.signature;
  return { verified, accepted: verified && checks.issuer_pinned, checks };
}
