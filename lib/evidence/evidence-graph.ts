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
import type { KeyLike } from 'node:crypto';
import { evaluateAdmissibility } from './admissibility.js';
import {
  evaluatePredictedEffects,
  predictedEffectsDigest,
  validatePredictedEffects,
} from './effect-predicates.js';

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
 *     deterministically. Structured observations require a signed prediction
 *     baseline returned by opts.resolveApprovedEffect(); relying-party policy
 *     is additive and may tighten that baseline, never replace it. The approved
 *     side is NEVER accepted from the executor-signed attestation. 'divergent'
 *     OR 'incomparable'
 *     (missing/malformed observation — a refusal, never a pass) downgrades to
 *     'conflicted' exactly like the exact-digest path.
 */
export const CEREMONY_EVIDENCE_TYPE = 'ceremony_evidence';
export const EFFECT_ATTESTATION_TYPE = 'effect_attestation';

// Deterministic JCS-style canonicalization (I-JSON subset; no floats) —
// byte-identical to lib/evidence/admissibility.js canon().
function canon(v: any): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`;
  return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(',')}}`;
}
const sha256hex = (s: string): string => crypto.createHash('sha256').update(s).digest('hex');
const normDigest = (d: unknown): string | null => (typeof d === 'string' ? d.replace(/^sha256:/i, '').toLowerCase() : null);

/** Content digest of an artifact: sha256 over its canonical bytes. */
export function artifactDigest(artifact: unknown): string {
  return `sha256:${sha256hex(canon(artifact))}`;
}

/**
 * Graph identity = structure only (node ids/types + edges + action digest),
 * INDEPENDENT of whether artifact bytes are inlined. Disclosure does not
 * change what graph you are talking about.
 */
export function graphDigest(graph: any): string {
  const nodes = (graph?.nodes || []).map((n: any) => ({ id: normDigest(n.id), type: n.type ?? null }))
    .sort((a: any, b: any) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const edges = (graph?.edges || []).map((e: any) => ({ from: normDigest(e.from), rel: e.rel ?? null, to: normDigest(e.to) }))
    .sort((a: any, b: any) => canon(a) < canon(b) ? -1 : 1);
  return `sha256:${sha256hex(canon({ v: EVIDENCE_GRAPH_VERSION, action_digest: normDigest(graph?.action_digest), nodes, edges }))}`;
}

/**
 * Default edge-backing check: the source artifact's canonical bytes must
 * contain the target's bare digest as a string value somewhere. Byte-grounded
 * and type-agnostic; per-rel checkers in opts.edgeCheckers can be stricter.
 */
function edgeBackedByBytes(fromArtifact: unknown, toDigestBare: string | null): boolean {
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
function downgradeToConflicted(verdict: string): string {
  return verdict === 'unverifiable' ? 'unverifiable' : 'conflicted';
}

/**
 * Evaluate an Action Evidence Graph against a relying-party policy.
 * FAIL-CLOSED: anything malformed, unresolved-but-required, unbacked, or
 * conflicting degrades the verdict; nothing degrades toward "admissible".
 *
 * `graphDoc` and `policy` are typed `any` deliberately, matching
 * evaluateAdmissibility()'s own params (lib/evidence/admissibility.ts): both
 * are presenter/relying-party-supplied documents whose shape this function
 * validates structurally at runtime rather than trusting a static type for.
 *
 * @param graphDoc {'@version', action_digest, nodes:[{id,type,artifact?}], edges:[{from,rel,to}]}
 * @param policy   EvidencePolicy (see admissibility.js) + optional
 *                          {required_edges:[{from_type,rel,to_type}],
 *                           ceremony_min_review_sec?: number,  // review-latency floor for ceremony_evidence
 *                           expected_effect_digest?: string,   // relying-party-pinned approved effect for effect_attestation
 *                           predicted_effects?: object[]}      // relying-party-pinned approved predicted effects (EP-OUTCOME-BINDING-v1)
 * @param opts   {verifiers?: {[type]:(artifact)=>({valid,action_digest,issued_at?,outcome?,revoked?,
 *                             // ceremony_evidence verifiers additionally return: approver?, viewed_at?, approved_at?
 *                             // effect_attestation verifiers additionally return only executor-attested fields:
 *                             //   receipt_id?, observed_effect_digest?, observed_effects?
 *                           })},
 *                           resolveApprovedEffect?: (receipt_id:string)=>({
 *                             valid:boolean, receipt_id?:string,
 *                             action_digest?:string, action_hash?:string,
 *                             committed_effect_digest?:string,
 *                             predicted_effects?:object[],
 *                             predicted_effects_digest?:string
 *                           }),
 *                           edgeCheckers?: {[rel]:(fromArtifact,toArtifact,edge)=>boolean},
 *                           as_of?: string}
 */
export function evaluateEvidenceGraph(graphDoc: any, policy: any, opts: any = {}): any {
  opts = opts && typeof opts === 'object' && !Array.isArray(opts) ? opts : {};
  const reasons: string[] = [];
  const g_digest = graphDigest(graphDoc);
  const structuralFail = (why: string, code?: string): any => {
    reasons.push(code ? `${code}: ${why}` : why);
    // The malformed-graph component intentionally has no action_digest to report
    // (there is nothing to bind yet); admissibility.js's Component type declares
    // action_digest required, so this minimal literal is cast loosely rather than
    // widening that shared type from this batch. evaluateAdmissibility()'s own
    // return type is likewise not declared, so the whole result is `any` here —
    // this function augments it with graph-shape metadata after the fact.
    const res: any = evaluateAdmissibility({ components: [{ type: 'evidence_graph', verified: false } as any] }, policy, { as_of: opts.as_of });
    res.reasons = [...reasons, ...res.reasons];
    // evaluateAdmissibility's return type doesn't declare `graph` — this function
    // augments the result with graph-shape metadata after the fact.
    res.graph = { graph_digest: g_digest, nodes: 0, edges: 0 };
    res.outcome_binding = {
      '@version': 'EP-OUTCOME-BINDING-v1',
      outcome: 'incomparable',
      evaluations: [],
    };
    res.replay = {
      '@version': 'EP-AEG-REPLAY-v1',
      base: res.replay,
      graph: res.graph,
      verdict: res.verdict,
      reasons: res.reasons,
      outcome_binding: res.outcome_binding,
    };
    res.replay_digest = `sha256:${sha256hex(canon(res.replay))}`;
    return res;
  };

  if (!graphDoc || typeof graphDoc !== 'object') return structuralFail('graph is not an object', 'malformed_graph');
  if (graphDoc['@version'] !== EVIDENCE_GRAPH_VERSION) return structuralFail(`unexpected @version (want ${EVIDENCE_GRAPH_VERSION})`, 'malformed_graph');
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) return structuralFail('no relying-party policy supplied', 'malformed_graph');
  if (Object.hasOwn(policy, 'required_edges') && !Array.isArray(policy.required_edges)) {
    return structuralFail('relying-party policy required_edges is not an array', 'malformed_graph');
  }
  if (Array.isArray(policy.required_edges)
      && !policy.required_edges.every((edge) => edge && typeof edge === 'object'
        && !Array.isArray(edge)
        && typeof edge.from_type === 'string' && edge.from_type
        && typeof edge.rel === 'string' && EDGE_RELS.includes(edge.rel)
        && typeof edge.to_type === 'string' && edge.to_type)) {
    return structuralFail('relying-party policy required_edges contains a malformed edge', 'malformed_graph');
  }
  if (Object.hasOwn(policy, 'ceremony_min_review_sec')
      && (!Number.isFinite(policy.ceremony_min_review_sec)
        || policy.ceremony_min_review_sec < 0)) {
    return structuralFail('relying-party policy ceremony_min_review_sec is not a non-negative finite number', 'malformed_graph');
  }
  if (Object.hasOwn(policy, 'expected_effect_digest')
      && (typeof policy.expected_effect_digest !== 'string'
        || !/^(?:sha256:)?[0-9a-f]{64}$/i.test(policy.expected_effect_digest))) {
    return structuralFail('relying-party policy expected_effect_digest is malformed', 'malformed_graph');
  }
  const nodes = Array.isArray(graphDoc.nodes) ? graphDoc.nodes : null;
  const edges = Array.isArray(graphDoc.edges) ? graphDoc.edges : [];
  if (!nodes || nodes.length === 0) return structuralFail('graph has no nodes', 'malformed_graph');
  for (const e of edges) {
    if (!EDGE_RELS.includes(e?.rel)) return structuralFail(`unknown edge rel "${e?.rel}"`, 'malformed_graph');
  }

  const verifiers = opts.verifiers || {};
  const byId = new Map<string | null, any>();

  // 1) Resolve + verify nodes into admissibility facts.
  const facts = nodes.map((n: any, idx: number) => {
    const id = normDigest(n.id);
    // `ceremony`/`effect` are populated conditionally below, per node type —
    // declared here so those later assignments aren't adding unknown
    // properties to an otherwise-fixed object-literal type.
    const row: {
      type: any; label: any; verified: boolean; action_digest: any;
      issued_at: any; outcome: any; revoked: any;
      ceremony?: any; effect?: any;
    } = {
      type: n.type, label: n.label ?? `#${idx}`, verified: false,
      action_digest: null, issued_at: undefined, outcome: undefined, revoked: undefined,
    };
    const rec = { node: n, id, artifact: null as any, verified: false, fact: row };
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
    const verifierChecks = res?.checks && typeof res.checks === 'object'
      ? res.checks
      : (res?.attestation_result?.checks && typeof res.attestation_result.checks === 'object'
        ? res.attestation_result.checks : null);
    const explicitSignatureFailure = verifierChecks
      && Object.hasOwn(verifierChecks, 'signature') && verifierChecks.signature !== true;
    const explicitPinFailure = verifierChecks
      && Object.hasOwn(verifierChecks, 'executor_key_pinned')
      && verifierChecks.executor_key_pinned !== true;
    row.verified = res.valid === true && !explicitSignatureFailure && !explicitPinFailure;
    if (explicitSignatureFailure) reasons.push(`executor_signature_invalid: ${row.label} reported a failed executor signature check`);
    if (explicitPinFailure) reasons.push(`executor_key_not_pinned: ${row.label} reported an unpinned executor key`);
    const verifierCommitments = res?.commitments && typeof res.commitments === 'object'
      ? res.commitments : {};
    const verifiedAttestation = res?.attestation && typeof res.attestation === 'object'
      ? res.attestation : {};
    row.action_digest = res.action_digest ?? verifierCommitments.action_hash ?? null;
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
    // effect_attestation: only the executor-signed observed effect + the receipt
    // it names. Approved commitments are deliberately absent from this verifier
    // result: accepting them here would let the executor choose both sides of the
    // comparison. They are resolved later from relying-party-controlled input.
    if (n.type === EFFECT_ATTESTATION_TYPE) {
      row.effect = {
        receipt_id: res.receipt_id ?? verifierCommitments.receipt_id ?? null,
        receipt_digest: normDigest(res.receipt_digest ?? verifierCommitments.receipt_digest),
        action_hash: normDigest(res.action_hash ?? verifierCommitments.action_hash ?? row.action_digest),
        consumption_nonce: res.consumption_nonce ?? verifierCommitments.consumption_nonce ?? null,
        executor_id: res.executor_id ?? verifierCommitments.executor_id ?? null,
        executor_key_id: res.executor_key_id ?? verifierCommitments.executor_key_id ?? null,
        observed_effect_digest: normDigest(res.observed_effect_digest
          ?? verifiedAttestation.observed_effect_digest),
        observed_effects: Array.isArray(res.observed_effects) ? res.observed_effects
          : (Array.isArray(verifiedAttestation.observed_effects)
            ? verifiedAttestation.observed_effects : null),
      };
    }
    rec.verified = row.verified;
    return row;
  });

  // 2) Edges: presenter claims, checked against the source artifact's bytes.
  let unbacked = 0;
  const edgeRows = edges.map((e: any) => {
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
  const strippedTypes = new Set<any>();
  for (const req of policy.required_edges || []) {
    const ok = edgeRows.some((r) => r.backed && r.from_type === req.from_type && r.rel === req.rel && r.to_type === req.to_type);
    if (!ok) {
      strippedTypes.add(req.from_type);
      reasons.push(`required edge missing: "${req.from_type}" -${req.rel}-> "${req.to_type}"`);
    }
  }
  const effectiveFacts = facts.filter((f) => !strippedTypes.has(f.type));

  // 4) Classify via the admissibility layer (purpose-relative, replayable).
  // Cast loosely: this function augments the result with `graph` metadata
  // below, a property evaluateAdmissibility's return type doesn't declare.
  const result: any = evaluateAdmissibility(
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
  //     'conflicted'-class finding. The committed side is relying-party pinned
  //     (policy.expected_effect_digest / policy.predicted_effects) or obtained
  //     through opts.resolveApprovedEffect(), which is expected to verify the
  //     referenced approval. It is NEVER taken from the effect-attestation
  //     verifier because that artifact is controlled by the executor/presenter.
  //     Fail closed: a verified effect_attestation with no committed effect to
  //     compare against is 'conflicted' (we cannot show the effect was
  //     approved), never admissible.
  const pinnedEffect = normDigest(policy?.expected_effect_digest);
  const policyPredictionsPresent = Object.hasOwn(policy, 'predicted_effects');
  const suppliedPolicyPredictions = Array.isArray(policy?.predicted_effects)
    ? policy.predicted_effects : null;
  const policyPredictionValidation = suppliedPolicyPredictions
    ? validatePredictedEffects(suppliedPolicyPredictions) : null;
  const pinnedPredicted = policyPredictionValidation?.ok ? suppliedPolicyPredictions : null;
  const policyPredictionsMalformed = policyPredictionsPresent
    && (!suppliedPolicyPredictions || policyPredictionValidation?.ok !== true);
  const outcomeRows: any[] = [];
  for (const f of effectiveFacts) {
    if (f.type !== EFFECT_ATTESTATION_TYPE || !f.verified) continue;
    const eff = f.effect || {};
    const observed = eff.observed_effect_digest;
    let approved: any = null;
    let approvalLinkageFailure: any = null;
    if (typeof opts.resolveApprovedEffect === 'function') {
      if (typeof eff.receipt_id !== 'string' || eff.receipt_id.length === 0) {
        approvalLinkageFailure = {
          failed_bindings: ['receipt_id'], approved_commitments: null,
          detail: 'attestation carries no receipt_id for approved-effect resolution',
        };
      } else {
        try {
          const candidate = opts.resolveApprovedEffect(eff.receipt_id);
          const candidateAction = normDigest(candidate?.action_digest ?? candidate?.action_hash);
          const candidateActionBound = candidateAction === normDigest(graphDoc.action_digest);
          const receiptBound = candidate?.receipt_id === eff.receipt_id;
          const receiptDigestBound = !eff.receipt_digest
            || normDigest(candidate?.receipt_digest) === eff.receipt_digest;
          const consumptionBound = !eff.consumption_nonce
            || candidate?.consumption_nonce === eff.consumption_nonce;
          if (candidate?.valid === true
              && receiptBound && candidateActionBound
              && receiptDigestBound && consumptionBound) {
            approved = candidate;
          } else {
            const failedBindings = [
              ...(candidate?.valid === true ? [] : ['approval_validity']),
              ...(receiptBound ? [] : ['receipt_id']),
              ...(candidateActionBound ? [] : ['action_hash']),
              ...(receiptDigestBound ? [] : ['receipt_digest']),
              ...(consumptionBound ? [] : ['consumption_nonce']),
            ];
            approvalLinkageFailure = {
              failed_bindings: failedBindings,
              approved_commitments: {
                receipt_id: candidate?.receipt_id ?? null,
                receipt_digest: normDigest(candidate?.receipt_digest),
                action_hash: candidateAction,
                consumption_nonce: candidate?.consumption_nonce ?? null,
              },
              detail: `approved payload failed exact ${failedBindings.join('/')} linkage`,
            };
          }
        } catch (e) {
          approvalLinkageFailure = {
            failed_bindings: ['resolver'], approved_commitments: null,
            detail: `approved-effect resolver failed: ${e.message}`,
          };
        }
      }
    }
    if (approvalLinkageFailure) {
      reasons.push(`effect_commitment_missing: effect_attestation "${f.label}" ${approvalLinkageFailure.detail} for receipt "${eff.receipt_id}"`);
      result.verdict = downgradeToConflicted(result.verdict);
      outcomeRows.push({
        attestation: f.label,
        receipt_id: eff.receipt_id,
        source: 'approved_effect_linkage',
        attested_commitments: {
          receipt_id: eff.receipt_id,
          receipt_digest: eff.receipt_digest ? `sha256:${eff.receipt_digest}` : null,
          action_hash: eff.action_hash ? `sha256:${eff.action_hash}` : null,
          consumption_nonce: eff.consumption_nonce ?? null,
          executor_id: eff.executor_id ?? null,
          executor_key_id: eff.executor_key_id ?? null,
        },
        approved_commitments: approvalLinkageFailure.approved_commitments,
        failed_bindings: approvalLinkageFailure.failed_bindings,
        outcome: 'incomparable',
      });
    }
    const committed = pinnedEffect ?? normDigest(approved?.committed_effect_digest) ?? null;
    // 6b-i) PREDICTED EFFECTS (EP-OUTCOME-BINDING-v1). Signed receipt
    //       predictions and relying-party policy predictions are ADDITIVE.
    //       Policy can tighten the bar; it cannot replace or loosen signed
    //       human intent. Neither source is ever read from the executor artifact.
    const resolvedPredicted = Array.isArray(approved?.predicted_effects) ? approved.predicted_effects : null;
    const hasStructuredObservations = Array.isArray(eff.observed_effects);
    if (hasStructuredObservations && !resolvedPredicted) {
      reasons.push(`effect_commitment_missing: effect_attestation "${f.label}" has structured observations but no action-bound signed receipt prediction baseline`);
      result.verdict = downgradeToConflicted(result.verdict);
    }
    const predictionSources = [
      ...(resolvedPredicted ? [{
        source: 'signed_receipt',
        predicted: resolvedPredicted,
        bound_digest: normDigest(approved?.predicted_effects_digest),
      }] : []),
      ...(pinnedPredicted ? [{
        source: 'relying_party_policy',
        predicted: pinnedPredicted,
        bound_digest: normDigest(predictedEffectsDigest(pinnedPredicted)),
      }] : []),
    ];
    if (policyPredictionsMalformed) {
      const evaluation = {
        outcome: 'incomparable',
        results: [],
        reasons: suppliedPolicyPredictions
          // suppliedPolicyPredictions truthy implies policyPredictionValidation was
          // computed by validatePredictedEffects(suppliedPolicyPredictions), which
          // always returns a {ok, reasons} object, never null (see effect-predicates.js).
          ? (policyPredictionValidation as { reasons: string[] }).reasons
            .map((reason: string) => `malformed predicted_effects: ${reason}`)
          : ['relying_party_policy predicted_effects is present but is not an array'],
      };
      outcomeRows.push({
        attestation: f.label,
        receipt_id: eff.receipt_id,
        source: 'relying_party_policy',
        ...evaluation,
      });
      reasons.push(`effect_incomparable: effect_attestation "${f.label}" cannot be compared to relying_party_policy predicted effects (refusal, never a pass): ${evaluation.reasons.join('; ')}`);
      result.verdict = downgradeToConflicted(result.verdict);
    }
    if (predictionSources.length > 0) {
      for (const source of predictionSources) {
        let evaluation;
        if (!source.bound_digest) {
          evaluation = {
            outcome: 'incomparable', results: [],
            reasons: [`${source.source} predicted effects have no bound predicted_effects_digest`],
          };
        } else if (normDigest(predictedEffectsDigest(source.predicted)) !== source.bound_digest) {
          evaluation = {
            outcome: 'incomparable', results: [],
            reasons: [`${source.source} predicted effects do not hash to the bound predicted_effects_digest`],
          };
        } else {
          evaluation = evaluatePredictedEffects(source.predicted, eff.observed_effects);
        }
        outcomeRows.push({
          attestation: f.label,
          receipt_id: eff.receipt_id,
          source: source.source,
          ...evaluation,
        });
        if (evaluation.outcome === 'divergent') {
          reasons.push(`effect_divergence: effect_attestation "${f.label}" observed effects diverge from ${source.source} predicted effects: ${evaluation.reasons.join('; ')}`);
          result.verdict = downgradeToConflicted(result.verdict);
        } else if (evaluation.outcome === 'incomparable') {
          reasons.push(`effect_incomparable: effect_attestation "${f.label}" cannot be compared to ${source.source} predicted effects (refusal, never a pass): ${evaluation.reasons.join('; ')}`);
          result.verdict = downgradeToConflicted(result.verdict);
        }
      }
      // If the attestation ALSO carries the exact digests, they must agree too
      // (the degenerate case never weakens the predicate result).
      if (observed && committed && observed !== committed) {
        reasons.push(`effect_divergence: effect_attestation "${f.label}" observed ${observed} but the approved committed effect is ${committed} ("approved X, executed Y")`);
        result.verdict = downgradeToConflicted(result.verdict);
      }
      if (observed || committed) {
        outcomeRows.push({
          attestation: f.label,
          receipt_id: eff.receipt_id,
          source: 'exact_effect_digest',
          observed_effect_digest: observed ? `sha256:${observed}` : null,
          committed_effect_digest: committed ? `sha256:${committed}` : null,
          outcome: observed && committed
            ? (observed === committed ? 'in_bounds' : 'divergent')
            : 'incomparable',
        });
      }
      continue;
    }
    // Structured observations without an independently sourced prediction are
    // not the legacy exact-digest case. Refuse on the missing approved side;
    // never reinterpret presenter-supplied predictions as that commitment.
    if (Array.isArray(eff.observed_effects) && !committed) {
      continue;
    }
    // 6b-ii) EXACT DIGEST (the pre-existing path; the degenerate {op:"eq"}
    //        case over one digest). Unchanged behavior when no predictions.
    if (!observed) {
      reasons.push(`effect_divergence: effect_attestation "${f.label}" carries no observed_effect_digest`);
      result.verdict = downgradeToConflicted(result.verdict);
      outcomeRows.push({
        attestation: f.label,
        receipt_id: eff.receipt_id,
        source: 'exact_effect_digest',
        observed_effect_digest: null,
        committed_effect_digest: committed ? `sha256:${committed}` : null,
        outcome: 'incomparable',
      });
      continue;
    }
    if (!committed) {
      reasons.push(`effect_commitment_missing: effect_attestation "${f.label}" has an observed effect but no approved committed effect to compare against`);
      result.verdict = downgradeToConflicted(result.verdict);
      outcomeRows.push({
        attestation: f.label,
        receipt_id: eff.receipt_id,
        source: 'exact_effect_digest',
        observed_effect_digest: `sha256:${observed}`,
        committed_effect_digest: null,
        outcome: 'incomparable',
      });
      continue;
    }
    if (observed !== committed) {
      reasons.push(`effect_divergence: effect_attestation "${f.label}" observed ${observed} but the approved committed effect is ${committed} ("approved X, executed Y")`);
      result.verdict = downgradeToConflicted(result.verdict);
    }
    outcomeRows.push({
      attestation: f.label,
      receipt_id: eff.receipt_id,
      source: 'exact_effect_digest',
      observed_effect_digest: `sha256:${observed}`,
      committed_effect_digest: `sha256:${committed}`,
      outcome: observed === committed ? 'in_bounds' : 'divergent',
    });
  }

  result.reasons = [...reasons, ...result.reasons];
  result.outcome_binding = {
    '@version': 'EP-OUTCOME-BINDING-v1',
    outcome: outcomeRows.some((row) => row.outcome === 'divergent') ? 'divergent'
      : outcomeRows.some((row) => row.outcome === 'incomparable') ? 'incomparable'
        : 'in_bounds',
    evaluations: outcomeRows,
  };
  result.graph = { graph_digest: g_digest, nodes: nodes.length, edges: edges.length, edge_rows: edgeRows };
  // Graph replay binds the complete base decision, graph commitments, outcome
  // evaluation, and final classified verdict in one inspectable record.
  result.replay = {
    '@version': 'EP-AEG-REPLAY-v1',
    base: result.replay,
    graph: g_digest,
    verdict: result.verdict,
    reasons: result.reasons,
    outcome_binding: result.outcome_binding,
  };
  result.replay_digest = `sha256:${sha256hex(canon(result.replay))}`;
  return result;
}

/**
 * EP-RELIANCE-RESULT-v1 — the verdict as a signed, portable artifact.
 * Accountability, not authority: verify the signature to know WHO decided;
 * recompute the replay_digest to know the decision was honest.
 */
export function signRelianceResult(
  result: any,
  policy: any,
  privateKey: KeyLike,
  opts: { evaluated_at?: string | null } = {},
): { payload: Record<string, any>; sig: string; verifier_key: string } {
  opts = opts && typeof opts === 'object' && !Array.isArray(opts) ? opts : {};
  const resultDigest = `sha256:${sha256hex(canon(result))}`;
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
    outcome_binding: result.outcome_binding ?? null,
    result_digest: resultDigest,
    result,
    evaluated_at: opts.evaluated_at ?? null,
  };
  const sig = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey);
  // crypto.createPublicKey() accepts a private KeyObject at runtime (it derives
  // the public key from it) even though @types/node's overloads don't cover
  // this case; the cast reflects that gap, not a behavior change (see
  // lib/authority/proof.ts / lib/commit.ts for the same established pattern).
  const pub = crypto.createPublicKey(privateKey as any).export({ type: 'spki', format: 'der' });
  return { payload, sig: sig.toString('base64url'), verifier_key: pub.toString('base64url') };
}

/**
 * Verified vs accepted, as everywhere in EP: `verified` = the signature holds
 * over the canonical payload; `accepted` additionally requires the verifier
 * key to be PINNED by the caller (out-of-band trust in who decided).
 */
export function verifyRelianceResult(
  doc: any,
  pinnedVerifierKeys: string[] = [],
): { verified: boolean; accepted: boolean; checks: Record<string, boolean> } {
  const checks: Record<string, boolean> = {
    structure: false, result_digest: false, result_consistent: false,
    signature: false, issuer_pinned: false,
  };
  if (!doc?.payload || doc.payload['@version'] !== RELIANCE_RESULT_VERSION || typeof doc.sig !== 'string' || typeof doc.verifier_key !== 'string') {
    return { verified: false, accepted: false, checks };
  }
  checks.structure = true;
  try {
    checks.result_digest = typeof doc.payload.result_digest === 'string'
      && doc.payload.result_digest === `sha256:${sha256hex(canon(doc.payload.result))}`;
    checks.result_consistent = checks.result_digest
      && doc.payload.result?.verdict === doc.payload.verdict
      && doc.payload.result?.action_digest === doc.payload.action_digest
      && doc.payload.result?.replay_digest === doc.payload.replay_digest;
  } catch {
    checks.result_digest = false;
    checks.result_consistent = false;
  }
  let key;
  try { key = crypto.createPublicKey({ key: Buffer.from(doc.verifier_key, 'base64url'), type: 'spki', format: 'der' }); }
  catch { return { verified: false, accepted: false, checks }; }
  try {
    checks.signature = crypto.verify(null, Buffer.from(canon(doc.payload), 'utf8'), key, Buffer.from(doc.sig, 'base64url'));
  } catch { checks.signature = false; }
  checks.issuer_pinned = pinnedVerifierKeys.includes(doc.verifier_key);
  const verified = checks.structure && checks.result_digest
    && checks.result_consistent && checks.signature;
  return { verified, accepted: verified && checks.issuer_pinned, checks };
}
