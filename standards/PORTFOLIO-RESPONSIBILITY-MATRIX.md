# Active `draft-schrock-*` responsibility matrix

Updated: 2026-08-16

## Decision and method

This matrix covers all 20 active `draft-schrock-*` series in
`STATUS.json.active_datatracker`. It is extension-agnostic: every current XML
source in `standards/posted/` was read for its abstract, top-level sections,
explicit claim boundary, inputs, and outputs. The three active coauthored
records in `STATUS.json` remain tracked separately and are not candidates for
unilateral consolidation here.

The dependency column uses the computed 2026-08-15 citation ledger. Counts are
independent external drafts under the current series name unless otherwise
stated; an informative reference is evidence of attention, not adoption or
endorsement. `0` is not a reason to delete a series when another active series
normatively or architecturally depends on its distinct function.

The result is **no consolidation now**. Two items remain conditional:

- Presentation Binding stays held because Authorization Receipts already
  carries its receipt-specific profile. A new revision earns its existence only
  through genuine cross-host registration templates and host-independent use.
- Reliance Agreement remains active while its overlap with the non-IETF
  Reliance Program artifacts is evaluated. It must not be refreshed merely to
  preserve a document count.

### Presentation Binding IANA gate

The July-August IANA correspondence does not supply a shortcut for Presentation
Binding. IANA closed the direct AE-CHALLENGE media-type request pending a real
publication path: either a document approaching RFC publication or another
applicable registration procedure. AGTP's API Tier A/B/C endpoint
classification is an operator-dispatch taxonomy, not an IANA classification.
AGTP's completed vendor-tree media types and provisional URI scheme are valid
allocations, but they do not create or review a cross-host render-profile or
display-attestation registry.

Accordingly, AGTP does not satisfy the hold gate. A future Presentation Binding
revision must carry complete, host-independent registration templates that
name the registry, fields, registration policy, change control, collision and
supersession rules, and initial entries, plus an external host that needs those
identifiers. A media-type or URI registration obtained only to add a logo is
not evidence that the presentation-binding semantics were reviewed or adopted.

## Complete 20-series matrix

| Active series | Sole responsibility and output | Inputs it consumes | Explicit boundary | External dependency signal | Overlap and disposition |
| --- | --- | --- | --- | --- | --- |
| `ae-challenge-07` | Describes, for one exact refused action, which evidence remains necessary and how a corrected presentation may be retried. Outputs a bounded, transport-neutral challenge; HTTP is one carrier. | Relying-party requirement, action binding, freshness/status needs, acceptable presentation profiles, refusal-path owner state. | Authorizes nothing, transfers no admission ownership, promises no execution, and does not solve conserved admission across gateways. | 0 current-name independent references; used by the coauthored DMSC analysis. | Distinct refusal/acquisition surface. Keep separate from AEB admission and OAuth-native transaction authorization. |
| `action-evidence-boundary-04` | Owns executor-side ordering: native verification, exact-action match, evidence satisfaction, local authorization, durable custody, invocation, outcome classification, and reconciliation. Outputs admission/refusal and lifecycle records. | Boundary-observed action, native verifier results, CAID mapping, AEC result, local policy, durable state, provider evidence. | Defines no token, receipt, policy language, universal taxonomy, provider truth, or complete-mediation claim. | 6 drafts / 4 parties. | Runtime waist. Keep independent; AEB consumes other formats and must not absorb them. AEB-04 adds only a generic field-origin assertion input. |
| `action-remedy-receipts-00` | Records a dispute decision and a separately authorized compensating action without rewriting the original effect. | Original action/effect record, dispute evidence, remedy authority, fresh remedy CAID and outcome. | Revocation or dispute does not undo an effect or authorize a remedy; unresolved outcomes stay fenced. | 0. | Distinct aftermath object. Keep separate from revocation and outcome observation because a remedy is a new consequential action. |
| `agent-qualification-statements-00` | Binds a candidate, evaluation campaign, policy, assignment, and status. Outputs separate observation and qualification claims for runtime use. | Candidate digest, evaluator suite and environment, results, qualification policy, assignment, freshness/status. | Qualification is not authorization, runtime identity, current safety, or permission to act. | 0. | Distinct pre-admission evidence role. Keep separate from AEC/AEB, which consume but do not create qualification evidence. |
| `canonical-action-identifier-02` | Owns typed material-action identity and loss-aware, profile-pinned cross-format mapping. Outputs CAID plus `EQUIVALENT_UNDER_PROFILE`, `NOT_EQUIVALENT`, or `INDETERMINATE`. | Independently verified native representations, action-type definitions, canonicalization suite, exact mapping profile. | Carries no identity, trust, authority, authorization, execution, safety, or legal-reliance semantics. | 2 drafts / 2 parties. | Join semantics are the one layer EMILIA must defend. Keep independent from every artifact verifier and policy engine. |
| `emilia-eye-00` | Produces scope-bound posture advisories that can recommend logging, step-up, signoff, or escalation. | Observation, scope commitment, advisory signer, lifecycle/supersession state. | Advisory can only tighten; it is never the sole gate and never authorizes. Signing is specified but not yet implemented in the reference path. | 0. | Distinct advisory plane. Keep only under its tighten-only invariant; never merge into authority or admission. |
| `ep-architecture-02` | Defines the system map, non-collapsing vocabulary, layer boundaries, and applicability limits. | Component contracts and deployment assumptions. | Defines no universal token, policy language, execution engine, settlement network, or consensus system. | 0 direct; architecture ordinarily earns informative rather than normative use. | Navigation document, not a wire format. Keep; do not use it as a substitute for mechanism specifications. |
| `ep-authority-introduction-03` | Introduces and rotates evidence-issuing keys and evaluates scoped authority at a pinned registry snapshot. Outputs Authority Documents, Scoped Authority Proofs, and an authority evaluation. | Pinned organization trust root, key sequence, subject role/scope/limits, registry snapshot, validity and revocation state. | A signature, domain control, log inclusion, or self-presented key is not authority; source precision cannot exceed the underlying source. | 4 drafts / 4 parties. | Distinct trust-root and scoped-authority leg. Keep separate from identity, receipts, and action authorization. |
| `ep-authorization-evidence-chain-05` | Composes heterogeneous, natively verified and action-matched evidence against a relying-party requirement. Outputs `SATISFIED` or `UNSATISFIED` plus replayable evaluation. | Native verifier outputs, CAID matches, evidence roles, requirement expression, freshness/status pins. | Satisfaction is not authorization, policy for the protected application, execution, or outcome. Defines no component receipt. | 0 under current name; 4 drafts / 4 parties still pin the superseded Action Evidence Graph name. | Living successor to AEG. Keep as the composition waist and publish a visible predecessor pointer rather than creating a second graph contract. |
| `ep-authorization-receipts-12` | Defines action-bound human approval evidence, pre-execution Authorization Bundles, signoffs, and terminal Trust Receipts. | Canonical action, policy, audience, approver directory/key proof, UV-gated signatures, log material, executor consumption record. | Evidence is not authorization; offline verification does not establish current revocation, comprehension, legality, safety, global non-replay, or execution. | 8 drafts / 5 parties. | Base human-approval profile. Keep independent; other human mechanisms may coexist. Receipts-12 adds historical-integrity limits without changing this ownership. |
| `ep-bounded-capability-receipts-04` | Grants finite multi-action authority and owns durable reserve/enter/commit accounting, parent-funded delegation, and indeterminate-effect charging within one atomic domain. | Issuance authorization, closed scope, budget, holder proof, expiry, parent capability, authoritative store. | Not human approval, global/offline double-spend prevention, cross-domain conservation, safety, legality, or successful execution. | 0 independent current-name references; 1 coauthored dependency. | Distinct budget instrument. Keep separate from one-action receipts and BEP program topology. |
| `ep-bounded-execution-program-00` | Defines a finite signed DAG of consequential action occurrences with reachability, occurrence, concurrency, and aggregate attempt budgets enforced at admission. | Exact actions or pinned mappings, per-node trust programs, dependency outcomes, program signature/status, linearizable admission store. | Does not prove intent comprehension, plan safety/lawfulness, provider truth, or complete mediation. | 0. | Distinct program-level envelope. Keep separate from BCR: topology/reachability versus fungible budget and delegation. |
| `ep-evidence-record-01` | Preserves long-lived verifiability through algorithm-renewal chains, optional witness cosignatures, and independently pinned time attestation. | Original artifact, renewal algorithms/keys, timestamps, checkpoints and witnesses. | Does not improve original claim truth, current status, or independent-implementation status; JavaScript-only companion profiles remain scoped. | 0. | Distinct preservation layer. Keep separate from live status, revocation, and acceptance semantics. |
| `ep-outcome-binding-00` | Joins signed predicted effects to source-routed executor, system-of-record, and independent observations. Outputs availability plus `in_bounds`, `divergent`, `incomparable`, or indeterminate lifecycle state. | Authorization/action/CAID/operation bindings, predicted predicates, relying-party source policy, authenticated observations. | Does not prove physical truth, sensor correctness, legal finality, or that an executor claim is independent. | 0. | Distinct aftermath comparison. Keep separate from admission, remedy, and evidence preservation. |
| `ep-presentation-binding-00` | Defines deterministic rendering and display-attestation concepts for checking what a signing surface claims it displayed. | Canonical action, renderer/template identifier, display bytes/digest, signing-client attestation. | Cannot prove pixels, comprehension, or an uncompromised display path. | 0. | **Hold.** Receipt-specific semantics already exist in Receipts. Revive only with real IANA templates and a cross-host need; otherwise do not file a wording-only revision. |
| `ep-quorum-03` | Evaluates distinct-human M-of-N and ordered approval trails over one exact action. Outputs a fail-closed quorum result. | Base signoffs, shared action and authorization instance, role set, threshold/order/window, distinct-human and separation rules. | Does not prove collusion resistance, arbitrary human identity truth, execution, or authority beyond each native signoff. | 0 direct current-name references; used through Receipts profiles. | Distinct ceremony composition. Keep separate from the base receipt and from general AEC evidence roles. |
| `ep-revocation-statement-01` | Carries a pinned revoker's terminal negative statement about one exact logical target and action commitment. | Target identifier/action binding, revoker key, revocation instant, current decision time, aggregation policy. | Does not prove universal delivery or current non-revocation; later revocation cannot relabel an effect already admitted. | 0. | Distinct negative evidence. Keep separate from current online status and remedy actions. |
| `ep-reliance-agreement-00` | Binds parties and machine-readable terms to an exact evidence-condition digest and records a per-action reliance result. | Party signatures, agreement scope/time, evidence-condition digest, action and reliance result. | Does not authorize, re-evaluate evidence, create legal enforceability, issue insurance, allocate fault, prove solvency, reserve funds, or compel payment. | 0. | Conditional keep. Compare with the non-IETF Reliance Program artifacts before its next revision; absorb only if the signed terms/event object has truly been superseded. |
| `human-authorization-binding-00` | Defines host-agnostic by-reference or embedded binding of named-human authorization evidence into adjacent records. | Host record, canonical authorization artifact or compact claim, digest, action agreement, verifier acceptance rules. | Defines no new authorization evidence and does not turn a host slot into proof without native verification and relying-party acceptance. | 4 drafts / 4 parties. | Cross-host adapter contract. Keep separate from Receipts because hosts may bind non-EP authorization artifacts. |
| `model-to-matter-04` | Profiles executor-owned pre-execution evidence custody and post-execution observation for model-directed physical actions. | Model, safety, institutional, domain, screening, human, physical-state, action, admission, and outcome evidence. | Does not perform screening, determine scientific safety, certify facilities, establish physical truth, or upgrade one source claim into independent observation. | 0. | Flagship application profile, not a replacement for its component specifications. Keep while it provides a concrete physical-boundary composition. |

## Consolidation gates

No series may be merged, renamed, or allowed to lapse on apparent thematic
overlap alone. A future consolidation proposal must show all of the following:

1. the two current sources produce the same protocol result for the same
   relying party at the same lifecycle point;
2. no external or coauthored document depends on the donor name or its distinct
   behavior;
3. the receiving draft can preserve the donor's normative boundary without
   creating version skew or an overloaded artifact;
4. an explicit replacement pointer preserves stale citations; and
5. the revision has independent substantive reason to exist beyond editorial
   consolidation.

Under those gates, neither shared vocabulary nor a shared implementation is
duplication. The immediate constraints remain external reproduction and paid
buyer conversations, not reducing the document count.
