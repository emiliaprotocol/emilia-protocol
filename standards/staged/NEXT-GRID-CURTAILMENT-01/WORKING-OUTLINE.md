# GRACE-01 working outline

Status: working agreement for the next revision. This file is not an Internet-Draft and does not change the checksum-pinned `-00` publication packet.

## Purpose of the revision

`-01` should make the consequence boundary implementable in operational-technology deployments without moving identity binding into GRACE or implying that evidence proves complete mediation.

The revision closes four gaps found during the shared EMILIA and TrueAlter work:

1. bind the approved curtailment objective to a pinned actuation plan, then bind each native command at the first conduit;
2. use one durable admission domain across redundant paths, handoffs, and restarts;
3. represent partial execution and reconcile each device from command-channel evidence plus independent readback or telemetry; and
4. keep safety trips, protective relays, emergency shutdowns, and interlocks outside the Gate.

## Scope and layer boundaries

- GRACE consumes a verified result from the identity layer and states what properties it requires from that result.
- Credential-to-person or credential-to-device binding remains in `draft-morrison-ot-command-authority`; GRACE does not redefine it.
- Without the required external identity result, GRACE may identify an enrolled credential but must not claim a natural person.
- GRACE binds authorization, admission, command projection, dispatch evidence, and observed effects. It does not prove that every physical effect passed through the Gate.
- Transparency inclusion, where used, proves logging under the log service policy. It does not prove identity, physical truth, or complete mediation.
- Safety functions remain able to act when GRACE, identity services, revocation services, networks, and logs are unavailable.

## Proposed editors and section ownership

The names below record the division accepted in email. Final RFCXML metadata still requires each new author to confirm preferred name, organization, country, and email.

| Area | Lead | Review |
| --- | --- | --- |
| Overall integration, authorization, evidence, and document editing | Iman Schrock and Justin Kintzele | All authors |
| OT topology, native command semantics, and safety boundary | Blake Morrison | Drew and Iman |
| Degraded communications, handoffs, restarts, conflicting evidence, and control-room needs | Drew | Blake and Iman |
| Cross-layer identity requirements | Joint | Keep the binding definition in `ot-command-authority` |

Authorship is substantive: each lead owns the requirements, failure cases, and conformance text for the named sections, not merely editorial review.

## Proposed section structure

### 1. Introduction and claim boundary

- Retain the current problem statement and requirements language.
- Add the objective-to-plan-to-command chain and the per-device reconciliation problem.
- State plainly that GRACE is a consequence-control profile, not an identity system, safety system, or proof of complete mediation.

### 2. Terminology and roles

Add precise definitions for:

- actuation plan;
- native command projection;
- first conduit;
- durable admission domain;
- device attempt;
- provider outcome;
- observed-effect relation;
- independent readback; and
- safety function.

Keep provider outcome and observed-effect relation as separate axes.

### 3. Trust, deployment inputs, and layer boundaries

- Define the external identity result GRACE requires and how its freshness is evaluated.
- Reference `draft-morrison-ot-command-authority` for the credential-binding mechanism.
- Require an effect-path inventory covering every path capable of reaching the controlled devices.
- Require one configured durable admission-domain identifier for all redundant paths within the protected action.
- Preserve the limit that receipts and logs cannot establish absence of bypass paths.

### 4. Curtailment action

- Retain the canonical curtailment objective.
- Make every material field used to construct the actuation plan explicit.
- Bind the action identifier to the exact approved objective, not to a human-readable summary.

### 5. Participation envelope and containment

- Preserve the current containment rules.
- Add the participating device set, allowed native command families, plan validity interval, and permitted conduits.
- Refuse a command for a device, conduit, or command family outside the envelope.

### 6. Human authorization

- State exactly which identity-layer result and freshness policy the relying party requires.
- Bind authorization to the exact curtailment action and pinned actuation-plan digest.
- Do not infer natural-person identity from an enrolled device credential alone.

### 7. Actuation plan and native command binding

Lead: Blake.

- Derive a deterministic actuation plan from the approved objective and participation envelope.
- Give the plan a digest and bind it into admission.
- Bind each plan step to the exact native command bytes and security-relevant transport context at the first conduit.
- Specify material Modbus and DNP3 fields and refusal on their mutation.
- Keep encoding, projection, and transport acceptance distinct from authority to dispatch.

### 8. OT topology and durable admission domain

Lead: Blake. Drew reviews handoff and restart behavior.

- Define primary and redundant ingress paths, the Gate, durable admission store, executor, command conduit, devices, and reconciliation path.
- Require all ingress paths to reserve, enter, and terminalize through one admission domain.
- Fence executor ownership during handoff and restart.
- Distinguish refusal before provider entry from uncertainty after entry may have occurred.
- Never mint fresh authority because a worker, route, or executor instance changed.

### 9. Safety boundary

Lead: Blake.

- Safety trips, protective relays, emergency shutdowns, and interlocks must not depend on GRACE admission.
- GRACE must not delay, suppress, or consume authority needed by an independent safety function.
- A safety action may be observed and recorded after the fact without becoming Gate-authorized.
- Conformance must include operation with the Gate and network unavailable.

### 10. Per-device dispatch records

Lead: Blake for command semantics; Drew reviews degraded-response semantics.

For every device attempt, record at least:

- operation, admission, plan-step, device, conduit, and attempt identifiers;
- exact native-command digest and security-relevant context;
- admission and provider-entry timestamps;
- command-channel acknowledgment state;
- provider outcome and evidence digest; and
- observed-effect relation, evidence digest, and observation time.

One aggregate success value must not hide partial execution.

### 11. Partial execution, degraded communications, and reconciliation

Lead: Drew.

- Define a per-device state matrix for not entered, invoking, committed, proven not committed, and indeterminate outcomes.
- Combine command-channel evidence with independently authenticated readback or telemetry.
- Treat missing or conflicting evidence as indeterminate.
- Forbid blind retry after possible provider entry.
- Define restart and handoff behavior while any device remains unresolved.
- Define the minimum control-room view needed to reconcile or escalate an event.

### 12. Outcome binding

- Derive the aggregate outcome from the complete per-device matrix.
- Preserve disagreement between provider outcome and observed effect rather than collapsing it into success or failure.
- Bind terminal results to the original action, plan, admission, and device attempts.

### 13. Action State and optional transparency binding

Lead: Iman and Justin.

- Register a pre-dispatch audit statement before provider entry where deployment policy requires it.
- Emit a correlated Action State after reconciliation.
- Allow optional SCITT inclusion evidence while preserving the claim boundary.

### 14. Single-use settlement admission

- Preserve one-time consumption.
- Apply duplicate suppression across redundant routes and replacement workers through the durable admission domain.
- Return the prior terminal state, or an indeterminate state requiring reconciliation, without redispatch.

### 15. Proof-of-curtailment bundle

- Include the approved action, plan, native-command projections, admission records, per-device attempts, provider evidence, readback evidence, and aggregate outcome.
- Keep unavailable evidence explicit.

### 16. Artifact signature profiles

- Preserve role-specific keys and relying-party trust configuration.
- Do not treat a self-carried key as organization-level attribution.

### 17. Privacy considerations

- Minimize disclosure of device topology and operational telemetry.
- Support selective release of per-device evidence without weakening the aggregate claim.

### 18. Security considerations

Add threats and required responses for:

- split admission domains;
- bypass paths;
- objective, plan, and native-command substitution;
- redundant-path and cross-worker replay;
- crash or restart after possible dispatch;
- partial actuation;
- lost acknowledgments;
- stale, missing, or conflicting readback;
- executor ownership races; and
- accidental capture of independent safety paths.

### 19. Implementation and conformance

The `-01` packet should include executable cases for:

1. exact objective, plan, and native-command binding;
2. native-command mutation refusal;
3. concurrent duplicate arrival through two ingress paths;
4. replacement worker replaying the same operation;
5. restart before provider entry;
6. lost response after provider entry;
7. partial multi-device execution;
8. conflicting command acknowledgment and readback;
9. authenticated reconciliation without redispatch; and
10. safety-interlock independence while the Gate is unavailable.

The worker-to-Gate and FC10 lost-response fixtures should be replaced by one joined topology so duplicate and lost-response cases share the same operation, admission domain, and executor history.

### 20. IANA considerations

Keep statement and fixture identifiers profile-local unless the coauthors deliberately define stable interoperability semantics and request registration.

## Existing material to reuse

- `docs/standards-engagement/OT-COMMAND-TRANSPORT-BINDING-OUTLINE.md`
- `docs/standards-engagement/EP-CAE-COMMAND-AUTHORITY-MAPPING.md`
- `examples/ot-command-binding-v1/vectors.v1.json`
- `examples/ot-command-binding-v1/vectors.test.mjs`
- `conformance/vectors/grace-mobile-grid.v1.json`
- `PIPs/PIP-014-grid-curtailment-profile.md`

## Immediate decisions

1. Blake and Drew confirm their preferred RFCXML author metadata.
2. Blake checks Sections 7 through 10 for OT fidelity and identifies any required device/protocol-specific split.
3. Drew checks Sections 8, 10, and 11 against degraded operations and control-room practice.
4. Iman and Justin turn the agreed outline into the first `-01` RFCXML candidate without modifying `-00`.
5. The four authors review the joined conformance topology before its fixture values are frozen.
