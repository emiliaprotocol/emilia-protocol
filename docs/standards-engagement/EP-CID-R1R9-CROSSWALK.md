<!-- SPDX-License-Identifier: Apache-2.0 -->
# EMILIA Protocol — C-ID to R1-R9 crosswalk

Offered to the WIMSE requirements-mapping discussion so the registry can pin to
stable, agreed identifiers rather than two numbering schemes drifting apart.

Three authorities, three lanes, kept distinct here on purpose:

- **C-ID criterion text** is authoritative from
  [`draft-bu-agentproto-security-principal-binding-02`](https://datatracker.ietf.org/doc/html/draft-bu-agentproto-security-principal-binding-02)
  Section 9 (Songbo Du holds the pen; the quoted question for each claim is
  verbatim from that section, not an EP paraphrase).
- **R1-R9 anchors** are from
  [`draft-reece-wimse-cross-org-delegation-00`](https://datatracker.ietf.org/doc/draft-reece-wimse-cross-org-delegation/)
  (Morgan Reece). R2 is under active revision on the list (the acquisition
  versus binding split, plus a first-contact-root security consideration); this
  crosswalk cites R2 as written in -00 and will update when the revised
  requirements draft posts, rather than racing it.
- **EP rows** are EP's own artifact-layer mapping, contributed for the human
  authorization slice only. EP is an inheritance target, not an agent
  communication protocol.

Honesty carried through, per the registry's own discipline: the JavaScript,
Python, and Go reference verifiers live in one repository and are a
cross-language consistency check, **not** independent implementations. An
independent clean-room reimplementation (COSA) is underway; until it agrees on
the same vectors, EP labels its vector evidence **local-harness**, not interop.
No EP Internet-Draft is IETF-adopted or endorsed. The four revisions the
registry will reference are receipts-06, quorum-02, evidence-record-01, and
evidence-chain-02.

Repo root for evidence references:
`https://github.com/emiliaprotocol/emilia-protocol/blob/main/`

## Crosswalk

| C-ID (draft-bu-02 §9) | Authoritative criterion (verbatim) | R1-R9 anchor (draft-reece-00) | EP carrier | Tests / vectors (`node conformance/run.mjs`) | Gradient position |
|---|---|---|---|---|---|
| **C-002** Human or organizational authority | "Who authorized the task, policy, role, or delegation?" | **R5** Principal binding and invariance (primary); **R1** Recursive attenuation for the delegation chain | EP-RECEIPT-v1 / EP-QUORUM: Ed25519 over RFC 8785/JCS canonical action bytes; M-of-N distinct principals, order enforced when declared | `receipts.v1.json` (13), `quorum.v1.json` (11), `signoffs.v1.json` (9) | Verified at general infrastructure (any verifier, offline, first-contact-safe); accepted only against a pinned issuer key; consequence tier is explicit: `software` -> Class-A device (WebAuthn UV) -> M-of-N human quorum |
| **C-005** Action evidence | "What action was requested, attempted, completed, blocked, or failed?" | **R8** Tamper-evident, composable audit (primary); **R6** Dual-axis authorization for composition | EP-AEG-v1 action evidence graph + tamper-evident gate evidence log + signed EP-RELIANCE-RESULT-v1; `ceremony_evidence` and `effect_attestation` nodes | `evidence-record.v1.json` (5), `provenance.exec.v1.json` (6); `tests/evidence-graph.test.js`, `tests/admissibility-profiles.test.js` | The sufficiency bar is a relying-party-authored, content-addressed EP-ADMISSIBILITY-PROFILE (`profile_hash`), graded by the relying party per consequence; EMILIA never authors the bar and is never in the trust path |
| **C-007** Evidence provenance | "What evidence, signature, receipt, attestation, log entry, or record supports an action or decision?" | **R8** Tamper-evident, composable audit | EP provenance chains, evidence records (RFC 4998-style renewal), optional SCITT/COSE registration, optional EP-WITNESS-v1 cosignatures | `provenance.exec.v1.json` (6), `evidence-record.v1.json` (5), `witness.v1.json` (6), `timestamp-proof.v1.json` (13) | Native signature rooted in general infrastructure; transparency inclusion is only as strong as the log operator's checkpoint, raised toward "established" by independent witness cosignatures; each leg reports a separate named result, never one collapsed boolean |
| **C-008** Freshness or revocation | "Is the authority, delegation, instance state, tool binding, or session state still current?" | **R7** Authentic, bounded-staleness revocation | Validity windows; portable offline revocation statement; signed time-attestation incl. RFC-3161 timestamp proof against a pinned TSA key | `revocation.exec.v1.json` (6), `time-attestation.v1.json` (6), `timestamp-proof.v1.json` (13) | Revocation authenticity is offline/general-infra; the staleness bound is a relying-party policy input graded per consequence; distribution channel is the relying party's and stale material fails safe, never open |
| **C-011** Accepted result | "What normalized result may the application consume after successful verification, and what does that result not authorize?" | **R2** Cross-organizational verification (the verified-versus-accepted discipline the acceptance level names) | Constrained verifier outputs: `{valid, checks{version,signature,anchor}}`; `{verified, accepted, checks}`; signed EP-RELIANCE-RESULT-v1; pinned EP-ADMISSIBILITY-PROFILE verdict (closed 5-state) | `boundary.v1.json` case `raw_claim_pass_through` (3 vectors, JS/Py/Go agree); `examples/binding/human-authorization-binding-vector.mjs` (B3 verified-but-never-accepted) | This claim IS the gradient's accept side made explicit: VERIFIED (general infrastructure) and ACCEPTED (pinned root) are computed and reported separately, never collapsed; the result names its own non-claims |
| **C-012** Authorization and attribution boundary | "Is the row claiming pre-execution authority, delegated scope, post-execution attribution, execution evidence, audit enforcement, or relying-party acceptance, and which of those does it not claim?" | **R5** (pre-execution WHO leg) with **R8** (post-execution attribution leg); the boundary between them is the EP-contributed structure | Pre-execution: EP-RECEIPT-v1 / EP-QUORUM. Post-execution: EP-AEG-v1 + gate log + EP-EXECUTION-INTEGRITY-v1 (executor identified, never trusted); `effect_attestation` observed-effect leg | `boundary.v1.json` case `attribution_substituted_for_authorization` (JS/Py/Go agree); `examples/scitt/capsule-seam-vector.mjs` reject cases | The two legs sit at different gradient positions and stay there: pre-execution authority carries C-002's position; post-execution attribution roots only in the executor's own pinned key and grants no authority; the shared action digest joins the legs without making them interchangeable |

## The gradient position as a declared field

Karthik's editor-seat observation is right: the acquisition-versus-binding split
and the consequence gradient are the shape all three constructions share, so the
gradient position is worth carrying as **structure a row states and an artifact
declares**, not as prose a reader has to reconstruct.

EP already carries this natively, which is why the column above is populated
rather than promised. Every EP acceptance decision declares two things a
verifier reads directly from the artifact and the relying party's pinned policy:

1. **Where the root sits.** Verification is unconditional and general-infrastructure
   (Ed25519 over JCS, any verifier, offline, first-contact-safe). Acceptance
   requires a pre-pinned root (issuer key, approver directory, or admissibility
   profile hash). The verifier returns `verified` and `accepted` as separate
   fields, so the gradient position between first encounter and established
   relationship is never hidden inside one boolean.
2. **The consequence class it operates at.** `required_assurance` is an explicit
   tier on the action (`software` -> Class-A device with WebAuthn user
   verification -> M-of-N human quorum), and for evidence sufficiency the
   relying party pins a named EP-ADMISSIBILITY-PROFILE whose bar rises with
   consequence. The more consequential the action, the stronger the pinned root
   EP requires, which is exactly the gradient Morgan's proposed R2 security
   consideration describes.

If the registry adopts a `gradient_position` field per artifact, EP can populate
it today from these two existing fields, and the EP conformance suite can emit it
per vector. Proposed minimal shape, offered for the list:
`{ root: "general_infrastructure" | "pinned_root", consequence_tier:
"software" | "class_a" | "quorum", sufficiency_bar: "<profile_hash | none>" }`.

## Reconciliation note

The C-IDs are Songbo's registry (draft-bu). This crosswalk pins each row's
criterion to his -02 Section 9 text so the reconciliation is against a
definition, not an EP description, and so the registry inherits stable
identifiers. The C-ID-to-R mapping in column 3 is EP's proposed correspondence,
offered for confirmation on the list with the pen-holder present rather than
settled unilaterally. The EP artifact rows, tests, and gradient positions are
EP's to maintain and correct through the list.

---

*Maintained at `docs/standards-engagement/EP-CID-R1R9-CROSSWALK.md`. Companion to
`EP-CLAIM-MATRIX-MAPPING.md` (the full per-C-ID EP mapping) and
`CROSS-ORG-DELEGATION-R1-R9-MAPPING.md` (EP graded against R1-R9). PR-ready for
the requirement registry once it is stood up.*
