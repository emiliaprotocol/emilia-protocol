# Authorization Evidence Chains: Composing Heterogeneous Agent-Authorization Receipts (EP-AEC)
## draft-schrock-ep-authorization-evidence-chain-01

```
Network Working Group                                         I. Schrock
Internet-Draft                                     EMILIA Protocol, Inc.
Intended status: Informational                               6 July 2026
Expires: 7 January 2027
```

### Abstract

A growing family of Internet-Drafts defines signed "receipts" about an AI
agent's action: delegation receipts that attest an agent was authorized to act
for a principal, policy/permit receipts that attest a policy allowed an external
effect, decision and compliance receipts, route authorizations, and
human-authorization receipts that attest a named, accountable human approved a
specific action. The mature efforts independently converged on a common
substrate: bind the action with a canonical digest (JSON Canonicalization Scheme,
[RFC8785]) and sign it. No specification, however, defines how a relying party
verifies that, for ONE action, the several heterogeneous receipts it has been
handed (a) all bind the SAME canonical action and (b) each verify under their own
rules — yielding a single, offline, fail-closed ALLOW or DENY. This document
defines the Authorization Evidence Chain (EP-AEC): a thin, transport-agnostic
composition object and an offline verification algorithm that references existing
receipts, checks that every component binds one canonical action digest,
dispatches each component to a verifier for its type, and evaluates a fail-closed
requirement expression. EP-AEC introduces no new receipt type and replaces none;
it is the verifier-side glue that lets independently specified receipts compose
into one accountability decision. This revision additionally profiles two
optional component record types for that composition: the effect attestation, a
post-execution record in which the executor signs the receipt identifier
together with a digest of the observed effect, and ceremony evidence, a signed
record of signing-ceremony telemetry (the challenge issued, viewed, and approved
instants and the approver identity) that enables review-latency policies.

### Status of This Memo

This Internet-Draft is submitted in full conformance with the provisions of
BCP 78 and BCP 79. Internet-Drafts are working documents of the IETF. This
document is an individual submission and has no formal standing in the IETF
standards process.

---

## 1. Introduction

As autonomous and semi-autonomous agents begin to take irreversible external
actions — moving funds, changing records, releasing data, invoking privileged
APIs — relying parties increasingly demand a verifiable artifact answering
"was this exact action authorized, and by whom?" The IETF community has
responded with a cluster of receipt formats, each answering one facet:

* **Identity** — who or what the agent is.
* **Delegation** — that the agent was authorized to act for a principal
  (e.g. [draft-nelson-agent-delegation-receipts], [draft-mishra-oauth-agent-grants]).
* **Policy / permit** — that policy permitted the effect before commit
  (e.g. [draft-lee-orprg-permit-receipts],
  [draft-nivalto-agentroa-route-authorization]).
* **Decision / compliance** — that a decision or compliance check occurred
  (e.g. [draft-farley-acta-signed-receipts],
  [draft-marques-asqav-compliance-receipts]).
* **Human authorization** — that a named, accountable human, or a quorum of
  distinct humans, approved the exact action
  ([draft-schrock-ep-authorization-receipts], [draft-schrock-ep-quorum]).
* **Transparency** — that a statement was registered in an append-only log
  ([I-D.ietf-scitt-architecture]).

These are complementary layers, not competitors: a single high-risk action may
warrant a delegation receipt AND a policy permit AND a human authorization. Yet
each effort defines only its own receipt. The relying party is left to correlate
heterogeneous artifacts by hand, and in practice implementers hand-roll ad-hoc
"composite proofs" with no shared correctness model — in particular, no
guarantee that the several receipts authorize the SAME action rather than
different ones spliced together (a cross-binding attack).

The Entity Attestation Token [RFC9711] provides a CBOR mechanism (detached
submodules / detached EAT bundles) for composing claims from multiple attesting
environments into one token. No equivalent exists for the predominantly
JSON/JCS receipt cluster described above. This document fills that gap.

### 1.1. Scope and non-goals

EP-AEC defines (1) a composition object that references component receipts and
declares a requirement over them, and (2) an offline verification algorithm.
EP-AEC does NOT define any component receipt format, does not require any
particular component to be present, and does not bless any component
specification. It is deliberately minimal: its only novel normative content is
the same-action binding check and the requirement evaluation.

## 2. Terminology

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as described
in BCP 14 [RFC2119] [RFC8174].

* **Action Object** — the canonical representation of the external effect being
  authorized, as defined by [draft-schrock-ep-authorization-receipts] Section 3.
* **Canonical action digest** — the SHA-256 digest of the JCS [RFC8785]
  serialization of the Action Object, expressed as lowercase hexadecimal,
  optionally prefixed `sha256:`. The Action Object MUST conform to the I-JSON
  profile of [draft-schrock-ep-authorization-receipts] Section 3 (strings,
  booleans, null, arrays, objects, and safe integers only) so that the digest is
  byte-identical across implementations.
* **Component** — one referenced receipt within a chain, carrying a `type`, the
  receipt `evidence`, and an optional human-readable `label`.
* **Component verifier** — a function that verifies one component and returns
  both a validity result AND the canonical action digest that component attests
  it authorized.
* **Requirement** — a Boolean expression over component types/labels that
  determines ALLOW.

## 3. The Authorization Evidence Chain object

```json
{
  "@version": "EP-AEC-v1",
  "action": { ... Action Object ... },
  "action_digest": "sha256:<hex>",
  "components": [
    { "type": "ep-quorum",     "label": "two-person human authorization",
      "evidence": { ... EP-QUORUM-v1 object ... } },
    { "type": "policy-permit", "label": "machine policy permit",
      "evidence": { ... permit receipt ... } },
    { "type": "delegation",    "label": "agent delegation",
      "evidence": { ... delegation receipt ... } }
  ],
  "requirement": "ep-quorum AND policy-permit"
}
```

* `@version` (string, REQUIRED) — MUST be `EP-AEC-v1`.
* `action` (object, REQUIRED) — the Action Object every component must authorize.
* `action_digest` (string, OPTIONAL) — if present, MUST equal the canonical
  action digest recomputed from `action`; a mismatch is a fatal error.
* `components` (array, REQUIRED, non-empty) — each has `type` (string),
  `evidence` (object), and optional `label` (string).
* `requirement` (string, REQUIRED) — a Boolean expression (Section 5).

The chain carries the Action Object once; components reference the same action by
digest rather than re-embedding it. This is what makes the same-action binding
check possible and is the heart of the format.

## 4. Verification algorithm

A verifier is configured with a set of component verifiers keyed by `type`. Given
a chain `C`, the verifier MUST proceed fail-closed:

1. If `C` is malformed (missing `@version`, wrong version, missing or non-object
   `action`, empty `components`, or missing `requirement`), return DENY.
2. Compute `chain_digest` = canonical action digest of `C.action`. If
   `C.action_digest` is present and does not equal `chain_digest`, return DENY.
3. For each component `k`:
   a. If no verifier is registered for `k.type`, mark `k` unsatisfied
      (reason: no verifier) and continue.
   b. Invoke the verifier on `k.evidence`. It returns `{valid, action_digest}`.
      Any exception marks `k` unsatisfied.
   c. `k` is SATISFIED iff `valid` is true AND the returned `action_digest`
      equals `chain_digest`. A valid component that binds a different action MUST
      be treated as unsatisfied (reason: binds a different action). This is the
      cross-binding defense.
   d. If satisfied, add `k.type` and `k.label` (if present) to the satisfied set.
4. Evaluate `C.requirement` over the satisfied set (Section 5). Return ALLOW iff
   it evaluates true; otherwise DENY.
5. Any unexpected error at any step MUST yield DENY.

The result SHOULD include, per component, whether it verified and whether it was
bound, with a reason for any failure, to support audit.

Two optional component record types, the effect attestation (Section 7) and
ceremony evidence (Section 8), attach additional evidence rules on top of
step 3. Findings from those rules are conflict-class: they never move the
outcome toward ALLOW, and in the graded verdict set used by the reference
evaluation (admissible, missing_evidence, stale, conflicted, unverifiable) they
downgrade the verdict to `conflicted`. A record whose signature does not verify
is `unverifiable`, which is strictly worse and is never softened to
`conflicted`. No rule in this document ever moves a verdict toward a more
admissible one.

## 5. Requirement expressions

A requirement is a Boolean expression with the grammar:

```
expr := term (('AND' | 'OR') term)*
term := '(' expr ')' | IDENT
```

`IDENT` matches a component `type` or `label` in the satisfied set; an unknown
identifier evaluates to false. Implementations MUST evaluate the expression with
a bounded parser and MUST NOT use a general-purpose evaluator. Operator
precedence is left-associative; parentheses group explicitly. Example:
`ep-quorum AND (policy-permit OR delegation)` requires a human quorum plus either
a policy permit or a delegation receipt, all bound to the same action.

## 6. The human-authorization leg

Of the receipt families enumerated in Section 1, only the EP human-authorization
receipt binds a named, accountable human (or, via [draft-schrock-ep-quorum], a
quorum of distinct humans under separation of duties) to the exact action.
Several policy/permit formats reserve a slot for a threshold or multi-party
signature but specify no human semantics behind it. EP-AEC lets a relying party
require the human leg explicitly (e.g. `requirement` includes `ep-quorum`) while
composing it with machine-side delegation and permit receipts. The built-in
component verifiers `ep-quorum` and `ep-receipt` are defined by
[draft-schrock-ep-quorum] and [draft-schrock-ep-authorization-receipts]
respectively; all other types are supplied by the relying party.

## 7. Effect attestation

Every receipt family enumerated in Section 1 attests something about an action
before or at authorization time. None of them states what was then done. An
effect attestation is a post-execution evidence record that closes that
"approved X, executed Y" gap: the executor signs the receipt identifier of the
authorization it acted under together with a digest of the effect it observed.
Any third party holding both the authorization (which commits to the approved
effect) and the effect attestation can check divergence offline: if the observed
effect digest differs from the approved action's committed effect digest,
"approved X, executed Y" is demonstrated by the two records alone, with no
access to the executing system, and in the evidence verdict the divergence
surfaces as a conflict.

Use of this record type is OPTIONAL. Its component type identifier is
`effect_attestation`. When it is used, the following rules apply:

* The record MUST carry the receipt identifier of the authorization it attests
  and the digest of the observed effect, and MUST be signed by the executor. The
  component verifier for this type returns, alongside `valid` and
  `action_digest`, the fields `receipt_id`, `observed_effect_digest`, and, where
  the verifier could read the approved effect out of the referenced
  authorization, `committed_effect_digest`. Digest values are compared as
  lowercase hexadecimal after removal of an optional `sha256:` prefix.
* An effect attestation whose executor signature does not verify, or whose
  executor key is not pinned by the relying party, is inadmissible as evidence:
  the component verifier MUST report it invalid, and it MUST NOT be weighed as
  effect evidence at all (fail closed).
* The committed effect digest against which the observed digest is compared MUST
  NOT be taken from the presenter. It is either pinned by the relying party (the
  `expected_effect_digest` member of the relying-party policy) or read by the
  component verifier from the referenced authorization; where both are
  available, the relying-party pin takes precedence.
* If the observed effect digest differs from the committed effect digest, the
  verification result MUST record the reason code `effect_divergence` and treat
  the finding as a conflict (Section 4); it never moves the outcome toward
  ALLOW.
* A verified effect attestation that carries no observed effect digest MUST
  likewise be recorded under `effect_divergence` and treated as a conflict
  (fail closed).
* A verified effect attestation with no committed effect digest to compare
  against MUST record the reason code `effect_commitment_missing` and be treated
  as a conflict, never as admissible: an observed effect that cannot be tied to
  an approved effect does not show the effect was approved (fail closed).

Stated honestly: an effect attestation says what the executor CLAIMS was
observed. It is one more accountable, signed leg in the chain, not ground truth.
Its value is that an executor that misreports the effect is now misreporting in
a signed, attributable artifact bound to a specific receipt, and that a
divergence between two honest records is checkable offline by any third party
holding both. How the observed effect is represented and digested is
action-family specific and out of scope for this document.

## 8. Ceremony evidence

A human-authorization receipt proves that an accountable human approved the
exact action. It does not show how the approval happened. Ceremony evidence
carries signing-ceremony telemetry as a first-class evidence record: the
instants at which the authorization challenge was issued, viewed, and approved,
and the approver identity. Its component type identifier is `ceremony_evidence`;
the component verifier for this type returns, alongside `valid` and
`action_digest`, the fields `approver`, `issued_at`, `viewed_at`, and
`approved_at`. The component verifier proves the ceremony record is authentic;
the rules below judge what it says.

Ceremony evidence enables review-latency policies. An approval that comes in at
or below a policy floor every time is itself evidence of rubber-stamping: the
recorded human review contradicts a genuine one, and a relying party MAY weigh
it as a conflict. A relying party adopting such a policy sets a review-latency
floor (the `ceremony_min_review_sec` member of the relying-party policy). When a
floor is set, the following rules apply:

* The review interval of a verified ceremony record is `approved_at` minus
  `viewed_at`, in whole seconds.
* A verified ceremony record whose review interval is strictly below the floor
  MUST be recorded under the reason code `rubber_stamped_ceremony` and treated
  as a conflict (Section 4); it never moves the outcome toward ALLOW.
* If the telemetry on a verified ceremony record is absent or unusable (a
  missing or unparseable `viewed_at` or `approved_at`, or `approved_at` earlier
  than `viewed_at`), real review cannot be shown; the record MUST be recorded
  under the reason code `ceremony_telemetry_missing` and treated as a conflict,
  never as a silent pass (fail closed).
* A ceremony record whose signature does not verify is unverifiable; it is never
  softened to a conflict.

When no floor is set, this document attaches no judgment to the telemetry.
Stated honestly: ceremony telemetry is operator-originated. The issued, viewed,
and approved instants are recorded by the operator of the signing ceremony, not
by an independent observer; ceremony evidence gives the relying party an
accountable, signed record of the claimed timeline, not an independent
measurement of human attention.

## 9. Security considerations

* **Cross-binding (action substitution).** The core threat is splicing receipts
  that authorize DIFFERENT actions into one chain. Step 3c defeats this by
  requiring every satisfied component to attest the chain's exact canonical
  digest. The strength of this defense rests entirely on the canonical digest
  being byte-identical across implementations; the I-JSON profile
  ([draft-schrock-ep-authorization-receipts] Section 3) is therefore normative.
* **Component verifier trust.** A chain is only as sound as its weakest
  registered verifier and the keys it trusts. Relying parties MUST configure
  verifiers and trust anchors explicitly; an unconfigured type is unsatisfied,
  never assumed.
* **Requirement under-specification.** A weak requirement (e.g. one naming a
  component a relying party does not actually require) yields a weak decision.
  Requirements SHOULD name every leg the relying party depends on, including the
  human leg where accountability is required.
* **Freshness and revocation.** EP-AEC composes point-in-time evidence; it does
  not by itself prove the absence of a later revocation. Components that carry
  status/freshness evidence SHOULD be verified against the relying party's
  freshness policy.
* **No transport assumptions.** EP-AEC is a data structure; it inherits the
  confidentiality and integrity properties of whatever conveys it. It is
  fail-closed by construction (Section 4).

## 10. Relationship to other work

EP-AEC is complementary to, and composes, the efforts in Section 1. It is the
JSON/JCS analogue of the EAT [RFC9711] detached-bundle composition model and can
itself be registered as a SCITT [I-D.ietf-scitt-architecture] signed statement
for transparency. It neither extends nor constrains
[draft-nelson-agent-delegation-receipts], [draft-lee-orprg-permit-receipts],
[draft-farley-acta-signed-receipts], or
[draft-nivalto-agentroa-route-authorization]; each plugs in as a component type.

## 11. IANA considerations

This document has no IANA actions. A future revision may request a media type
(e.g. `application/ep-aec+json`) and a registry of component `type` identifiers
should the work be adopted.

## 12. Implementation status

A reference verifier and a runnable demonstration (composing a real EP human
quorum with a policy-permit leg, and rejecting both a cross-binding attack and a
missing human leg) are maintained as open-source software at
https://github.com/emiliaprotocol/emilia-protocol and are exercised offline with
no network dependency, by three cross-language implementations (JavaScript,
Python, Go) that agree on a shared conformance vector set. The three
implementations live in one repository and are a cross-language consistency
check, not clean-room independent implementations; independent implementations
remain future interoperability evidence. The evidence rules for the
effect-attestation and ceremony-evidence record types (Sections 7 and 8) are
implemented in a JavaScript-only reference evaluation in the same repository;
they are not yet part of the shared cross-language conformance vector set.

## 13. References

### 13.1. Normative References

[RFC2119], [RFC8174], [RFC7493], [RFC8785],
[draft-schrock-ep-authorization-receipts], [draft-schrock-ep-quorum].

### 13.2. Informative References

[RFC9711], [I-D.ietf-scitt-architecture],
[draft-nelson-agent-delegation-receipts], [draft-lee-orprg-permit-receipts],
[draft-farley-acta-signed-receipts], [draft-nivalto-agentroa-route-authorization],
[draft-mishra-oauth-agent-grants], [draft-marques-asqav-compliance-receipts].

### Author's Address

Iman Schrock, EMILIA Protocol, Inc. — team@emiliaprotocol.ai
```

This is the markdown working copy. Before submission it MUST be converted to
xml2rfc v3 and idnits-cleaned (ASCII, <=72-byte lines, full reference entries),
as with the other EP drafts.
