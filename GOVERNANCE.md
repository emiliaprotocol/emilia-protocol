# EMILIA Protocol Governance

This document states how the EMILIA Protocol (EP) specification and its
conformance suite are governed. It governs a wire format, its verification
discipline, and the public tests that define conformance. It does not govern
commercial products built above the protocol; those are out of scope here and
addressed only by the neutrality commitments below.

Where this document and the
[Neutrality Covenant](docs/NEUTRALITY-COVENANT.md) touch the same subject,
this document controls process and the covenant controls the commitments.

## 1. Object of governance

The governed artifacts are:

1. **EP-RECEIPT-v1**, the authorization-receipt wire format: a signed,
   offline-verifiable record binding a named human approver to one exact
   high-risk action, as specified in `draft-schrock-ep-authorization-receipts`.
2. **The verification discipline** attached to that format:
   - Offline verification against relying-party-pinned keys. The relying
     party chooses and pins the keys it trusts; no EP server sits in the
     trust path.
   - Fail-closed enforcement. A missing, malformed, unrecognized, or invalid
     receipt is a refusal, never a silent pass and never a fallback to a
     weaker mode.
   - One-time consumption. An authorization, once consumed or refused, is
     terminally unusable. Consumption is a state check performed by the
     enforcing system; offline verification of a receipt document proves
     signature, binding, and anchor integrity, and does not by itself
     establish that an authorization is currently valid or unconsumed.
3. **EP-QUORUM**, the multi-party approval profile (M-of-N and ordered
   approvals with distinct-key checks, fail-closed), as specified in
   `draft-schrock-ep-quorum`.
4. **The evidence and recourse layer**: the Action Evidence Graph (EP-AEG),
   its deterministic Evidence Policy Replay with five closed verdicts
   (admissible, missing_evidence, stale, conflicted, unverifiable), and the
   signed Reliance Result (EP-RELIANCE-RESULT), as specified in
   `draft-schrock-ep-action-evidence-graph`.
5. **The conformance vector suites** that pin all of the above, published in
   [`conformance/`](conformance/).

## 2. Stewardship and change control

EP is stewarded by EMILIA Protocol, Inc. All governed artifacts are public
and Apache-2.0 licensed.

The wire format is standardized in the open through the IETF as
individual-submission Internet-Drafts (`draft-schrock-ep-*`). These are
active individual submissions, not IETF-adopted or endorsed documents. They
are submitted in full conformance with BCP 78 and BCP 79, which means change
control over any document an IETF working group adopts passes to the IETF.
That open-standardization path is the intended destination for change
control over the wire format.

## 3. Specification changes

1. Anyone may propose a change as a GitHub issue or pull request.
2. A change to normative behavior lands in the specification text, the
   reference verifiers, and the conformance vectors together, or not at all.
3. The published vectors are the operational definition of conformance. If
   the reference verifiers disagree with each other or with the
   specification, that is a bug; protocol correctness outranks backward
   compatibility.

The reference verifiers (JavaScript, Python, Go) are one team's
cross-language ports in one repository: a consistency check, not clean-room
independent implementations.

## 4. Versioning

Wire format versions are explicit strings (for example `EP-RECEIPT-v1`).
A verifier rejects any version string it does not recognize; this behavior
is itself pinned by a reject vector. A change that alters the meaning of an
existing version string is not permitted; changed semantics require a new
version string. Vectors for a released version may be added; the expected
outcome of a published vector does not change for that version.

## 5. Conformance

[CONFORMANCE.md](CONFORMANCE.md) is the source of truth for what a
conformant implementation is, which suites exist, and how many vectors each
contains. Counts and suites evolve there, not here.

Conformance is self-certified against the published suites. The complete
vector set, including all adversarial and reject vectors, is in the public
repository. The cross-language runner is `conformance/run.mjs`.

## 6. Recourse and disputes

Any adverse decision made through EP's evidence layer must be reproducible
by the party it affects.

Evidence Policy Replay is deterministic: given the same Action Evidence
Graph and the same relying-party-supplied evidence policy, any party
recomputes the same verdict, one of five closed values. The replay digest
lets a third party recompute the decision without trusting the party that
made it. The verdict can be issued as a signed Reliance Result, making the
reliance decision itself auditable evidence; a Reliance Result from an
unpinned verifier key is not accepted.

Disputes are therefore resolved by recomputation against the stated policy,
not by appeal to the steward. A verdict is evidence of sufficiency under a
stated policy; it is not adjudication, and it does not establish the
business correctness of the underlying action.

## 7. Neutrality

The full commitments are in the
[Neutrality Covenant](docs/NEUTRALITY-COVENANT.md). In summary:

- There is no paid or private vector tier. Every vector that counts toward
  conformance is in the public repository, free of charge.
- EMILIA products receive no protocol-level privilege. Anything our products
  can verify, anyone's code can verify, against the same public formats.
- No certification program exists today. If one is ever created, it tests
  only against the public vectors and is offered to any implementer,
  including direct competitors, on identical published terms.
- The protocol is not bound exclusively to any transport, agent framework,
  vendor, or model provider.

## 8. Intellectual property

- All contributions to the EP specification and conformance suites are
  licensed under Apache-2.0. Released versions are licensed irrevocably:
  irrevocability is a property of the Apache-2.0 grant itself.
- Contributors retain copyright to their contributions.
- No contributor can claim exclusive rights over the protocol specification.
- The specification is a shared standard, not a product.

## 9. Names and marks

Apache-2.0 licenses code, specifications, and vectors, not names. The EMILIA
name and marks are held by EMILIA Protocol, Inc. and are not licensed by
this document or by the covenant. Anyone may implement, fork, and verify the
protocol; presenting a product as "EMILIA" remains subject to the marks.
Interoperability never requires the name.

## 10. Code of Conduct

Contributors follow the
[Contributor Covenant](https://www.contributor-covenant.org/) Code of
Conduct.

## 11. Contact

- **GitHub:** https://github.com/emiliaprotocol/emilia-protocol
- **Email:** team@emiliaprotocol.ai
- **Standards:** IETF datatracker, `draft-schrock-ep-authorization-receipts`
  and `draft-schrock-ep-quorum`; companion `draft-schrock-ep-*` documents
  under [`standards/`](standards/)
