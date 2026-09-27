# AE Challenge revision 08 submission candidate

This isolated packet contains the candidate source and review artifacts for
`draft-schrock-ae-challenge-08`. The only upload candidate is:

`UPLOAD-THIS/draft-schrock-ae-challenge-08.xml`

The source is prepared for posting as an Internet-Draft and for a later
request to the Independent Submissions Editor under RFC 4846. It is an
individual draft; nothing in it states or implies IETF consensus.

## What -08 changes

Revision -08 adds one optional profile to the existing challenge protocol.
`AE-EVALUATION-LINEAGE-v1` carries an authenticated issuer statement about
the bounded result of evaluating one claimed presentation. It binds the
predecessor challenge, presentation, evaluation semantics, exact action,
policy, issuer, presenter, and relying-party evaluation time.

The profile uses the outcome terms of the Authorization Evidence Chain draft
(`draft-schrock-ep-authorization-evidence-chain-07`, staged in
`../NEXT-AEC-07/`) instead of a vocabulary of its own. Section 1.3 restates
VERIFIED, ACCEPTED, SATISFIED and UNSATISFIED, so the AEC draft stays an
informative reference and this document has no normative dependency on
another Internet-Draft. The lineage outcomes are `SATISFIED` and
`UNSATISFIED`. The closed reason identifiers keep apart a presented artifact
that is not VERIFIED (`evidence_not_verified`), one that is VERIFIED and not
ACCEPTED (`evidence_not_accepted`), one not bound to the exact action
(`action_not_matched`), and an evaluation that did not complete
(`evaluation_unavailable`, `evaluation_state_uncertain`). A successor
challenge can be linked only after a completed `UNSATISFIED` evaluation, and
the link remains a fresh refusal rather than reusable authority. None of the
outcomes means that an action was authorized, admitted, executed, or settled.

The artifact is data-minimized. It carries digests and identifiers, not raw
evidence, policy documents, credentials, authority objects, execution results,
or free-form explanations. Stable identifiers and low-entropy digests can
still reveal or correlate information. A recipient that retains authenticated
artifacts can distinguish earlier and later issuer statements, but the profile
does not prove challenge consumption, ordering, completeness, or non-omission.

The core also names acceptance as its own step: evidence obtained through an
obtain hint needs relying-party acceptance, acceptance is part of the
evaluation order, and a follow-up challenge is allowed when evidence is not
VERIFIED, not ACCEPTED, or not bound to the exact action.

Christine Classy's public missing-evidence and repair-history example is
credited informatively. Its branding, legal conclusions, and unrelated schema
are not imported into the protocol.

## Independent Submission shape

- `submissionType="independent"`, category Informational.
- IANA: one entry in the existing "HTTP Problem Types" registry
  (Specification Required, RFC 9457 Section 4.2). RFC 8726 Section 2 lets an
  Independent Stream document request allocations from existing registries
  under their own policy; the draft creates no registry.
- The description of the same-team reference implementation, which was
  Section 2.6.2 of -07, is now an Implementation Status section marked
  `removeInRFC`. It notes that the RFC 7942 process covers IETF-stream drafts
  and that this document is intended for the Independent Submission Stream.
- The replaced `draft-klrc-aiagent-auth-03` reference is now
  `draft-ietf-wimse-aims-00`, cited in Appendix A for its human-in-the-loop
  guidance (AIMS Section 10.7), which is the native OAuth path Section 1.1
  keeps separate from AE-CHALLENGE.
- Example lines longer than 69 characters are folded as RFC 8792 specifies,
  so every line of the text rendering fits 72 columns.
- One References section with Normative and Informative subsections.
- Every normative reference is an RFC.

## Hold

This packet remains a candidate until the exact XML is accepted and published
by the IETF Datatracker. The immutable published -07 source remains
authoritative until that event. Posting and the ISE request are the author's
decisions. Before them:

1. Upload `draft-schrock-ep-authorization-evidence-chain-07` first; this
   draft cites that revision.
2. Set the date, confirm that -07 is still the latest AE Challenge revision
   and that each cited draft revision is still the latest on Datatracker,
   re-render with the procedure in `VALIDATION.md`, and refresh
   `SHA256SUMS.txt`, `VALIDATION.md` and the date pin in
   `scripts/check-ae-challenge-08.mjs`.
3. The Implementation Status paragraphs moved unchanged from -07 were not
   re-verified for this candidate (see `VALIDATION.md`). Re-check them
   against the reference implementation before posting.
4. Whether the HTTP Problem Types designated expert accepts `ae-required` is
   unchecked. RFC 9457 Section 4.2 excludes vendor-specific,
   application-specific and deployment-specific values.
