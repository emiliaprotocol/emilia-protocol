# AE Challenge revision 08 submission candidate

This isolated packet contains the candidate source and review artifacts for
`draft-schrock-ae-challenge-08`. The only upload candidate is:

`UPLOAD-THIS/draft-schrock-ae-challenge-08.xml`

Revision -08 adds one optional profile to the existing challenge protocol.
`AE-EVALUATION-LINEAGE-v1` carries an authenticated issuer statement about the
bounded result of evaluating one claimed presentation. It binds the
predecessor challenge, presentation, evaluation semantics, exact action,
policy, issuer, presenter, and relying-party evaluation time.

The profile has three closed outcomes: evidence sufficient, evidence
insufficient, and evaluation indeterminate. Those outcomes never mean that an
action was authorized, admitted, executed, or settled. A successor challenge
can be linked only after an insufficient evaluation, and the link remains a
fresh refusal rather than reusable authority.

The artifact is data-minimized. It carries digests and identifiers, not raw
evidence, policy documents, credentials, authority objects, execution results,
or free-form explanations. Stable identifiers and low-entropy digests can
still reveal or correlate information. A recipient that retains authenticated
artifacts can distinguish earlier and later issuer statements, but the profile
does not prove challenge consumption, ordering, completeness, or non-omission.

Christine Classy's public missing-evidence and repair-history example is
credited informatively. Its branding, legal conclusions, and unrelated schema
are not imported into the protocol.

This packet remains a candidate until the exact XML is accepted and published
by the IETF Datatracker. The immutable published -07 source remains
authoritative until that event.
