# Human Authorization Binding -01 candidate packet

This isolated packet contains the review candidate for
`draft-schrock-human-authorization-binding-01`. It has not been submitted.

Candidate source:

- `UPLOAD-THIS/draft-schrock-human-authorization-binding-01.xml`

Revision -01:

- keeps owner, delegator, terminal accountable authority, per-action human
  approver, logical agent, live workload instance, OAuth client, executor, and
  target tool or action as separate roles;
- adds authoritative approver attribution, so a signature, a self-asserted
  name, a workload identity, or an OAuth subject cannot by itself establish a
  named human;
- states that discovery locates metadata and keys but does not create a
  relying-party trust decision;
- distinguishes a standing terminal grant from a per-action human approval,
  using the IA-9(T) assessment overlay as independent supporting analysis;
- composes resource-server-discovered human-evidence requirements with
  AE-CHALLENGE and AIMS Section 10.7 without replacing CIBA, OAuth, or the
  authorization server's decision; and
- expands the deterministic binding vector with hostile discovery,
  self-assertion, subject-relabeling, dual-form inconsistency, and
  terminal-authority/approver-collapse cases.

The posted `-00` bytes remain immutable. Publication of this candidate would
not make it a working-group document, IETF consensus, or IETF endorsement.
