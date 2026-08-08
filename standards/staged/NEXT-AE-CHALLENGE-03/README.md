# AE Challenge revision 03 candidate

This isolated candidate is derived from the immutable posted
`draft-schrock-ae-challenge-02` source. It is a substantive protocol revision,
not an IANA-only or publication-path edit.

Revision -03 separates the transport-neutral `AE-CHALLENGE-v1` data model from
its carriers. It defines a normative HTTP binding using `403 Forbidden`, RFC
9457 `application/problem+json`, `Cache-Control: no-store`, and an
`evidence_challenge` extension. It withdraws the proposed dedicated media type
and instead requests an HTTP Problem Types registry entry under Specification
Required.

The revision also adds an informative DMSC gateway profile. A receiving
gateway can challenge for missing, stale, or unverifiable authorization
evidence, but the challenge does not transfer admission ownership, conserve a
single-use right across gateways, or prevent double admission. Those remain
the separate Section 7.8 handoff problem in the proposed DMSC -04 revision.

The core now pins authenticated carriage, action-profile identification,
requirement correlation, presentation alternatives, obtain hints that confer
no authority, nonce-consumption ordering, follow-up challenge rules, and a
critical-extension mechanism. Open identifier-governance and carrier choices
are called out explicitly for Agent2Agent and AgentProto review.

