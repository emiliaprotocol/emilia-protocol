# EMILIA bare AE Challenge media-type serialization specification, Version 1

Status: Version 1 vendor product specification.

Media type:

    application/vnd.emilia.authorization-evidence-challenge+json

This document defines the media-type label and bare UTF-8 JSON serialization
for an `AE-CHALLENGE-v1` object. It does not define a complete carrier or
presentation binding, change draft-schrock-ae-challenge-07, request IETF
adoption, or replace any protocol carrier defined by that Internet-Draft.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and
**OPTIONAL** in this document are to be interpreted as described in BCP 14
[RFC 2119] [RFC 8174] when, and only when, they appear in all capitals.

## Representation

The representation is one UTF-8 JSON text whose top-level value is one
`AE-CHALLENGE-v1` object. It is not a JSON text sequence and does not use record
separator framing.

The object follows Sections 2, 2.7, and 2.8 of
draft-schrock-ae-challenge-07. In particular:

- `@version` is `AE-CHALLENGE-v1`.
- `challenge_id`, `nonce`, `action_digest`, `action_profile`, `audience`,
  `policy_id`, `policy_digest`, `required_evidence`, `present_as`, and
  `expires_at` are required.
- `obtain_hints`, `retry_timing`, and `critical` are optional.
- duplicate JSON members are rejected before semantic processing.
- nested core objects are closed.
- `critical` governs unknown top-level extension members.
- recipients refuse an unsupported `@version` instead of guessing.

A generic `+json` processor can parse the representation but does not thereby
implement challenge semantics. This specification does not select a JSON
canonicalization profile.

## Carrier boundary

This media type labels only the bare object. Every carrier binding or
presentation profile that uses it **MUST** define the complete-body digest and
deterministic representation or exact-byte preservation, authenticated issuer
identity, effective-audience binding and comparison rules, replay domain,
trustworthy evaluation time, and return-path semantics required by Sections
2.2, 2.3, and 2.8 of draft-schrock-ae-challenge-07.

The media type **MUST NOT** be used as the `Content-Type` of the HTTP refusal
response in Section 3 of draft-schrock-ae-challenge-07. That response remains
`application/problem+json` and carries the core object in the
`evidence_challenge` member.

## Security considerations

An AE challenge authorizes nothing. Satisfying one does not reserve an action,
consume action authority, promise execution, or establish that an external
effect occurred.

The representation contains declarative JSON and no active or executable
content. It uses neither compression nor a container format. It provides no
origin authentication, integrity, confidentiality, replay protection, trusted
time, or audience verification. Those properties belong to the carrier or an
authenticated envelope.

The object contains URI-valued semantic identifiers and may contain
`obtain_hints`. Dereferencing a URI is not required to parse this media type.
Security-relevant URI semantics **MUST** be locally pinned or resolved only from
immutable, authenticated content. `obtain_hints` are untrusted inputs and can
create SSRF, redirect, credential-forwarding, and evidence-exfiltration risks.

Single-use handling requires an authoritative replay domain keyed by
authenticated issuer identity and nonce, plus an atomic first-claim transition.
Expiry and nonce randomness do not replace that state. A live replay key is not
overwritten. Uncertain replay-store or claim state fails closed.

Action and policy digests do not hide low-entropy values and do not prove
business correctness or execution. Implementations apply finite message,
nesting, string, array, and retained-state limits and the JSON security
considerations in RFC 8259 Section 12. Confidentiality appropriate to the
deployment is required when a challenge exposes sensitive action, policy,
identity, or routing information.

## Change control

EMILIA Protocol, Inc. controls this serialization specification and the
vendor-tree registration. The underlying Internet-Draft remains an individual
submission and is not represented here as IETF-adopted or endorsed.

## References

- RFC 2119
- RFC 8174
- RFC 8259, especially Section 12
- RFC 6838, especially Sections 3.2, 4.4, 4.6, and 5.6
- RFC 6839, Section 3.1
- RFC 9457
- draft-schrock-ae-challenge-07, Sections 2, 2.2, 2.3, 2.7, 2.8, 3, and 5
