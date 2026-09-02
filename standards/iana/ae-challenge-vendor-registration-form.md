# IANA vendor media-type request: live-form field map

Status: Submitted to IANA as ticket #1458921; designated-expert review pending.

Leave the form's humanity-check field blank.

## Submitter

Your Full Name: Iman Schrock

Your E-mail: team@emiliaprotocol.ai

## Media type

Type Name: application

Registration tree: Vendor Tree (`vnd.` prefix)

Subtype Name, entered without the tree prefix:

    emilia.authorization-evidence-challenge+json

Full media type:

    application/vnd.emilia.authorization-evidence-challenge+json

Required Parameters: N/A

Optional Parameters: N/A

Encoding Considerations: binary

Additional encoding notes:

The content is one UTF-8 JSON text whose top-level value is a single
`AE-CHALLENGE-v1` object. It is not a JSON text sequence and does not use
record-separator framing. Binary is selected because JSON representations can
contain lines longer than 998 octets.

## Security Considerations

This media type contains declarative JSON and no active or executable content.
It uses neither compression nor a container format. It provides no origin
authentication, integrity, confidentiality, replay protection, trusted time,
or audience verification; a carrier or authenticated envelope must supply the
properties required by its use. A challenge authorizes nothing and does not
reserve or consume action authority, promise execution, or establish that an
external effect occurred.

The object contains URI-valued semantic identifiers and may contain
`obtain_hints`. Dereferencing is not required for parsing. Security-relevant URI
semantics must be locally pinned or resolved only from immutable,
authenticated content. `obtain_hints` are untrusted inputs and can create SSRF,
redirect, credential-forwarding, and evidence-exfiltration risks.

Single-use processing requires an authoritative replay domain keyed by
authenticated issuer identity and nonce and an atomic first-claim transition;
expiry and nonce randomness alone do not prevent replay. Implementations reject
duplicate JSON members, enforce finite parsing and state limits, and fail closed
on replay-store uncertainty. Action and policy digests do not hide low-entropy
values and do not prove business correctness or execution. Confidentiality
appropriate to the deployment is required when the challenge exposes sensitive
action, policy, identity, or routing information. See RFC 8259 Section 12 and
the complete Security Considerations in the Version 1 published specification.

## Interoperability Considerations

The representation is exactly one UTF-8 RFC 8259 JSON text containing a single
`AE-CHALLENGE-v1` core object. Generic `+json` processors can parse the syntax
but do not thereby implement challenge semantics. Recipients refuse an
unsupported `@version` and duplicate members; nested core objects are closed;
`critical` governs unknown top-level extensions. This media type labels the
bare core object, not an RFC 9457 Problem Details wrapper. It does not select a
canonicalization profile; every carrier binding or presentation profile must
define the complete-body digest and representation, issuer identity, audience,
replay domain, time, and return-path semantics required by this Version 1
specification.

## Published specification

EMILIA bare AE Challenge media-type serialization specification, Version 1:

https://github.com/emiliaprotocol/emilia-protocol/blob/main/standards/iana/ae-challenge-vendor-binding.md

## Application Usage

This media type is intended for use by EMILIA product implementations and
compatible presenters that exchange a bare `AE-CHALLENGE-v1` object through a
separately specified carrier or presentation profile.

This applications list is not exhaustive.

## Fragment Identifier Considerations

As specified for `+json` in RFC 6839 Section 3.1. Because
`application/json` defines no fragment-identifier syntax, this registration
defines none.

## Restrictions on Usage

This type labels only the bare `AE-CHALLENGE-v1` object. It **MUST NOT** label
an HTTP Problem Details envelope. A carrier that embeds the object in such an
envelope uses the envelope's media type, such as `application/problem+json`,
and separately defines the embedding member and its semantics. Any carrier or
presentation profile must satisfy the requirements in the Version 1 published
specification.

Provisional Registration: No

## Additional Information

Deprecated alias names: N/A

Magic number(s): N/A

File extension(s): N/A

Macintosh File Type Code(s): N/A

Object Identifier(s): N/A

## Intended Usage

LIMITED USE

Additional information: N/A

## Other Information & Comments

This is a vendor-tree product registration for the bare `AE-CHALLENGE-v1` JSON
object. It does not request a standards-tree allocation and does not change the
media type of an enclosing carrier. The vendor designation `emilia` refers to
EMILIA Protocol, Inc.

Informative protocol context, not required to parse or process this media type:

https://www.ietf.org/archive/id/draft-schrock-ae-challenge-07.html

## Contact Person

Contact Name: Iman Schrock

Contact Email Address: team@emiliaprotocol.ai

Author/Change Controller:

Iman Schrock, EMILIA Protocol, Inc. <team@emiliaprotocol.ai>. Change controller:
EMILIA Protocol, Inc. <team@emiliaprotocol.ai>.

## Submission controls

- Accept IANA's privacy-policy and terms-of-service acknowledgement only at the
  final submission step.
- Do not claim this is the HTTP response type in the Internet-Draft.
- Select the vendor tree and enter the subtype without `vnd.`.
- Select binary encoding.
- Select No for provisional registration.
- Do not use IETF as change controller.
- Do not claim deployment, IETF review, or standards endorsement.
- Keep the serialization-specification URL public and stable throughout review.
- Preserve IANA ticket #1458921 and record the final registry outcome.
