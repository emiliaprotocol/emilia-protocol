# Discovery-to-Permit Continuity Profile v1

Status: reference profile, version 1

## Purpose

This profile carries discovery provenance into later permit evaluation without
turning discovery into authorization. It binds one relying-party-pinned source
chain to one CAID, one canonical action digest, and one mapping digest. A
successful result says only that the configured source chain is current and
internally consistent. An executor still requires its configured AEC/AEB/Gate
authorization and consumption path before effect.

The profile is an interoperability profile over CAID, AEB, and AEC. It is not a
new core authorization protocol.

## Constructor-pinned trust boundary

A resolver MUST receive the following values at construction and MUST snapshot
them immutably:

- the exact HTTPS source origin;
- the exact discovery and permit URLs;
- the discovery-schema and permit-binding-schema SHA-256 digests;
- the exact mapping SHA-256 digest;
- the maximum source age;
- the complete exact redirect map; and
- an address-pinned transport dependency.

The resolver operation accepts only the executor-owned `caid` and `action`.
Origin, URLs, schema digests, mapping digests, age limits, redirects, transport
configuration, or other trust material supplied with an individual operation
MUST be refused before address resolution or network access. Post-construction
mutation of the caller's options or transport object MUST NOT change the
resolver.

## Address-pinned retrieval

For each URL, the transport boundary has two operations:

1. resolve the hostname to the complete A/AAAA answer set; and
2. connect directly to one approved address while preserving the URL hostname
   for TLS SNI, certificate validation, and the HTTP Host field.

The resolver rejects an empty, malformed, private, reserved, link-local, or
documentation-only address set. The transport returns the connected address,
which MUST be in the approved set. A plain injected or global `fetch` is not an
acceptable dependency because it can independently re-resolve the hostname.

All requests use `redirect: manual`. A redirect is followed only when the
constructor map contains the exact current URL and its exact value equals the
resolved `Location` URL. Unmapped redirects, target mismatches, cycles, and
redirect chains beyond the finite pinned map are refused.

## Bounded document processing

Each response MUST:

- be a successful HTTP response or an allowed manual redirect;
- carry `application/json` (parameters such as `charset=utf-8` are allowed);
- fit within the constructor-pinned byte limit;
- decode as strict UTF-8;
- contain no duplicate object member names or unpaired Unicode surrogates;
- fit within the constructor-pinned JSON depth; and
- match the exact profile object shape and `@type`.

The resolver records both:

- `raw_digest`: SHA-256 over the exact response bytes; and
- `canonical_digest`: SHA-256 over the EP deterministic JSON serialization.

Provenance also records the requested URL, final resolved URL, complete redirect
chain, connected address, media type, and byte length for each document.

## Source and action continuity

The discovery document and permit binding repeat the same:

- `source.origin`;
- `source.discovery_url`;
- `source.permit_url`;
- `schema_digests.discovery`;
- `schema_digests.permit_binding`;
- `mapping_digest`;
- `status`; and
- `issued_at`.

Every value MUST agree exactly with the other document and the constructor pins.
The binding's `caid` MUST equal the executor-supplied CAID. Its `action_digest`
MUST equal SHA-256 over the executor-owned canonical action. A CAID match does
not excuse an action-digest mismatch, and a matching action does not excuse a
mapping-digest mismatch.

## Dispositions

The resolver emits one of four dispositions:

- `current`: both documents are active, agree exactly, and are no older than the
  pinned maximum age;
- `stale`: the exact active source chain is older than the pinned maximum age;
- `unknown`: both exact source documents explicitly report unknown status; or
- `deprecated`: both exact source documents explicitly report deprecated
  status.

Only `current` sets `usable_for_permit: true`. Every disposition, including
`current`, sets `authorizes_action: false`. Stale and unknown results become
indeterminate AEB evidence; deprecated results are rejected.

## Native AEB adapter

The native adapter verifies the immutable resolution, rechecks the pinned
source/schema/mapping/max-age configuration, and maps the executor-owned action
to the already-bound CAID. Its result carries:

```json
{
  "evidence_role": "discovery-permit-continuity",
  "authorization": "EVIDENCE_ONLY",
  "authorizes_action": false
}
```

`ACCEPTED` means the evidence leg was verified for composition. It does not mean
the action is authorized. The adapter exposes no invocation method and does not
reserve or consume a permit. Authorization remains a relying-party decision
under a constructor-pinned AEC requirement and Gate consequence boundary.

## Security non-claims

This profile does not prove that the source was entitled to grant authority,
that a user approved an action, that a permit is unconsumed, or that an external
effect occurred. It supplies bounded, content-addressed discovery provenance
for a later permit decision.
