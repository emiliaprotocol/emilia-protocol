# CAID — Canonical Action Identifiers

**The missing join key for agentic-action evidence. It works with whatever
you already issue; it replaces nothing.**

Permits, receipts, outcome attestations, delegation chains, payment
mandates, consent records, audit events, insurance objects often reference
"the action" using format-local objects and digests. Without an agreed
material-action definition, a permit
from one system, an approval from a second, and an outcome attestation from
a third cannot be composed as evidence about the same action without
bilateral negotiation, and each artifact is only as strong as whatever
fields its author happened to digest.

CAID addresses both problems with one small object and one string:

```json
{
  "action_type": "payment.release.1",
  "amount": "40000.00",
  "currency": "USD",
  "beneficiary_account": "sha256:7c9e...beef",
  "payment_instruction_id": "pi_42"
}
```

    caid:1:payment.release.1:jcs-sha256:Kq3v...N9w

- **Typed**: `action_type` is inside the digested content and names an
  entry in the action-type registry (or a local definitions file in the
  same schema). Each type declares its REQUIRED material fields, so a
  conforming issuer cannot mint an identifier for an underspecified action.
  This is the unilateral win: your artifact stops being challengeable on
  "the digest did not cover the amount."
- **Joinable**: under the selected suite and pinned type definition, matching
  CAIDs commit to matching canonical typed content. Each artifact still
  verifies under its own specification and trust boundary. A shared action
  identifier reduces bilateral correlation work; it does not guarantee that
  two deployments selected equivalent type definitions or mapping profiles.
- **Mappable without guessing**: when native formats cannot emit identical
  bytes, a relying-party-pinned Action-Mapping Profile projects each verified
  source into a material CAID action. The comparison returns
  `EQUIVALENT_UNDER_PROFILE`, `NOT_EQUIVALENT`, or `INDETERMINATE`; missing or
  lossy mappings abstain.
- **Boring on purpose**: no trust semantics, no assurance levels, no
  authorization logic, no network dependency, no fees. Registry data is
  CC0. Reference implementations (JavaScript, Python, Go) are Apache-2.0,
  dependency-free, and agree on a shared conformance vector suite.

## The verification boundary

CAID mapping starts only after each source artifact has verified under its
own specification and trust anchors. A mapping profile binds an exact source
media type, schema, version, transform set, and target action type. The
relying party pins the profile hash. Mapping never upgrades an untrusted
artifact into trusted evidence and never converts equivalence into
authorization.

Run the signed cross-format demonstration:

```sh
node examples/caid-action-mapping.mjs
```

It accepts two independently signed native objects only after native
verification and refuses or abstains on signature tampering, merchant
substitution, profile substitution, and missing native verification.

## What a CAID is not

A CAID commits an identifier to canonical typed content. It does not
prove the action was authorized, executed, safe, or wise. It is not a
capability: treat it as public. Composition joins on the identifier; no
verifier ever ingests another verifier's evidence into its own trust
boundary.

## Layout

- `DESIGN.md` — normative core
- `../standards/staged/draft-schrock-canonical-action-identifier-00.xml` —
  candidate Internet-Draft source (xml2rfc v3)
- `registry/` — action-type registry seed, suites, governance
- `impl/js`, `impl/python`, `impl/go` — reference implementations
- `conformance/vectors.json` — 48 core identifier vectors
- `conformance/mapping-vectors.json` — 13 cross-format mapping vectors
- `bindings/` — one-page composition notes for existing specs (MCP, A2A,
  AP2, AuthZEN, ACTA, WIMSE, permit receipts, outcome attestation, OAuth
  agent-authorization drafts, AGTP, EMILIA receipts, Continuum)

Stewardship: currently maintained by EMILIA Protocol with a standing
commitment, stated in `registry/GOVERNANCE.md`, to transition the registry
to IANA or another neutral body upon adoption.
