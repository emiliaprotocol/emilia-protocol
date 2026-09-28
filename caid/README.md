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
- **Replayable enums**: inline enums are closed sets. External enums resolve
  only through a locally supplied snapshot whose reference, edition label,
  and SHA-256 pin all match the type definition. Mutable names, missing
  snapshots, digest mismatches, and out-of-set values fail closed without a
  network fetch.
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
capability: possession proves nothing. It is not anonymous either: it has
the same confidentiality as its action object, because anyone who can guess
the object's low-entropy fields can recompute the identifier (the draft's
Privacy Considerations). Composition joins on the identifier; no verifier
ever ingests another verifier's evidence into its own trust boundary.

## Layout

- `../standards/posted/draft-schrock-canonical-action-identifier-04.xml` —
  the Internet-Draft, posted on 2026-09-28, which is the normative text; its
  publication provenance packet is `../standards/staged/NEXT-CAID-04/`
- `DESIGN.md` — where each rule lives now; no longer normative
- `spec/` — derived from the draft: `caid.abnf` (Appendix A), `core.json`
  (limits, reasons and ranks, field types, mapping closed sets), `gen.mjs`
  (writes the constants each port compiles in), `abnf-check.mjs` (proves the
  generated matchers equal the grammar and run in linear time)
- `registry/` — action-type registry (version 5), suites, value sets, frozen
  history, definition digests, governance
- `impl/js`, `impl/python`, `impl/go` — reference implementations
- `conformance/vectors.json` — 616 core vectors (corpus version 5): every
  compute and verify input as exact JSON text with native/byte parity, a
  native lane for host values no decoder produces, the JSON text rules and
  size limits, number rounding, reason order, verification details,
  definitions and `definition_sha256`, the named code formats, and one
  vector per registry v5 type; the 96 version 4 vectors keep their ids
  (`conformance/history/vectors.v4.json` is version 4 byte for byte)
- `conformance/grammar-vectors.json` — 1,966 grammar boundary cases driven
  through the public parse and compute entry points
- `conformance/mapping-vectors.json` — 86 mapping vectors
  (version 2) with exact reason lists in the -04 stage order, including the
  SILP IR to CAID `CANCEL+EMAIL` profile
- `fuzz/` — the differential fuzz: about 88,000 seeded cases through the
  JavaScript, vendored Verify, Python and Go entry points against the spec
  oracle, with an empty allow list
- `interop/consequential-action-v1/` — 25 candidate, revision-pinned
  mechanism mappings with 100 positive, refusal, and abstention vectors;
  all await author review
- `bindings/` — one-page composition notes for existing specs (MCP, A2A,
  AP2, AuthZEN, ACTA, WIMSE, permit receipts, outcome attestation, OAuth
  agent-authorization drafts, AGTP, EMILIA receipts, Continuum)

Stewardship: maintained by the EMILIA Protocol maintainers as initial
editors. The -04 draft asks IANA to create the CAID registries; until it
does, `registry/` is the reference copy (`registry/GOVERNANCE.md`).

## Changing a rule, a field type or a suite

The grammar and the rule data have one source each: `spec/caid.abnf` and
`spec/core.json` (with `registry/suites.json` for suites). Never edit a
generated region or file by hand; the checks fail on it.

1. Edit `spec/caid.abnf` and `spec/core.json`, then run
   `node caid/spec/gen.mjs --write`. It rewrites the generated region of
   `impl/js/caid.mjs`, its byte copy `packages/verify/vendor/caid.mjs`,
   `impl/python/caid_spec.py` and `impl/go/spec_gen.go`. `gen.mjs` asserts
   the compute and verify gates, which follow from data dependencies, and
   reads the verify reason order from `core.json`.
2. A new field type is a `core.json` `field_types` entry (JSON kind,
   members, refusals, pattern and calendar check) plus `checkField` in
   `impl/js/caid.mjs`, `impl/python/caid.py` and `impl/go/caid.go`, and in
   the spec oracle `spec/reference.mjs`. A new code format is an ABNF rule
   in part A.4 plus a `code_formats` entry with its syntax reference; the
   generator refuses a format that is not linear-time. A new suite is a
   `registry/suites.json` entry with its `digest_octets`, a
   `suite_digest_rules` entry and its ABNF digest rule, and each port's set
   of implemented suites.
3. Add cases where a port is driven: the rule-to-driver maps of the three
   grammar runners (`impl/js/run-grammar-vectors.mjs`,
   `impl/python/run_grammar_vectors.py`, `impl/go/cmd/grammar-vectors`),
   `conformance/tools/core-cases.mjs`, the drivers of
   `conformance/tools/build-grammar.mjs`, and a family in `fuzz/gen.mjs`.
   Then `npm run caid:corpus`.
4. Run `node caid/spec/abnf-check.mjs`, `npm run caid:conformance` and
   `npm run caid:fuzz`.
5. Update the draft. -04 is posted, so its packet
   (`standards/staged/NEXT-CAID-04`) is publication provenance and is not
   edited. `node scripts/check-caid-04.mjs` fails when a change here
   contradicts what -04 states (Appendix A against `caid.abnf`, the
   generated tables, Appendix D, the recomputed examples). Such a change
   belongs in a new revision packet built the way the -04 packet was:
   `node scripts/check-caid-04.mjs --emit` prints every generated table,
   the two Appendix D listings, and the Appendix C.1 cbor-sha256 example,
   a processing change needs a `chg-` item mapped to vectors in
   `CHANGES-VECTORS.json`, and the renders follow the procedure in the
   packet's `VALIDATION.md`.
6. A change to the vendored copy moves pins outside `caid/`: the source
   locks of the composition profiles that pin `vendor/caid.mjs`
   (`conformance/composition/*/source-lock.json`),
   `formal/results/formal-runtime-scenario-conformance.v2.json`, the
   clean-room pins (`npm run sync:clean-room-pins`), the conformance
   manifest (`npm run conformance:manifest`) and the LLM context
   (`npm run sync:llm-context`). A change to `packages/verify/src` also
   rebuilds `packages/verify/dist` (`npm --prefix packages/verify run
   build`) and the standalone runtimes (`npm run build:standalone-runtimes`).

## Registry v5

Registry v5 resolves every external enum of every active type: 62 types, 53
active, all of which compute, and 9 deprecated.

- `dns.record.delete.1` and `vendor.onboard.1` receive their first pins
  (the IANA DNS RR TYPE registry; ISO 3166-1 alpha-2 as carried by the IANA
  Language Subtag Registry) and now compute.
- `key.create.2`, `key.rotate.2`, `firewall.rule.open.2`, `pii.export.2`,
  and `phi.disclose.2` pin or inline their sets.
- `payment.refund.2`, `ach.debit.originate.2`, `rx.dispense.2`, and
  `prior.auth.approve.2` use the new `code` field type: a code system URI
  and a registered format that fixes syntax only. CAID never snapshots a
  large, changing, or licensed code system, and never publishes CPT.
- `contract.execute.2` requires both `contract_value` and `currency`;
  `contract.execute.1` stays active for contracts with no monetary value.
- The nine superseded `.1` types are deprecated. Deprecated types still
  resolve, compute, and verify wherever their fields resolve.

Registry v4 is kept byte-identical at `registry/history/action-types.v4.json`,
so every pin of its bytes still holds. `registry/digests.json` lists every
type's `definition_sha256`; a relying party that needs exact reproducibility
pins it. `node caid/registry/check.mjs` checks the registry.

## Registry v4 migration

Registry v4 added an immutable `2026-09-17` SIX ISO 4217 snapshot. A currency
action object whose code is in that snapshot produces the same CAID bytes as
before. A code that registry v3 accepted but the snapshot does not list (for
example `BGN`, `HRK`, or `ZZZ`) is refused under v4. Issuers and verifiers must
move their registry pin from v3 to v4 and supply the referenced snapshot.

What else now refuses, in every implementation:

- a v3-style bare external `values_ref`, and an unresolved or
  digest-mismatched one, whenever the field is present;
- a value outside a compact `inline:` list. The v3-era implementations
  accepted any string there; there are 15 such fields across 15 registered
  types, and local definitions using the form are affected the same way;
- an enum definition in none of the three forms the draft's enum resolution allows,
  including a `values` or `values_ref` member written as `null`; and
- a string or member name containing an unpaired surrogate
  (`unsupported_value`).

Eleven active types could not produce or verify any CAID under registry v4,
because a required field referenced an external code set that had no pinned
snapshot: `payment.refund.1`, `ach.debit.originate.1`, `key.create.1`, `key.rotate.1`, `dns.record.delete.1`, `firewall.rule.open.1`, `pii.export.1`, `rx.dispense.1`, `prior.auth.approve.1`, `phi.disclose.1`, and `vendor.onboard.1`. The registry lists their twelve fields in
`unresolved_external_enums`. Registry v5 resolves all twelve. The ISO 4217
snapshot is List One verbatim, so it also contains codes such as `XXX` (no
currency involved) and `XTS` (reserved for testing); a type that must exclude
them needs its own narrower pinned set in a new type version.

Historical v3 decisions remain v3 decisions. The v4 code refuses v3's bare
external references, so replaying a v3 decision requires the v3 registry and
the pre-v4 implementations together, for example from commit `f46328afc`, the
last `main` commit before registry v4. The version 1 core corpus from that
commit is recorded by digest in `conformance/vectors.json`, as is the
version 2 corpus that preceded the whole-string grammar and integer-field
vectors.
