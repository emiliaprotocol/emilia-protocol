<!-- SPDX-License-Identifier: Apache-2.0 -->
# Hostile COAZ/AuthZEN translation vector, v0.1

Status: source-pinned discussion artifact. It is not an Internet-Draft, an
AuthZEN or COAZ specification, an interoperability claim, or an independent
implementation result. Running it externally reproduces the pinned checks; it
is not an independent implementation.

This artifact demonstrates, executably, one property of the cross-format
translation surface that the OpenID AuthZEN COAZ work opens up:

> A well-formed MCP-to-AuthZEN translation can drop a consequential tool-call
> argument, so that two materially different source actions construct
> byte-identical AuthZEN Access Evaluation requests. A PDP that decides on the
> constructed tuple cannot distinguish the two source actions, and nothing in
> the base Authorization API or the COAZ framework requires the translation to
> be faithful to the full source action. A canonical action identifier (CAID)
> computed over the full typed source action and carried in request context
> closes the gap: the two source actions then yield different CAIDs, and a
> relying check at the enforcement boundary refuses the substituted action with
> a named reason, without changing the PDP.

## What was fetched

The COAZ profile was fetched and read in full. The former single document at
`authzen-mcp-profile-1_0.html` now states verbatim: "This draft has been
superseded and is retained only as a pointer to its replacements." Its content
is split into two Draft 1 documents, both published 13 February 2026 by the
OpenID AuthZEN Working Group, both fetched and read here:

- COAZ Framework (`authzen-coaz-framework-1_0.html`)
- COAZ-MCP binding (`authzen-coaz-mcp-binding-1_0.html`)

The exact fetched bytes, their SHA-256, the OpenID AuthZEN repository head, and
the refresh date are pinned in [`source-lock.json`](./source-lock.json).
AuthZEN Authorization API 1.0 Final was refreshed with the COAZ sources on
2026-08-25.

The bounded upstream change proposed from this reproduction is recorded in
[`AUTHZEN-CONTRIBUTION.md`](./AUTHZEN-CONTRIBUTION.md). It remains a local
proposal. It has not been submitted to, reviewed by, or accepted by OpenID
AuthZEN.

## The translation surface, anchored to the pinned text

COAZ is a projection from a protocol's inputs into an AuthZEN request. The COAZ
Framework abstract states its purpose verbatim: "the inputs of an incoming
operation are projected, through a declarative mapping, into an AuthZEN
Authorization API request". The framework fixes the output and specializes the
input: "The output side is fixed" and "The input side is specialized."

The mapping is a template whose leaf values are literals or expressions. The
framework's expression contract (Section 2.6) states verbatim that an
expression "MUST evaluate to a single JSON value ... or to the distinguished
value absent. A value is used as the value of the field in which the expression
appears; absent causes that field to be omitted from the constructed request
entirely."

Two facts from the pinned text are what this vector turns on:

1. The only "lossless" requirement anywhere in the framework is on the
   literal-versus-expression discriminator, not on the projection. Section 2.5
   states verbatim: "The distinction MUST be lossless." That sentence is about
   telling a literal apart from an expression. There is no requirement that the
   projection carry every source argument into the request. A mapping author is
   free to omit a field, and the framework explicitly provides `absent` for
   exactly that.

2. The base decision is a boolean over the constructed tuple. AuthZEN
   Authorization API 1.0 Final, Section 5.5 (quoted in
   `caid/bindings/authzen-acta.md`): "Decision is an object that contains a
   REQUIRED decision key with a boolean value, and an OPTIONAL context key with
   an object value." The PDP decides on the SARC tuple it is shown. If two
   different source actions produce the same tuple, the PDP returns the same
   decision for both, correctly, because it never saw the difference.

The material parameters of an AuthZEN action ride in `action.properties` and
`resource.properties`. AuthZEN Section 5.3 (quoted in the binding note): an
Action "contains a REQUIRED name key with a string value, and an OPTIONAL
properties key with an object value", and Section 5.3.1: "Such attributes can
include, but are not limited to, parameters of the action that is being
requested." A COAZ mapping decides which source parameters become those
properties; the ones it does not map are simply absent from the tuple.

## The demonstration

`run.mjs` is a self-contained runner over `vectors.json`. Nine cases, four
legs. Run it:

```bash
node conformance/composition/coaz-translation-v0.1/run.mjs
```

or as a test:

```bash
npx vitest run conformance/composition/coaz-translation-v0.1/run.test.mjs
```

The boundary is a payment release: a `tools/call` to a `release_payment` tool
whose consequential argument is `beneficiary_account`. The account identifier
appears only as a digest, never as cleartext, matching the `payment.release.1`
registered type in `caid/registry/action-types.json`.

Two pinned mappings drive the translation:

- The **default `tools/call` mapping**, copied verbatim from COAZ-MCP Section
  7.2. It maps `resource.id` to `$params.name` (the tool name) and carries no
  arguments at all into the tuple. Every argument is dropped by construction.
- A **declared mapping** authored for this vector in the exact style of the
  binding's Section 6 and Section 8 examples. It maps `amount`, `currency`, and
  the instruction id (the fields a threshold policy consumes) and does not map
  `beneficiary_account`. It is well-formed under the binding's rules; nothing in
  the pinned framework or binding text rejects it.

The toy PDP (`toyPdpDecide`) is explicitly labeled: it decides on the tuple it
is shown and stands in for any spec-conformant PDP. It applies a plausible
threshold policy (permit `release_payment` at or below 20000). No real PDP
product is exercised, and no deployed PDP is claimed vulnerable.

### Leg (a): baseline

`default-mapping-benign-allowed` and `declared-mapping-benign-allowed`: a benign
call translates under each mapping and the toy PDP permits it. This establishes
that the mappings are functional.

### Leg (b): semantic substitution

`default-mapping-substituted-identical-tuple` and
`declared-mapping-semantic-substitution-identical-tuple`: a second call differs
only in `beneficiary_account` (a different payee). The runner asserts, using the
same RFC 8785 canonicalizer the CAID suite uses, that the constructed AuthZEN
tuple is byte-identical to the baseline tuple while the source actions are NOT
byte-identical. The toy PDP permits the substituted call too, because the tuple
it sees is the same. Consent to pay payee A has become consent to pay payee B
with no observable difference at the PDP.

### Leg (c): field reclassification

`declared-mapping-field-reclassification-identical-tuple`: the consequential
argument is moved into an unmapped `notes` bag. It survives translation
unnoticed: the tuple is byte-identical to the baseline and the toy PDP permits
it. A field the mapping does not read cannot affect the decision.

### Leg (d): the close

The same translator additionally emits `context.caid`, a CAID computed over the
full typed source action, using the repository's real CAID implementation
(`caid/impl/js/caid.mjs`, `computeCaid`), not a reimplementation. Placement
follows `caid/bindings/authzen-acta.md`: request `context` is the request-scoped
bag (AuthZEN Section 5.4, quoted there: "Context is an object which can be used
to express attributes of the environment"), and the identifier "carries no trust
semantics and changes no evaluation behavior."

- `caid-close-benign-admitted`: the benign call carries its CAID; the relying
  check (holding the approved typed action) admits it.
- `caid-close-semantic-substitution-refused`: the substituted call carries a
  DIFFERENT CAID (the two computed CAIDs are pinned in `vectors.json` and
  asserted distinct). The toy PDP still permits the tuple, but the relying check
  refuses with `caid_mismatch:beneficiary_account`, naming the exact field.
- `caid-close-field-reclassification-refused`: the reclassified call has no
  well-typed `beneficiary_account` on the source action, so `computeCaid`
  refuses; the translator returns
  `caid_refused:missing_material_field:beneficiary_account` and never calls the
  PDP. Fail-closed as a refusal with a reason, proven against the bad input, not
  a crash.
- `caid-close-malformed-identifier-refused`: a tampered `context.caid` is
  refused with `caid_invalid:malformed_caid`. The test also drives the relying
  check with several junk identifiers (empty string, non-string, wrong-length
  digest) and confirms each returns a named refusal rather than throwing.

The CAID changes no PDP behavior: one test asserts the toy PDP returns the same
decision with and without the identifier present. The identifier does its work
at the relying boundary, not inside the PDP.

## Exactly what is and is not claimed

- This shows that the translation surface **admits** lossy mappings that a PDP
  cannot detect absent a content identifier. It does **not** show that any
  deployed translator, gateway, or PDP is lossy or vulnerable. The lossy
  mappings here were authored for this vector.
- The default `tools/call` mapping dropping arguments is not a COAZ defect; it
  is the correct coarse-grained default, and the binding provides declared
  mappings precisely so a server can map the parameters that matter. The point
  is narrower: whether coarse or fine, a mapping that omits a consequential
  field leaves the PDP deciding on a tuple that does not commit to that field,
  and nothing in the base surface makes that omission observable downstream.
- A CAID proves that two artifacts reference the same typed content. Per
  `caid/impl/js/caid.mjs` and the binding note, it "carries no trust
  semantics." It does not prove the action was authorized, executed, safe, or
  wise, it names no humans, and it replaces no verifier. The relying check here
  is a content-identity gate, not an authorization decision.
- VERIFIED is not ACCEPTED: `verifyCaid` returning valid means the observed
  action recomputes to the presented identifier, nothing more. The admit or
  refuse verdict in leg (d) is a separate content-equality check against the
  relying party's own pinned approved action.

## Files

- `README.md` (this file)
- `AUTHZEN-CONTRIBUTION.md` bounded candidate text and claim boundary
- `run.mjs` runnable demonstration and corpus runner (exit 0 on all-pass)
- `run.test.mjs` vitest suite
- `vectors.json` the pinned case set and computed CAIDs
- `source-lock.json` fetched spec bytes and local load-bearing file digests
