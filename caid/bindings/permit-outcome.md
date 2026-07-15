# CAID binding note: permit receipts + execution outcome attestation

Status: PRIVATE draft, grounded, NOT submitted. Per DESIGN.md section 9, no
PR, no issue, no post leaves this directory without Iman's go.

Grounding: both drafts fetched 2026-07-08 from:
- https://www.ietf.org/archive/id/draft-lee-orprg-permit-receipts-00.txt
  (Lee, Meridian Verity Group: "Permit Receipts for Permit-Before-Commit
  Authorization of AI-Agent and Workload External Effects")
- https://www.ietf.org/archive/id/draft-morrow-sogomonian-exec-outcome-attest-00.txt
  (Morrow and Sogomonian, AI Internet Foundation: "Execution Outcome
  Attestation for AI Agents and Automated Systems")

All claims below trace to the fetched text; one quoted anchor per draft.

Scope, stated up front: CAID carries no trust semantics. It proves two
artifacts reference the same typed action content. It does not prove the
action was authorized, executed, safe, or wise. Each artifact below still
verifies inside its own trust boundary under its own spec.

## 1. How each draft references the action

### draft-lee-orprg-permit-receipts-00

The permit's whole binding story runs through a digest over a canonical
form of the request. Section 2 defines the action digest as a digest
computed over the canonical request representation, and defines that
representation as a deterministic encoding of the effect-relevant fields
under a selected canonicalization profile. Section 7's abstract data model
makes the binding mandatory:

> "The PermitReceipt MUST bind authorization to either an action digest, a
> cryptographic commitment to the canonical request representation, or
> both."

The model carries `action_digest` and `canonicalization_profile` fields
(Section 7), and Section 9 requires the digest to be computed per the
selected profile and the receipt to identify or be bound to that profile.
What the draft leaves abstract, per the fetched text, is the profile
itself: the profile slot is an identifier or digest, and the draft does not
supply a concrete registry saying which fields are effect-relevant for a
given kind of action.

### draft-morrow-sogomonian-exec-outcome-attest-00

The receipt's semantic core is `outcome_claim`, structured in Section 3.1
as {status, outputs, completion_timestamp, outcome_detail}; the draft says
it is what distinguishes an execution receipt from a mere invocation log.
It attests the ACTUAL outcome as asserted by the executing system. The
execution it attests about is identified by `invocation_id`, defined in
Section 3.1 as a globally unique identifier for the specific action
request. As fetched, that is an identifier of the request instance, not a
recomputable digest of the requested action's content. Section 8.3 then
deliberately scopes comparison out of the format:

> "Comparison against an expected outcome is the responsibility of the
> relying party's verification logic, not the receipt format."

## 2. Where the CAID goes

### In the permit receipt (lee)

CAID drops into the slot the draft already reserves. Register the CAID
suite as a canonicalization profile: profile = CAID action object rules
plus jcs-sha256 (RFC 8785 -> SHA-256). Then:

- `action_digest` = the CAID digest bytes (b64url of the same SHA-256).
- `canonicalization_profile` = the CAID type + suite, or simply carry the
  full `caid:1:<action_type>:<suite>:<digest>` string, which packs profile
  identification and digest into one field and satisfies Section 9's
  requirement that the receipt identify the profile used at issuance.

No wire change to the draft's model is needed; CAID is a concrete profile
for a field the model already mandates. CAID deliberately uses no domain
separation prefix (DESIGN.md section 2) precisely so an issuer that
already digests canonical bytes can adopt the identical digest.

### In the outcome attestation (morrow)

Add one field next to `invocation_id`: the CAID of the requested action
object (e.g. `action_caid`). `invocation_id` keeps identifying the request
instance; the CAID identifies the typed content of what was requested.
The two are complementary: instance identity vs content identity. The
attestation's trust story (who asserts the outcome, how it is signed) is
untouched; CAID adds a join key, nothing more.

## 3. The joint win

With both artifacts carrying the same CAID, a permit (lee), a
human-authorization receipt (for example an EMILIA Protocol receipt over
the same action object), and an outcome attestation (morrow) about ONE
action become a composable evidence set with zero bilateral negotiation.
No author pair has to read the other's spec, adopt the other's trust
model, or agree on a schema. Each artifact still verifies under its own
spec, in its own trust boundary; composition joins on identifier equality
and never ingests another verifier's evidence.

Morrow Section 8.3 is the sharpest case for this. It explicitly leaves
expected-vs-actual comparison to the relying party. Today that relying
party holds an outcome receipt keyed by an opaque, deployment-scoped
invocation_id and has no format-independent way to say which "expected"
the actual should be compared against. A shared CAID is what makes that
comparison well-defined across formats: expected = the action object the
permit's action_digest bound, actual = the outcome_claim in the
attestation carrying the same CAID. The relying party checks string
equality of two CAIDs and then runs each artifact's own verifier. The
comparison morrow scoped out of the receipt format becomes a one-line join
instead of a bilateral integration project.

## 4. Unilateral gain per author

### Lee gains, with zero counterparties

Section 7 mandates a digest binding and Section 9 mandates naming the
profile, but the draft does not itself define which fields are
effect-relevant for a given action. That is exactly the failure CAID's
material-fields validation closes: a digest over {action:"wire"} binds
nothing, and nothing in an abstract profile slot stops an issuer from
minting it. Adopting CAID gives lee a ready-made, versioned profile
family: typed action objects, REQUIRED material fields per type, amounts
as strings, cross-language deterministic bytes via JCS. The permit gets
harder to issue vacuously even if no other artifact on earth ever carries
a CAID.

### Morrow gains, with zero counterparties

An outcome receipt keyed only by invocation_id is legible to the system
that minted the invocation_id and nobody else. Adding the requested
action's CAID makes every attestation independently anchorable: any
relying party holding the action object can recompute the CAID offline and
know which typed content the outcome_claim is about, without the invoking
system's cooperation. It also gives Section 8.3's relying-party comparison
a stable "expected" anchor inside morrow's own ecosystem, before any
cross-spec composition exists.

## 5. PR-ready pitches (NOT submitted; gated on Iman's go)

### To draft-lee-orprg-permit-receipts

Section 7 requires binding the PermitReceipt to an action digest over a
canonical request representation, and Section 9 requires identifying the
canonicalization profile, but the profile itself is left abstract. We
built a concrete profile that fits the slot as-is: CAID, a typed action
object with per-type REQUIRED material fields, canonicalized with RFC 8785
JCS and digested with SHA-256, identified by one compact string. It closes
the vacuous-digest case where an issuer digests an object naming no
effect-relevant fields, and it makes the same digest reusable by
authorization receipts and outcome attestations about the same action.
CAID carries no trust semantics; your verification model is untouched.

### To draft-morrow-sogomonian-exec-outcome-attest

Section 8.3 leaves expected-vs-actual comparison to the relying party,
which is the right call, but the receipt gives that relying party only an
opaque invocation_id to anchor the comparison. We propose one optional
field alongside it: the CAID of the requested action, a compact identifier
over a typed, canonicalized (RFC 8785 JCS, SHA-256) action object with
per-type required material fields. Any relying party holding the request
content can recompute it offline, so the outcome_claim becomes comparable
against a well-defined "expected" without the invoking system in the loop,
and joinable with permits and authorization receipts binding the same
digest. CAID carries no trust semantics; your attestation is unchanged.
