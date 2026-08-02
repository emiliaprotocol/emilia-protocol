# EMILIA Trusted Context Pack v1

Status: implemented product profile; not an Internet-Draft, RFC, independent
ApertoMemory conformance result, or claim that a model used particular context.

## Purpose

Persistent memory is an input to consequential agent actions. A native memory
format can establish confidentiality, integrity, provenance, and the context
bytes a local adapter emitted. It does not decide whether a relying party may
let a particular action execute now.

The Trusted Context Pack supplies that missing control without becoming a
memory vendor:

```text
native memory provider
  -> provider-owned verification
  -> signed projection commitment (digests and exclusions, never plaintext)
  -> signed context-to-action binding
  -> AEC evidence satisfaction under relying-party policy
  -> separate Gate authorization and one-time admission
  -> independently verified execution and outcome continuity
```

ApertoMemory is the first provider plug-in. The Gate kernel remains
provider-neutral.

The source format is the independent IETF Internet-Draft
[`draft-ferro-apertomemory`](https://datatracker.ietf.org/doc/draft-ferro-apertomemory/).
ApertoMemory remains independently governed and authoritative for its native
format and read-time semantics. The downstream Memory-to-Action Composition
Profile is hosted by EMILIA because EMILIA owns the evidence-to-action and
consequence boundary. The profile requires reciprocal informative references;
neither reference makes one project a component of, or an endorsement by, the
other.

## Three separate decisions

| Decision | Result | Does not establish |
| --- | --- | --- |
| Native projection verification | `VERIFIED`, `NOT_VERIFIED`, or `INDETERMINATE` | action authorization or execution |
| AEC composition | whether `ep-memory-projection` satisfies one pinned evidence role for the exact action | local authorization |
| Continuity | `CONTINUOUS`, `BROKEN`, or `INDETERMINATE` across projection, action, execution, and outcome digests | that any unverified evidence is authentic |

Every result carries `authorizes: false`. The executor remains the sole owner
of local authorization and consequence custody.

## Exact-action binding without a digest cycle

The provider projection exists before the final action contains its context
reference. Binding the complete action into the projection would create a
cycle: the action would contain the projection digest while the projection
contained the action digest.

`EP-TRUSTED-CONTEXT-BINDING-v1` breaks that cycle explicitly:

1. Compute `action_subject_digest` over the exact action with only its
   `trusted_context` member omitted.
2. Sign that digest together with the provider/profile, complete signed
   projection-record digest, projected-byte digest, policy digest, nonce, and
   validity window.
3. Put the signed binding digest and both projection digests into the action's
   closed `trusted_context` member.
4. Compute the ordinary action digest and CAID over the resulting complete
   action.

The relying party compares the signed nonce with the current admission
challenge. The projection therefore cannot be replayed into a different
admission or for a different material action. Replay of the same complete
admitted action remains the responsibility of Gate's durable
admission/consumption store.

## Relying-party policy

The constructor-pinned policy controls:

- accepted provider and source profile;
- maximum projection age;
- maximum provider-keyring age;
- maximum signer-status age and whether current status is mandatory;
- allowed delivered trust classes;
- allowed exclusion reasons and maximum excluded-object count; and
- the policy digest signed into the context-to-action binding.

The current admission nonce, verification time, key directories, and signer
status sources are also constructor-pinned. Caller mutation of a supplied key
directory cannot alter the evaluator after construction.

The presenter supplies only the provider record and signed binding. It cannot
supply keys, policies, verifier functions, status snapshots, or trust roots at
transaction time.

## ApertoMemory provider boundary

`createApertoMemoryContextProvider()` verifies the signed provider-neutral
`MEMORY-PROJECTION-RECORD-v1` envelope under relying-party-pinned adapter keys
and current status. It retains explicit compatibility with the frozen
`AMEM-PROJECTION-RECORD-v0` discussion artifact. It preserves ApertoMemory
-02's material semantics:

- trust is derived at read time under the current keyring;
- ordered projection entries bind sealed-object and framed-fragment digests;
- exclusions are explicit and counted;
- non-`self` content is data, not instructions; and
- the record does not claim model ingestion, weighting, action authorization,
  execution, or outcome.

The Gate provider performs the v1 **signed-envelope** verification scope. It
does not receive plaintext context or source objects and therefore does not
claim to have rehashed those commitment preimages. The full neutral verifier
in `@emilia-protocol/verify/memory-projection` separately requires the exact
request, policy, trust snapshot, source objects, fragments, complete projection,
and one native source-verifier result per entry. It refuses when the supplied
fragments do not byte-concatenate to the supplied projection.

The provider plug-in does **not** decrypt `.amem` objects or independently
implement the raw CBOR/COSE format. Native format verification remains owned by
the ApertoMemory consumer. The checked-in `v0` record is a composition profile
over the source draft, not an ApertoMemory standard or endorsement. The v1
record is provider-neutral and its ApertoMemory source fields remain governed
by ApertoMemory's native verifier.

For source commitments, the adapter hashes the exact complete sealed-object
CBOR supplied by ApertoMemory. Keys 1-4 are mandatory and reserved OPTIONAL key
5 (`dek_wrap_ref`) may also be present; all present source bytes are covered.
The composition field `custody_present` is adapter-derived and is not presented
as a native assertion from vector 007. The source-fidelity acceptance cases are
paired exactly as 007 (positive custody), 008 (unproven custody), 011
(non-owner signer), 012 (unaccepted named author), and 014 (empty/malformed
custody map with recall isolation).

## Privacy boundary

Gate receives signed records and digests. The runtime evidence envelope does
not carry decrypted memory, prompt text, embeddings, passphrases, DEKs, KEKs,
or raw context bytes. Provider-native evidence remains on the provider side of
the boundary unless a deployment deliberately retains it under its own data
governance controls.

## Failure behavior

Cryptographic mutation, provider/profile mismatch, action substitution,
forbidden trust classes, forbidden exclusions, revoked signers, and expired
bindings are `NOT_VERIFIED`. Missing or stale current-status information and a
provider verification outage are `INDETERMINATE`. Both states refuse the AEC
evidence role and therefore cannot unlock execution.

## Implementation

- provider-neutral kernel: `packages/gate/src/trusted-context.ts`
- ApertoMemory provider: `packages/gate/src/apertomemory-context.ts`
- signed source records: `interop/apertomemory-emilia/`
- neutral producer/verifier: `packages/verify/src/memory-projection.ts`
- v1 schema: `public/schemas/memory-projection-record-v1.schema.json`
- reciprocal v1 vectors:
  `interop/apertomemory-emilia/memory-projection-record.v1.vectors.json`
- hostile tests: `packages/gate/trusted-context.test.ts`
- package exports: `@emilia-protocol/gate/trusted-context` and
  `@emilia-protocol/gate/trusted-context/apertomemory`

## Commercial packaging

This is a control inside the existing protected-workflow offer, not a new
memory-object SKU: the 60-day Amelia I Diagnostic identifies and attacks one
memory-to-action workflow; Gate Implementation installs the provider verifier,
policy, exact-action binding, and reconciliation; Operated Gate runs the
deployment-specific control. Pricing remains governed by
`lib/commercial-offer.ts`.

## Remaining deployment evidence

The five-vector ApertoMemory trust-and-custody source-fact subset has now been
derived independently in the ApertoMemory tree and matched field-for-field
against the EMILIA composition fixtures; the reciprocal references and exact
limits are recorded in `interop/apertomemory-emilia/README.md`. This does not
constitute blanket ApertoMemory conformance or independent reproduction of its
full 14-vector native conformance suite by this provider plug-in.

The EMILIA-side v1 producer, full verifier, Gate envelope consumer, and hostile
vectors are implemented. Reciprocal v1 execution by ApertoMemory or another
independently governed implementation remains pending, so no independent v1
interoperability claim is made.

No live customer memory system is connected. Production claims still require a
real provider adapter deployment, durable Gate admission state, managed
key/status operations, independently governed execution/outcome evidence, and
customer-specific privacy and retention approval.
