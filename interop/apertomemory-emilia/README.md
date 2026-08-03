# ApertoMemory / EMILIA Memory-to-Action Composition Profile v0.2

This directory closes two concrete composition outputs discussed with the
ApertoMemory authors:

1. a minimum signed **trust-and-custody result** that an ApertoMemory adapter
   can produce today from the read-time verification semantics in
   `draft-ferro-apertomemory-02`; and
2. the provider-neutral signed **MEMORY-PROJECTION-RECORD-v1** boundary where
   an adapter commits to the exact ordered bytes it delivered to a caller.

The first record is a composition vector over existing ApertoMemory semantics.
The second implements the wire format in
`draft-ferro-schrock-memory-projection-record-00`. ApertoMemory -02 does not
define or claim that downstream record.

## Independent source authority and reciprocal references

[ApertoMemory](https://datatracker.ietf.org/doc/draft-ferro-apertomemory/)
is an independent IETF Internet-Draft and remains authoritative for sealed
objects, read-time trust, authorship, and custody semantics. This downstream
profile is hosted by EMILIA because it defines the subsequent evidence,
exact-action, admission, and outcome boundaries. It does not incorporate
ApertoMemory into EMILIA or imply an ApertoMemory endorsement.

Publication of this profile requires reciprocal informative references:
EMILIA cites the independent ApertoMemory draft and ApertoMemory may cite this
composition profile. Each implementation and specification remains
independently versioned and governed.

### Confirmed cross-implementation check (2026-07-30)

ApertoMemory independently derived the five native source-fact records from
its reference `open_sealed` implementation before comparing them with the
EMILIA fixtures. The ApertoMemory-owned fixture is pinned at:

- repository: [`apertomemory/apertomemory`](https://github.com/apertomemory/apertomemory)
- path: [`interop/emilia/apertomemory-source-facts.v2.json`](https://github.com/apertomemory/apertomemory/blob/4c44b0c/interop/emilia/apertomemory-source-facts.v2.json)
- commit: [`4c44b0c`](https://github.com/apertomemory/apertomemory/commit/4c44b0c)

That independently generated fixture matched EMILIA commit `961f101f`
field-for-field for vectors 007, 008, 011, 012, and 014 across the exact
sealed-object digest, native trust and authorship results, author/signer key
identifiers, and custody claimed/proven authors. The commitment method also
matched byte-for-byte.

This is dated interoperability evidence for that five-vector trust-and-custody
set. It is not blanket ApertoMemory conformance, does not replace the native
14-vector conformance suite, and establishes none of model use, action linkage,
action authorization, execution, or outcome. Each project keeps its fixture in
its own tree so the comparison can be repeated after either side changes.

### Projection v1 reciprocal check (2026-08-01)

ApertoMemory also produced the Projection v1 source facts and a separate
projection producer without copying the EMILIA generator. The reciprocal
inputs are pinned at:

- source facts: [`apertomemory-source-facts.projection-v1.json`](https://github.com/apertomemory/apertomemory/blob/f5fe9ba5254b3c44c1cd5bc63c7c10bb1b1fc5a0/interop/emilia/apertomemory-source-facts.projection-v1.json), commit [`f5fe9ba`](https://github.com/apertomemory/apertomemory/commit/f5fe9ba5254b3c44c1cd5bc63c7c10bb1b1fc5a0), matched against EMILIA `c737f37277c85117ff05963ed6f8f14d03c5e6b3`; and
- independent producer: [`projection_producer.py`](https://github.com/apertomemory/apertomemory/blob/7439e6b6f001ad1a86644f69786a9c6b9411aa4f/interop/emilia/projection_producer.py), commit [`7439e6b`](https://github.com/apertomemory/apertomemory/commit/7439e6b6f001ad1a86644f69786a9c6b9411aa4f).

The two independently written producers first converged byte-for-byte on one
frozen positive example. That exercise exposed two `-00` underspecifications:
the exact `urn:apertomemory:context-frame:v0` bytes and the native keyring
trust-snapshot serialization.

Andrea Ferro subsequently defined both source-owned profiles and corrected an
internal trust-snapshot example before review. EMILIA independently checked
the corrected commit and adopted it as the reciprocal source boundary:

- corrected ApertoMemory profile commit: [`48be525`](https://github.com/apertomemory/apertomemory/commit/48be5250f26aea9e34bc4f8adaca22ac9016cc84)
- [`apertomemory-context-frame-v0-profile.md`](https://github.com/apertomemory/apertomemory/blob/48be5250f26aea9e34bc4f8adaca22ac9016cc84/interop/emilia/apertomemory-context-frame-v0-profile.md) ratifies the existing fragment bytes, including `author_key=none`; and
- [`apertomemory-trust-snapshot-profile.md`](https://github.com/apertomemory/apertomemory/blob/48be5250f26aea9e34bc4f8adaca22ac9016cc84/interop/emilia/apertomemory-trust-snapshot-profile.md) replaces the provisional JSON/base64url snapshot with canonical CBOR, raw eight-byte key identifiers, and raw-byte ordering.

The EMILIA vectors now use those normative bytes. The context fragments remain
unchanged; the trust-snapshot bytes, digest, record signature, and reciprocal
record change as required. The worked CBOR bytes and digests reproduce the
ApertoMemory profile at `48be525`, including the raw-byte-vs-base64url ordering
discriminator and the empty accepted-key case. This is profile-level reciprocal
evidence for the checked cases, not blanket ApertoMemory conformance. It proves
none of model use, action authorization, execution, or outcome.

## Exact source commitment

The source commitment is SHA-256 over the complete deterministic-CBOR sealed
object exactly as supplied by ApertoMemory. The mandatory map has keys 1-4;
the data model also permits reserved OPTIONAL key 5 (`dek_wrap_ref`). The
commitment therefore covers every source byte and every map member actually
present, rather than assuming that only keys 1-4 can occur or reserializing the
object through an EMILIA JSON representation.

The portable records deliberately do not repeat cleartext `id` or `scope_id`:
the digest is the only object linkage. This avoids turning stable source
identifiers into a cross-context correlation surface. For official vector 007,
the committed input is exactly 278 published bytes and the required digest is
`sha256:025672610783f255e7b0866325796200f85eded589462522f6e0cf6516f63620`.

ApertoMemory's native key identifiers are eight-byte values rendered as hex in
its vectors. Fields ending in `_b64u` are explicitly an EMILIA composition
representation of those same eight bytes, not an ApertoMemory wire-format
claim. The adapter neither invents nor substitutes key identifiers for the
source-anchored cases.

## Boundary

The records deliberately keep four questions separate:

| Record | Establishes | Does not establish |
| --- | --- | --- |
| `AMEM-TRUST-CUSTODY-RESULT-v0` | A pinned adapter verified one sealed object under a named read-time keyring snapshot and reported the native trust, authorship, custody, and AI-boundary classification | model ingestion, model weighting, action linkage, action authorization, execution, or outcome |
| `AMEM-PROJECTION-RECORD-v0` | Frozen provider-specific discussion input that preceded the joint draft | v1 conformance or any model/action/outcome claim |
| `MEMORY-PROJECTION-RECORD-v1` | A pinned adapter committed to the recall request, selection policy, native trust snapshot, exact source-object bytes, ordered fragment bytes, complete emitted projection, and closed exclusion counts | that a model ingested or used those bytes, that an action was authorized, or that an effect occurred |

The later EMILIA join binds a CAID or other action evidence to the projection
digest. The projection record itself carries no CAID and makes no action claim.

## Output 1: minimum trust-and-custody result

The positive vector exercises the ApertoMemory v2 custody path rather than the
simpler owner-key path:

- the currently verified signer is the vault owner that resealed the object;
- the custody record preserves the original claimed author key and a proven
  original author key;
- the proven original author key is accepted by the current read-time keyring;
- the derived result is therefore `trusted` with `attested` authorship; and
- the reported author is the proven original author, not the resealing vault
  owner.

The result also binds a digest of the current keyring snapshot. This is
required because ApertoMemory trust is derived at read time and may change when
the vault owner's accepted-key set changes.

`custody_present` is a composition-layer derived fact: it reports whether the
adapter encountered a custody map while evaluating the object, including an
empty malformed map that must degrade without aborting recall. It is
not represented as an assertion from vector 007's native `expect` block. The
native assertions remain `trust`, `authorship`, `author_key_id`, and
`signer_key_id`.

Custody field 3 (`migrated_at`) remains inside the encrypted ApertoMemory
payload. It is not re-exported as cleartext `resealed_at` in either portable
composition record. The adapter carries only the minimum custody facts needed
to preserve the read-time authorship decision.

The first source-fidelity acceptance set has the following exact pairing:

| Official v2 vector | Native case |
| --- | --- |
| `007-custody-attested` | positive custody-attested result; the proven original author is reported rather than the resealing custodian |
| `008-custody-unproven` | custody lacks field 4; result degrades to unverified/unknown with no proven author |
| `011-custody-from-non-owner-MUST-NOT-BE-HONOURED` | a non-owner signer attempts to assert custody; result degrades to unverified/unknown |
| `012-custody-naming-an-unaccepted-key` | accepted signer names an author absent from the current keyring; result degrades to unverified/unknown |
| `014-empty-custody-map` | malformed/empty custody map degrades without aborting the remaining recall |

## Output 2: provider-neutral memory-projection record v1

The projection record is signed only after the exact UTF-8 context bytes are
finalized and hashed, and before (or atomically with) returning those bytes to
the caller. Its ordered `delivered` entries bind each object to the exact
framed fragment placed in context. The top-level `projection` member binds the
complete concatenated byte sequence.

The full verifier recomputes the exact recall-request, selection-policy,
source-profile trust-snapshot, source-object, fragment, and complete-projection
commitments. It also requires a source-profile verifier result for every
delivered entry and proves that the ordered fragments byte-concatenate to the
supplied complete projection. The envelope-only verifier is deliberately
separate: it verifies the closed record, adapter signature, current pinned key,
freshness, and nonclaims when a downstream Gate receives commitments but not
plaintext memory.

This proves what the adapter emitted under a specific selection policy and
trust snapshot. It does not prove what any model received internally, paid
attention to, or used.

## Signing boundary

The trust/custody result and frozen v0 record retain their original domains.
The neutral v1 record uses the exact domain from the joint draft:

```text
AMEM-EMILIA-TRUST-CUSTODY-RESULT-v0\0 || JCS(record without proof)
AMEM-EMILIA-PROJECTION-RECORD-v0\0    || JCS(record without proof)
MEMORY-PROJECTION-RECORD-v1\0          || JCS(record without proof)
```

Every member except `proof` is inside the signature boundary. Verification
uses an adapter public key pinned by the relying party. A public key presented
inside or alongside the record is not a trust anchor.

## Files

- `trust-custody-result.v0.schema.json` — strict JSON Schema for output 1
- `memory-projection-record.v0.schema.json` — strict JSON Schema for output 2
  legacy compatibility
- `../../public/schemas/memory-projection-record-v1.schema.json` — public
  provider-neutral v1 JSON Schema
- `apertomemory-source-fixtures.v2.json` — six exact published objects: five
  custody cases plus one projection-support case, with the native expected
  outcomes used by the composition vectors
- `apertomemory-emilia.v1.json` — frozen v0 composition vectors retained for
  compatibility
- `memory-projection-record.v1.vectors.json` — deterministic reciprocal v1
  package with exact verification material, pinned adapter policy, one positive
  path, eighteen hostile cases, and three source-profile vectors under the
  normative ApertoMemory context-frame and trust-snapshot v0 profiles
- `generate.mjs` — deterministic vector generator
- `generate-memory-projection-v1.mjs` — deterministic v1 reciprocal-vector
  generator
- `verify.mjs` — structural, semantic, and signature verifier
- `verify.test.mjs` — positive and hostile mutation tests
- `../../packages/verify/src/memory-projection.ts` — neutral v1 producer,
  envelope verifier, and full verifier

## Run

```bash
node interop/apertomemory-emilia/generate.mjs --check
node interop/apertomemory-emilia/generate-memory-projection-v1.mjs --check
npm run memory-projection:conformance
```

## Status

`AMEM-TRUST-CUSTODY-RESULT-v0` remains an EMILIA composition profile over the
published ApertoMemory -02 trust/custody semantics, not an independent
ApertoMemory implementation claim. `AMEM-PROJECTION-RECORD-v0` remains frozen
discussion input and is not asserted to be part of ApertoMemory -02.

The EMILIA tree now implements the neutral v1 field set, domain, producer,
envelope verifier, full byte verifier, source-profile callback boundary,
single-use registry hook, Gate consumer path, and reciprocal hostile vectors.
ApertoMemory has independently reproduced the source facts and positive
projection example and has made the exact context-frame and trust-snapshot
profiles normative on its side. EMILIA's vectors implement those profiles at
the pinned commit. The hostile cases have not all been reproduced by the second
implementation, so this remains bounded reciprocal evidence rather than a
blanket interoperability or conformance claim. The already-published `-00`
artifact remains unchanged; its historical implementation-status text was
accurate when published.

The provider-neutral runtime control that consumes the projection record lives
in `packages/gate/src/trusted-context.ts`; the first provider plug-in is
`packages/gate/src/apertomemory-context.ts`. See
`docs/protocol/trusted-context-pack-v1.md`. Those modules preserve this
directory's nonclaims and do not turn a projection into authorization.
