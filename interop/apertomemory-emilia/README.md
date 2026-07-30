# ApertoMemory / EMILIA Memory-to-Action Composition Profile v0.1

This directory closes two concrete composition outputs discussed with the
ApertoMemory authors:

1. a minimum signed **trust-and-custody result** that an ApertoMemory adapter
   can produce today from the read-time verification semantics in
   `draft-ferro-apertomemory-02`; and
2. a proposed signed **memory-projection record** for the later boundary where
   an adapter commits to the exact ordered bytes it delivered to a caller.

The first record is a composition vector over existing ApertoMemory semantics.
The second is an EMILIA discussion profile; ApertoMemory -02 does not currently
define or claim it.

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
| `AMEM-PROJECTION-RECORD-v0` | A pinned adapter committed to the exact ordered context bytes it emitted, the object-level trust labels used to frame them, and the exclusions it applied | that a model ingested or used those bytes, that an action was authorized, or that an effect occurred |

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

## Output 2: proposed memory-projection record

The projection record is signed only after the exact UTF-8 context bytes are
finalized and hashed, and before (or atomically with) returning those bytes to
the caller. Its ordered `delivered` entries bind each object to the exact
framed fragment placed in context. The top-level `projection` member binds the
complete concatenated byte sequence.

This proves what the adapter emitted under a specific selection policy and
keyring snapshot. It does not prove what any model received internally, paid
attention to, or used.

## Signing boundary

Both records use deterministic canonical JSON from `lib/canonical-json.js` and
Ed25519 with domain separation:

```text
AMEM-EMILIA-TRUST-CUSTODY-RESULT-v0\0 || JCS(record without proof)
AMEM-EMILIA-PROJECTION-RECORD-v0\0    || JCS(record without proof)
```

Every member except `proof` is inside the signature boundary. Verification
uses an adapter public key pinned by the relying party. A public key presented
inside or alongside the record is not a trust anchor.

## Files

- `trust-custody-result.v0.schema.json` — strict JSON Schema for output 1
- `memory-projection-record.v0.schema.json` — strict JSON Schema for output 2
- `apertomemory-source-fixtures.v2.json` — six exact published objects: five
  custody cases plus one projection-support case, with the native expected
  outcomes used by the composition vectors
- `apertomemory-emilia.v1.json` — deterministic positive and negative
  composition vectors plus the pinned adapter key
- `generate.mjs` — deterministic vector generator
- `verify.mjs` — structural, semantic, and signature verifier
- `verify.test.mjs` — positive and hostile mutation tests

## Run

```bash
node interop/apertomemory-emilia/generate.mjs --check
node --test interop/apertomemory-emilia/verify.test.mjs
```

## Status

`AMEM-TRUST-CUSTODY-RESULT-v0` is an EMILIA composition profile over the
published ApertoMemory -02 trust/custody semantics, not an independent
ApertoMemory implementation claim. `AMEM-PROJECTION-RECORD-v0` is proposed
discussion input and is not asserted to be part of ApertoMemory -02.

The provider-neutral runtime control that consumes the projection record lives
in `packages/gate/src/trusted-context.ts`; the first provider plug-in is
`packages/gate/src/apertomemory-context.ts`. See
`docs/protocol/trusted-context-pack-v1.md`. Those modules preserve this
directory's nonclaims and do not turn a projection into authorization.
