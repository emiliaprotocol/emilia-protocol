# EP Portable State Handoff v0.1

Status: public experimental implementation profile. This document is not an
Internet-Draft, an adopted standard, a production deployment, or evidence of an
external implementation.

Implementation family name: **EMILIA Vortex**. The wire profile uses the
descriptive name `EP-PORTABLE-STATE-HANDOFF-v0.1`. “Vortex Protocol” is not the
standards name because that name already appears in unrelated protocol work.

## 1. Purpose

This profile lets one system offer a bounded set of portable state objects to a
named recipient, lets the source release that exact set under EMILIA authority,
and lets the recipient atomically admit and commit the set under its own EMILIA
authority.

The protocol answers five questions:

1. What exact objects did a pinned source assert and sign?
2. Which declared objects were required, optional, present, missing, or
   unsupported?
3. Did the source consequence boundary release this exact manifest to this
   exact recipient?
4. Did the recipient consequence boundary consume exact import authority and
   commit the accepted state in one local atomic transition?
5. What terminal result did the pinned recipient report?

The protocol does not answer whether the state is true, whether a mutable
source was fresh when read, whether the signed set contains everything the
source held, whether a tombstone erased every copy, or whether any later action
was authorized.

### 1.1 Threat model

The bundle and transport are untrusted. An adversary may mutate, omit, insert,
reorder, replay, delay, or redirect artifacts; substitute an agent, boundary,
action, algorithm set, or payload profile; race recipient state; suppress a
commit acknowledgement; and place authority-shaped data inside a payload.

The profile assumes locally pinned verification keys and payload adapters, a
source AEB that can evidence consumed release authority, and a recipient AEB
with one durable atomic state domain. It does not survive compromise of those
pinned roots, make a dishonest source truthful, protect state after a recipient
imports it, or turn a process-local reference store into a durable transaction.

## 2. Four invariants

### 2.1 State is not authority

A payload object, manifest, index, handoff receipt, memory, policy statement,
or imported credential never becomes reusable permission to act. The recipient
can use imported state as input to a later decision, but every consequential
action still requires its own exact EMILIA admission.

### 2.2 Source release and recipient import are different actions

The source consumes `agent.state.export.1`. The recipient consumes
`agent.state.import.1`. Neither receipt substitutes for the other. The source
cannot authorize a recipient’s local state change, and the recipient cannot
retroactively authorize the source disclosure.

### 2.3 Recipient authority and state commit share one atomic boundary

The recipient MUST recheck current state heads, verify and consume the exact
import action, write the accepted object bytes and new heads, and persist the
admission record in one authoritative local transaction. A design that consumes
authority in one store and later writes state in another does not conform.

### 2.4 Unknown stays unknown

Unsupported required profiles, missing lineage anchors, generation gaps,
unavailable vault state, head changes during commit, and lost commit
acknowledgements are `INDETERMINATE`. They are never silently accepted and never
permission for a blind retry.

## 3. Roles

* **Source agent** constructs and signs the manifest.
* **Source consequence boundary**, named by `source_boundary_id`, verifies and consumes the exact export and,
  when applicable, vault-key release actions.
* **Recipient agent** receives the bundle.
* **Recipient consequence boundary**, named by `recipient_boundary_id`, owns
  import authority, the atomic state transaction, and the import-receipt key.
* **Relying party** pins identities, keys, payload profiles, and local policy.
* **Payload adapter** validates one carrier-specific state object without
  acquiring authority semantics.

Workload identity can authenticate a source or recipient process, but workload
identity does not authorize export or import.

## 4. Protocol state machine

```text
OFFERED
  source-signed manifest + exact object bytes
      |
      | source boundary consumes agent.state.export.1
      | and agent.state.key-release.1 when VAULT objects exist
      v
SOURCE_RELEASED
      |
      | recipient verifies manifest, objects, source evidence, and lineage
      v
RECIPIENT_READY
      |
      | ONE recipient-local atomic transaction:
      |   recheck heads
      |   verify + consume agent.state.import.1
      |   store objects + heads + replay fence + admission record
      v
COMMITTED -----------------------------> IMPORT RECEIPT
      |
      | optional, separate action bound to accepted import receipt
      v
SOURCE_RETIRED
```

The base protocol is `COPY`. It does not have a `TRANSFER` or `SUCCESSION`
switch that silently changes custody semantics. Source retirement is a later,
separately authorized action.

## 5. Wire artifacts

### 5.1 Manifest

`EP-STATE-HANDOFF-MANIFEST-v0.1` is a closed JSON object containing:

* source-agent, source-boundary, recipient-agent, recipient-boundary, and
  relying-party identifiers;
* one pinned payload profile;
* creation, snapshot, and expiry times;
* a nonce and handoff identifier;
* an ordered descriptor set;
* a digest over the complete ordered descriptor set;
* a scope digest over mode, payload profile, both agents, both consequence
  boundaries, the relying party, and the index digest;
* the exact source and recipient action types;
* five fixed nonclaims; and
* an algorithm-agile signature policy plus signatures.

The descriptor for each object binds its position, identifier, digest, media
type, schema, required status, snapshot assertion time, sensitivity,
disposition, generation, and predecessor digest.

The manifest is complete only relative to itself. It detects an omitted object
that the manifest declared required. It does not prove that the source declared
every state object it possessed.

Schema:
`conformance/schemas/state-handoff-manifest.v0.1.schema.json`.

### 5.2 Payload objects

The carrier core treats object bytes as opaque strict JSON and delegates native
shape validation to exactly one pinned payload adapter. v0.1 does not negotiate
among several profiles inside one manifest. Mixed-profile ambiguity is refused.

The first payload profile is `EP-STATE-PAYLOAD-SOMA-COGOBJ-v0.1`, described in
Section 11.

### 5.3 Import receipt

`EP-STATE-HANDOFF-IMPORT-RECEIPT-v0.1` records:

* `INITIAL` or `RECONCILIATION` receipt kind;
* exact manifest digest and payload profile;
* the exact recipient consequence boundary that signed the receipt;
* `ACCEPTED`, `PARTIAL`, `REFUSED`, or `INDETERMINATE`;
* accepted object identifiers;
* every unavailable optional object and reason;
* every verified source and recipient authority record;
* the recipient admission-record digest;
* commit completion time and separate receipt issuance time; and
* the same fixed nonclaims as the manifest.

An `ACCEPTED` or `PARTIAL` receipt is invalid without exactly one recipient
commit authority record and a non-null admission-record digest. A failed
receipt cannot claim accepted objects or a committed admission record.

The receipt signer MUST be the manifest's `recipient_boundary_id`. A relying
party verifies the receipt with
`verifyPortableStateImportReceiptForManifest`, which also checks the exact
manifest digest, object-set partition, conditional source-action set, CAIDs,
boundary identity, and accepted-result time window. Signature verification by
itself is insufficient.

Schema:
`conformance/schemas/state-handoff-import-receipt.v0.1.schema.json`.

## 6. Canonicalization and signatures

Signed content uses the repository strict JSON profile: plain objects, dense
arrays, strings without unpaired surrogates, booleans, null, and safe integers.
Object keys are recursively sorted. Non-integer quantities must be strings.
Unknown members are refused.

The runtime also enforces 4,096 objects, 256 terminal reasons, two signature
legs, canonical depth 64, 100,000 canonical JSON nodes, and 16 MiB of total
string bytes per canonicalized artifact. Exceeding a limit is a refusal, never
permission to truncate or partially interpret an artifact.

The manifest signs:

```text
UTF8("EP-STATE-HANDOFF-MANIFEST-v0.1" || 0x00) ||
UTF8(canonical(manifest without signatures))
```

The receipt uses the same construction with its receipt version. Recipient-key
validity is evaluated at signed `issued_at`, not at the earlier commit time.

The signed bytes include `signature_policy.required_algorithms`. v0.1 permits
exactly:

* `Ed25519`; or
* `Ed25519` plus `ML-DSA-65` under `hybrid_all`.

Every required leg signs identical bytes. Removing the ML-DSA leg and narrowing
the declared set invalidates the surviving Ed25519 signature. Verification uses
pinned keys and the existing `EP-SIG-AGILITY-v1` implementation. ML-DSA support
is algorithm agility, not a FIPS module-validation claim.

All time fields are signed assertions. The fixed
`trusted_time: "NOT_ESTABLISHED"` nonclaim prevents internal time-order checks
from being presented as offline anti-backdating. A deployment that needs
trusted time must compose a separately pinned time-attestation or registration
profile and state its own claim boundary.

## 7. Normative EMILIA authority profile

The protocol normatively requires:

* CAID to identify each exact action object;
* native Authorization Receipt evidence that the source actions were consumed;
* AEB at the source for export and key release; and
* AEB at the recipient for atomic import admission and state commit.

The public CAID registry defines four actions:

### 7.1 `agent.state.export.1`

Required for every handoff. It binds the manifest digest, handoff identifier,
payload profile, `COPY` mode, both agents, both consequence boundaries, relying
party, scope digest, expiry, and nonce.

### 7.2 `agent.state.import.1`

Required for every handoff. It binds the same fields under a different action
type. The recipient consumes it only inside the state-commit transaction.

### 7.3 `agent.state.key-release.1`

Required when the manifest contains any VAULT object. It additionally binds a
digest over the ordered VAULT object identifiers and object digests. A consumed
key-release action does not prove that the recipient successfully obtained or
used the key, so local vault availability remains a separate check.

### 7.4 `agent.state.retire-source.1`

Never part of the base import. It is constructed only after a matching
`ACCEPTED` or `PARTIAL` import receipt exists and additionally binds that exact
receipt digest. It also binds `retirement_set_digest`, computed over exactly the
accepted object identifiers and object digests. On a `PARTIAL` import,
unavailable objects are outside retirement authority and remain at the source.
The action does not transfer operational authority and does not prove physical
erasure.

Before evaluating retirement, the source AEB MUST authenticate the import
receipt under pinned recipient keys, verify its exact manifest binding, and
apply its own retirement policy. Constructing the action object is not
authorization.

All material action fields are registered in
`caid/registry/action-types.json`. CAID commits content identity only. It is not
authorization by itself.

## 8. Source release verification

The bundle carries source-side native evidence for exactly the source action
set declared by the manifest. Extra or missing evidence is refused.

The recipient MUST verify that each native source receipt:

1. is accepted under a pinned native profile;
2. maps to the locally recomputed expected CAID;
3. names the exact source consequence boundary; and
4. records the source action as consumed.

The recipient verifies this evidence. It does not consume source authority a
second time.

## 9. Recipient atomic transaction

Before entering the transaction, the recipient may validate signatures,
digests, schemas, required members, and current lineage. Immediately before
commit, the authoritative boundary MUST recheck every current head.

The one transaction MUST:

1. reject a reused handoff identifier;
2. compare every expected current head;
3. verify the exact import evidence and CAID;
4. consume `agent.state.import.1`;
5. store each accepted object’s exact bytes;
6. advance each object head;
7. persist the replay fence; and
8. persist the admission record from which the import receipt is derived.

If a head changed, the result is `INDETERMINATE`. Import authority must remain
unconsumed. If a deployment cannot make these steps one local atomic transition,
it does not conform to the strong profile and must not issue an accepted receipt.

## 10. Lineage and reconciliation

v0.1 uses a linear lineage per object:

* generation zero requires a null predecessor;
* an equal or lower generation is a rollback and is refused;
* a generation gap is indeterminate;
* the next generation with the wrong predecessor is a fork and is refused; and
* the next generation with the current local head as predecessor may commit.

v0.1 has no last-writer-wins, timestamp winner, or implicit merge. A future
merge profile would require its own exact action and hostile tests.

If the state commit succeeds but the acknowledgement is lost, the first result
is `INDETERMINATE`. The caller reconciles by handoff identifier and manifest
digest. The recipient may then issue a `RECONCILIATION` receipt from the stored
admission record without consuming authority or writing state again.

The reconciliation receipt preserves the stored `completed_at` and records a
fresh `issued_at`. A reconciliation receipt can only be `ACCEPTED` or `PARTIAL`.

A repeated bundle never receives that accepted receipt automatically. It
returns `handoff_already_committed_use_reconciliation`, even when the manifest
matches, because the repeated object bytes could have been altered. Only the
explicit reconciliation operation reads the stored admission record.

## 11. SOMA/COGOBJ payload profile

`SOMA-COGOBJ-v0.1` is the first payload object. It carries:

* stable object, domain, and schema identifiers;
* a snapshot assertion separated from source mutability and observation basis;
* sensitivity and content-protection declarations;
* an origin assertion;
* one linear lineage predecessor;
* `authority_semantics: "NONE"`; and
* strict JSON content or an opaque ciphertext envelope.

Origin is the manifest source's signed assertion about the named origin issuer.
It is not the named origin issuer's signature unless a separately pinned native
artifact establishes that fact, and it is not independent proof of where bytes
truly came from.

Snapshot origin and snapshot freshness are separate facts. `observed_at` and
`freshness_basis_digest` are either both present or both absent. A mutable or
unknown source without a basis remains explicitly caveated.

An observation cannot occur after its snapshot assertion, and an origin
assertion cannot be created after the snapshot that carries it. Each object
snapshot MUST be at or before the manifest's set-level snapshot cut. A manifest
created in the verifier's future is not yet valid.

An active VAULT object MUST use `OPAQUE-CIPHERTEXT` with a named protection
profile and key-reference digest. The carrier does not invent encryption. It
transports and binds the ciphertext envelope while the relying party pins the
protection profile.

A tombstone has null content. It is a signed state transition, not proof that
all copies were erased.

Schema: `conformance/schemas/soma-cogobj.v0.1.schema.json`.
The JSON Schema validates the closed wire shape. The payload adapter adds the
semantic checks for origin and freshness pairs, lineage, VAULT protection, and
the rule that payload authority semantics remain `NONE`. Content that merely
resembles authority data remains inert payload and cannot satisfy an authority
check.

SHEESH, SOMA, COGOBJ, and the institutional memory-succession concept originated
in Justin Kintzele’s Agent-In-Body and Continuum architecture. EMILIA’s bounded
contribution is the carrier-neutral handoff, exact authority split, atomic
recipient admission, signed result, and hostile verifier. Attribution is not an
endorsement or a coauthorship claim.

## 12. Deliberate extension seams

The core stays small. Other protocols enter only where they own a distinct
question.

| Protocol or artifact | Optional role | Must never become |
| --- | --- | --- |
| WEXP | Appraise a carried execution-evidence object under a separately pinned payload profile | Authority, arbitrary memory truth, or a base dependency |
| CAP-1 | Describe examined-set coverage when a profile supplies a closed population root and count | Proof that the source population itself was complete |
| WIMSE | Authenticate exporter and importer workloads | Export or import authorization |
| SCITT | Register or timestamp manifest and receipt digests | Proof of source truth or recipient import |
| SAIHM | Carry encrypted state cells or key-management metadata | Replacement for set-level import, lineage, or admission semantics |
| AEC | Compose required evidence roles for a deployment | Authorization or truth by enumeration |
| OASNT or WebAuthn | Supply a native human-authorization leg accepted by AEB | A portable state token |

WEXP is intentionally not in the base protocol. It becomes useful only for an
object whose claim is execution evidence and only under a separately named
appraisal profile. A WEXP downgrade or refusal cannot be relabeled as import
authority.

Receipt verification is performed together with the corresponding manifest.
The receipt authenticates the committed result; manifest verification supplies
the object set, lineage, and any conditional key-release requirement.

## 13. Security controls and negative cases

The conformance suite covers:

* byte substitution after manifest signing;
* required omission and undeclared-object insertion;
* authority-shaped payload content;
* missing or unconsumed source release;
* recipient refusal without authority burn;
* head change between preflight and commit;
* rollback, fork, and lineage gap;
* missing optional objects;
* unsupported required payload profiles;
* VAULT plaintext and key unavailability;
* lost commit acknowledgement and reconciliation;
* hybrid-signature stripping;
* action, agent, consequence-boundary, and manifest substitution;
* receipt state-set and authority-CAID substitution;
* source retirement without a matching accepted receipt;
* tombstones misrepresented as erasure; and
* accepted receipts without an atomic admission record;
* malformed canonical payloads and producer/verifier drift; and
* source-verifier, payload-adapter, admission-store, head-store, commit-response,
  and vault-key-service failures.

The process-local reference boundary demonstrates the transaction contract. It
is not evidence of cross-process durability, database isolation, external key
custody, production deployment, or external implementation independence.

## 14. Privacy considerations

Encryption of VAULT content does not hide manifest metadata. Object
identifiers, schemas, domains, sensitivity classes, lineage, parties,
consequence-boundary identifiers, timing, and accepted or unavailable status
can reveal institutional structure and activity.

Deployments SHOULD use pairwise or opaque identifiers where global names are
not required, minimize descriptor detail, and avoid publishing manifests or
receipts to a transparency service unless that disclosure is intentional.
Publishing only a digest can still enable correlation when the underlying
artifact is known or guessable. Receipt retention must follow the relying
party's dispute and privacy policy. A tombstone remains evidence of a declared
state transition and is never proof that all payload, cache, backup, log, or
key copies were erased.

## 15. Related work and non-collision

As checked on 2026-08-21:

* [SAIHM -01](https://datatracker.ietf.org/doc/draft-saihm-memory-protocol/)
  defines encrypted memory cells, identity, sharing, receipts, and tool surfaces.
  It does not define this profile’s set-level recipient admission transaction.
* [AMSP -01](https://datatracker.ietf.org/doc/draft-liu-agent-metadata-sync-protocol/)
  synchronizes agent records and routing metadata, not durable state import.
* [Agent Context Protocol -00](https://datatracker.ietf.org/doc/html/draft-liu-agent-context-protocol)
  carries task and policy context, but does not define recipient lineage,
  atomic import, or source retirement.
* [WEXP Core -01](https://www.ietf.org/ietf-ftp/internet-drafts/draft-sergeev-wexp-core-01.html)
  appraises execution-evidence claims. It does not define serialization,
  signatures, CAID, authorization, or state lifecycle.

The formal profile therefore targets a narrower gap: portable, recipient-bound
state admission with explicit non-authority semantics and a separately
authenticated terminal result.

## 16. Implementation and publication gate

Reference modules:

* `packages/verify/src/portable-state-handoff.ts`
* `packages/verify/src/soma-cogobj-profile.ts`
* `examples/portable-state-handoff/continuum-exporter.mjs`
* `examples/portable-state-handoff/roundtrip.test.mts`

The Continuum producer has its own canonicalizer and signing implementation.
The EMILIA recipient independently verifies and imports. They remain in one
repository and were produced by one team, so this is implementation separation,
not external independence.

The profile should remain an implementation profile until:

1. Justin approves the SOMA/COGOBJ semantics and attribution;
2. a separately maintained client reproduces the round trip;
3. the exact schemas and negative controls are frozen;
4. source and recipient AEB adapters exercise real native receipts; and
5. the repository’s filing freeze permits a new Internet-Draft.

Only then should the descriptive standards title “Portable Agent State Handoff”
be considered. The implementation name Vortex may remain without becoming the
wire protocol name.
