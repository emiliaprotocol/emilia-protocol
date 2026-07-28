<!-- SPDX-License-Identifier: Apache-2.0 -->

# Reliance Programs v1

**Status:** public experimental source, signed-envelope, and compiler profile;
synthetic reference fixtures only

**Source discriminator:** `EP-RELIANCE-PROGRAM-SOURCE-v1`

**Signed-envelope discriminator:** `EP-RELIANCE-PROGRAM-v1`

**Compiler target:** `EP-GATE-TRUST-PROGRAM-PROFILE-v1`

**Reference fixtures:** [`examples/reliance-programs/`](../../examples/reliance-programs/)

**Conformance catalog:**
[`conformance/vectors/reliance-programs.v1.json`](../../conformance/vectors/reliance-programs.v1.json)

A Reliance Program is a customer-owned, signed source definition that compiles
to one existing Gate Trust Program for one exact consequential action. It lets
a relying party pin admissibility profiles, order their evaluations, set
stage-level rules, bound evaluation age, require revocation status, and select
one downstream consequence owner.

The source is not an evidence verifier and is not a second authorization or
execution engine. Native verifiers establish native facts; CAID and
action-binding logic establish the exact action; an admissibility evaluator
applies a relying-party profile; the compiled Gate Trust Program orders those
results and fences one downstream claim. Receipt Program or Action Escrow
remains responsible for its own reserve, provider-entry, outcome, and
reconciliation controls.

Compilation does not turn a profile result into universal authorization:

`VERIFIED != EQUIVALENT != SATISFIED != AUTHORIZED != CLAIMED != EXECUTED`

## 1. Customer ownership and trust

The source's closed `relying_party` object contains exactly `id` and `key_id`.
The customer signs the complete source with the private key corresponding to
that key identifier. Signing material is supplied out of band and is never
serialized.

Verification does not trust a raw key or an identity carried by the envelope.
The relying party supplies an exact trust entry:

```ts
const trustedKeys = {
  "key:customer:reliance-program:v1": {
    relying_party_id: "org:customer.example",
    public_key: customerEd25519PublicKey
  }
};
```

The trust entry's `relying_party_id` must equal `source.relying_party.id`, and
the map key must equal both `source.relying_party.key_id` and
`signature.key_id`. A valid signature under a key pinned for a different
organization is refused. A raw key value is not a valid trust entry.

The compiler does not choose an evidence bar, trust root, freshness interval,
revocation policy, action, CAID, stage graph, or consequence owner. Those are
customer inputs. EMILIA supplies the compiler, verifier, and enforcement
kernel; that does not make EMILIA the author of the customer's policy.

## 2. Closed source object

The complete top-level key set is:

| Field | Meaning |
| --- | --- |
| `@version` | Exactly `EP-RELIANCE-PROGRAM-SOURCE-v1`. |
| `program_id` | Stable bounded customer identifier. |
| `version` | Positive safe integer. |
| `relying_party` | Closed customer identifier and signing-key identifier. |
| `root_caid` | CAID for the exact protected action. |
| `action_digest` | Lowercase `sha256:` digest for the same exact action projection. |
| `valid_from`, `expires_at` | Strict UTC validity interval. |
| `stages` | One to 64 closed source stages. |
| `execution` | Existing Gate Trust Program consequence-owner definition. |

Unknown top-level or nested fields are refused. Canonical JSON safety,
identifier, digest, CAID, time-window, count, duplicate, and graph checks run
before compilation. The implementation clones accepted input and does not
retain presenter-mutable references.

The public fixtures are described as `synthetic_reference` by their directory
README and conformance catalog. That classification is intentionally not a
source field or runtime authorization input.

### 2.1 Stage rules and profile pins

Each source stage contains exactly:

- `stage_id`;
- `depends_on`;
- `rule`; and
- `profiles`.

`rule` is the existing Trust Program `all`, `any`, or `threshold` rule,
including `distinct_subjects` and `distinct_keys`. Threshold rules also carry a
positive `required` value no greater than the number of profile references.

Each entry in `profiles` contains exactly:

```json
{
  "profile_id": "rp.customer.profile.v1",
  "profile_hash": "sha256:...",
  "evaluation_max_age_sec": 300,
  "revocation_required": true
}
```

Both the identifier and hash are pinned. The compiler receives profile bodies
separately in `profiles`. For each body it removes `profile_hash`, canonicalizes
the remainder, recomputes SHA-256, and requires that value to equal the body's
declared self-hash. It then requires both the body identifier and recomputed
hash to equal the signed source reference. A self-consistent profile
substitution under the same identifier is therefore still a pin mismatch.

`evaluation_max_age_sec` limits the age of the admissibility evaluation
consumed by Gate; it is not the lifetime of every native artifact.
`revocation_required` requires the Trust Program projection to carry current
revocation-check evidence under the pinned evaluator. It does not define how an
authoritative status is obtained.

Dependencies name known stages, cannot self-reference, and must form an acyclic
graph. Every declared stage must contribute to execution. Decorative or
disconnected stages are refused by validation of the compiled Trust Program.

### 2.2 Execution owner

`execution` is copied into the compiled Trust Program and follows
[`GATE-TRUST-PROGRAM-PROFILE.md`](./GATE-TRUST-PROGRAM-PROFILE.md):

- `depends_on`;
- `consequence_mode`;
- `capability_template_digest`; and
- `escrow_profile_digest`.

`receipt-program` requires a capability-template digest and null escrow
profile. `action-escrow` requires an escrow-profile digest and null capability
template. Both populated, both null, an unknown mode, or an unknown execution
dependency is refused.

Selecting an owner configures one downstream claim path. It is not provider
entry and is not an external effect.

## 3. Signed source envelope

`signRelianceProgram(source, privateKey)` validates the source and returns:

```json
{
  "@version": "EP-RELIANCE-PROGRAM-v1",
  "source": {
    "@version": "EP-RELIANCE-PROGRAM-SOURCE-v1"
  },
  "source_digest": "sha256:...",
  "signature": {
    "algorithm": "Ed25519",
    "key_id": "key:customer:reliance-program:v1",
    "value": "base64url"
  }
}
```

The Ed25519 signature is domain separated by `EP-RELIANCE-PROGRAM-v1` and
covers the complete canonical source. The digest independently binds those
same source bytes. The envelope is closed; it has no unsigned extension point.

Verification is offline and fail closed:

```ts
const verified = verifyRelianceProgram(envelope, { trustedKeys });
```

The verifier:

1. rejects unknown or malformed envelope fields;
2. validates the closed source;
3. matches the signature key ID to the source key ID;
4. recomputes and matches the source digest;
5. resolves an exact `{ relying_party_id, public_key }` trust entry;
6. matches the trusted organization to the signed source organization; and
7. verifies the Ed25519 signature.

Only then does it return `valid: true`. This means the trusted customer signer
signed this exact source. It does not mean a stage passed or an effect was
authorized, claimed, or executed.

## 4. Deterministic compilation

Compilation verifies the signed envelope and all supplied profile bodies:

```ts
const compiled = compileRelianceProgram(envelope, {
  trustedKeys,
  profiles: customerPinnedProfileBodies
});
```

Each source profile reference compiles to one Trust Program requirement:

| Source or compiler value | Compiled Trust Program field |
| --- | --- |
| compiler constant | `evidence_type: "ep-admissibility-evaluation"` |
| compiler constant | `verifier_profile: "ep-admissibility-profile:v1"` |
| `profile_hash` | `policy_digest` |
| `evaluation_max_age_sec` | `max_age_sec` |
| `revocation_required` | `revocation_required` |

Requirement identifiers are deterministic stage-local identifiers
`admissibility-01`, `admissibility-02`, and so on. The compiled object's `trace`
joins each stage and requirement identifier back to the signed profile
identifier and hash.

Stage rules and dependencies, exact action bindings, validity interval, program
version, and execution owner are preserved. The compiler validates the result
as `EP-GATE-TRUST-PROGRAM-PROFILE-v1` before returning:

```json
{
  "version": "EP-RELIANCE-PROGRAM-v1",
  "source_digest": "sha256:...",
  "relying_party_id": "org:customer.example",
  "program": {
    "@version": "EP-GATE-TRUST-PROGRAM-PROFILE-v1"
  },
  "program_digest": "sha256:...",
  "trace": [],
  "claim_boundary": "..."
}
```

The compiled object is a deterministic compiler result, not a second signed
envelope. Consumers pin `source_digest` and `program_digest` as appropriate and
still construct Gate with relying-party-owned verifiers, trust roots, storage,
clock, action binding, and downstream owner controls.

## 5. Hostile coverage

The conformance catalog and
[`tests/reliance-program-fixtures.test.ts`](../../tests/reliance-program-fixtures.test.ts)
exercise all three positive fixtures plus:

- a self-consistent profile substitution under the same profile identifier;
- removal of the source-envelope signature;
- a raw public key without a relying-party identity binding;
- a valid key pinned for a different relying-party identifier;
- unknown source and envelope fields;
- action-digest drift after signing;
- CAID drift after signing; and
- a disconnected signed source stage.

The mutations are data operations from the JSON catalog. Case identifiers do
not select hard-coded verifier outcomes.

## 6. Published fixture claim boundaries

The payer fixture is a synthetic, PHI-free policy compilation example. It does
not contain a FHIR Claim or ClaimResponse and makes no payer-live, Da Vinci PAS
conformance, medical-necessity, reviewer-licensure, or legal-compliance claim.

The auditor fixture demonstrates a customer-authored evidence order. It does
not establish auditor independence, sufficient appropriate audit evidence, an
audit opinion, or compliance with a professional standard.

The MCP fixture demonstrates a policy gate for one exact synthetic tool call.
It does not establish MCP server correctness, tool safety, delegated authority,
platform integrity, durable deployment, or non-bypassability.

See
[`RELIANCE-PROGRAM-CANNOT-EXPRESS.md`](./RELIANCE-PROGRAM-CANNOT-EXPRESS.md)
for the normative non-expressibility boundary.
