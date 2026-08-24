<!-- SPDX-License-Identifier: Apache-2.0 -->
# EP Claim Assurance v1

Status: experimental reference implementation

EP Claim Assurance turns a typed claim and its evidence into a deterministic,
portable result that another party can re-perform without trusting the
presenter. It closes the evidence half of the claim-to-consequence lifecycle:

```text
claim
  -> Claim Case
  -> caller-pinned verification
  -> Assurance Record
  -> optional exact-action admissibility input
  -> separate Gate authority decision
  -> provider and outcome reconciliation
```

The core boundary is absolute:

> Claims become evidence. Evidence can inform Gate. It never becomes authority
> by itself.

Every `EP-ASSURANCE-RECORD-v1` therefore carries
`"authorizes_action": false`. A `VERIFIED` verdict means the Claim Case cleared
the exact profile and verifier implementations the relying party pinned. It
does not authorize an action, certify an organization, establish legal
compliance, prove a source truthful, or prove that an external effect occurred.

## Implemented artifacts

### `EP-CLAIM-ASSURANCE-PROFILE-v1`

The relying party defines the claim type, predicate, required evidence roles,
exact verifier id, verifier version, verifier implementation digest, minimum
distinct source count, and maximum evidence age. The relying party pins the
complete profile bytes and their SHA-256 digest out of band.

A presenter cannot register its own verifier, trust key, or profile. Profile
names are labels. The content digest is the commitment.

### `EP-CLAIM-CASE-v1`

A Claim Case contains:

- one subject digest and one scope digest;
- one typed claim and value;
- the pinned profile id and profile hash;
- an optional exact-action digest;
- a canonical `as_of` instant;
- zero or more evidence artifacts, each content-addressed and bound to the
  subject, scope, claim, and optional action.

The case presents artifacts. It does not present trust. Evidence is accepted
only through an exact caller-registered verifier tuple:

```text
(verifier_id, verifier_version, implementation_digest)
```

Unknown fields, duplicate evidence ids, duplicate artifact digests, malformed
canonical JSON, unsafe numbers, invalid timestamps, and resource-limit
violations fail before evaluation.

### `EP-ASSURANCE-RECORD-v1`

The zero-dependency verifier re-performs the case and emits:

- the exact profile and Claim Case digests;
- the subject, scope, claim, and optional action binding;
- one result per evidence item and requirement;
- a closed claim verdict;
- deterministic replay and record digests;
- the literal non-authority marker.

The record digest detects mutation and provides a content address. It is not a
signature and does not establish issuer identity or provenance. A relying
party either re-performs the Claim Case with its own pins or separately verifies
an authenticated envelope that binds the record digest.

`inspectAssuranceRecordIntegrity` validates the closed record shape, internal
verdict semantics, replay digest, record digest, and an optional independently
pinned expected digest. Its result always says `reperformed: false`. Even a
fully self-consistent record can be fabricated by someone who recomputes its
digests. Only `evaluateClaimAssurance` over the raw Claim Case with the relying
party's own profile and verifier pins re-performs the claim evaluation.

## Closed verdicts

| Verdict | Meaning |
|---|---|
| `VERIFIED` | Every profile requirement has enough distinct accepted supporting sources. |
| `UNVERIFIED` | Available evidence was checked and did not support the claim under the pinned bar. |
| `DIVERGED` | Accepted sources both support and contradict the claim. |
| `INDETERMINATE` | A required answer cannot be established because evidence is missing, stale, unavailable, malformed, or below the required source count. |

`DIVERGED` takes precedence over `VERIFIED`. A requirement is never satisfied
by a self-asserted verdict inside an artifact. Source quorum counts distinct
verifier-returned source identities, not filenames or repeated artifacts.

Evidence validity is the half-open interval `[observed_at, expires_at)`. An
`expires_at` equal to `observed_at` is malformed, and evidence is stale when
`evaluated_at` is equal to or later than `expires_at`. Expiry and
`max_age_seconds` are evaluated at `evaluated_at`, not only at the Claim Case's
historical `as_of` instant. Evidence observation must still be at or before
`as_of`. This prevents a once-current artifact from remaining current merely
because evaluation was delayed.

## Exact-action Gate bridge

`EP-CLAIM-ASSURANCE-GATE-PRESENTATION-v1` carries the raw Claim Case to a trusted
Gate callback. The callback:

1. checks that Gate selected the same constructor-pinned profile id and hash;
2. computes the digest of the executor-observed action;
3. re-performs the raw Claim Case with an explicitly injected, reviewed Claim
   Assurance evaluator and caller-pinned verifier callbacks;
4. requires the Claim Case action digest to match the observed action;
5. applies a deployment-pinned maximum Claim Case age;
6. projects the result into the Gate's closed admissibility states.

| Claim result | Gate admissibility result |
|---|---|
| current `VERIFIED` | `admissible` |
| `DIVERGED` | `conflicted` |
| missing required sources | `missing_evidence` |
| expired evidence or old Claim Case | `stale` |
| `UNVERIFIED`, unavailable verifier, malformed result, or other uncertainty | `unverifiable` |

This bridge is an additional condition inside Gate. It does not supply a Trust
Receipt, local business authority, policy permission, one-time consumption,
provider-entry custody, or outcome proof. Gate refuses a missing receipt before
it calls the Claim Assurance verifier.

A deployment-level `requiredAdmissibilityProfile` is authoritative. A request
or selector may repeat that pin for transport convenience, but cannot replace
the configured id or hash with a weaker profile.

The evaluator callback and every registered evidence-verifier callback are
deployment trust inputs. Gate snapshots those callback references during bridge
construction. They must be supplied from reviewed code and isolated or bounded
by the deployment; they are never accepted from the presentation. The
structural injection also keeps `@emilia-protocol/gate/claim-assurance` from
depending on a particular Verify package subpath release.

Gate applies its executor-side canonical carrier ceiling before invoking the
evaluator: at most 50,000 JSON nodes, 64 levels, and 1 MiB of aggregate UTF-8
string and key bytes for the presentation, with the same ceiling applied when
hashing the observed action. This is intentionally stricter than the standalone
Claim Assurance kernel's Claim Case ceiling of 330,000 nodes and 8,454,144
string bytes. A case that is valid for offline verification can therefore still
be too large to present at an enforcing Gate. Deployments must reduce or
reference evidence before that boundary rather than weakening the Gate carrier.

## Determinism and digests

The reference implementation uses strict canonical JSON and SHA-256:

- artifact digest: SHA-256 of the canonical artifact;
- profile hash: SHA-256 of the canonical profile;
- Claim Case digest: SHA-256 of the canonical Claim Case;
- replay digest: domain-separated digest of the exact evaluation inputs and
  per-evidence and per-requirement results;
- record digest: domain-separated digest of the complete record except
  `record_digest` itself.

Arrays whose order carries no evaluation meaning are sorted by stable ids using
binary UTF-16 code-unit order, never host locale collation. The same case, pins,
verifier outputs, and evaluation instant produce the same bytes.

## Public schemas and code

- [`ep-claim-assurance-profile.schema.json`](../public/schemas/ep-claim-assurance-profile.schema.json)
- [`ep-claim-case.schema.json`](../public/schemas/ep-claim-case.schema.json)
- [`ep-assurance-record.schema.json`](../public/schemas/ep-assurance-record.schema.json)
- [`ep-claim-assurance-gate-presentation.schema.json`](../public/schemas/ep-claim-assurance-gate-presentation.schema.json)
- [`ep-claim-assurance-admissibility.schema.json`](../public/schemas/ep-claim-assurance-admissibility.schema.json)
- `@emilia-protocol/verify/claim-assurance`
- `@emilia-protocol/gate/claim-assurance`

JSON Schema validates the portable shape. The reference implementation remains
the normative executable check for duplicate detection, strict canonical JSON,
resource bounds, digest recomputation, profile matching, verifier pinning,
freshness, source counting, and verdict aggregation.

## Public resolver boundary

The first resolver surface serves one deterministic, loudly synthetic reference
record by exact content address. It has no list or search operation and exposes
no customer data. It demonstrates portability, not a production registry,
certificate programme, surveillance service, customer deployment, or hosted
verification SLA.

Future registry and lifecycle services must distinguish at least current,
superseded, suspended, withdrawn, revoked, and unavailable. A resolver response
must never be treated as action authority.

## Security and non-claims

- A verified artifact can still contain a false real-world assertion if the
  verifier and its source semantics are inadequate.
- A content digest proves byte integrity, not who created the bytes.
- A Claim Case can cover only the evidence and scope it names.
- A Gate prevention claim applies only to configured, completely mediated
  protected paths.
- A valid authorization does not make the underlying claim or action correct,
  wise, safe, or lawful.
- Registered verifier callbacks are live relying-party trust inputs. The
  in-process reference kernel cannot preempt synchronous callbacks. Production
  deployments must isolate verifier code and enforce resource limits and
  deadlines outside the callback process.
- `INDETERMINATE` is not permission. It must fail closed at an enforcing Gate.
- Provider admission is not proof of provider receipt or external effect.
- No public accredited certification programme or EMILIA certification mark is
  operating as of this version.

## Scheme and assessment ownership

EMILIA can own and steward the public criteria, schemas, conformance vectors,
record format, registry and resolver rules, surveillance workflow, status
transitions, mark policy, licensing, and hosted operations. An independent
assessor or conformity assessment body retains responsibility for its own
assessment evidence, conclusion, impartiality, competence, and any accreditation
claim. EMILIA does not convert a vendor-generated result into an independent
opinion by relabeling it.

That separation preserves a complete EMILIA product lane without collapsing
independent judgment into software output.

## Deployment checklist

Before relying on a Claim Assurance result:

1. Pin the exact profile bytes and recomputed profile hash.
2. Inject the reviewed Claim Assurance evaluator, then register verifier code
   and trust material out of band.
3. Bind each artifact to the subject, scope, claim, and action it actually
   supports.
4. Set explicit evidence and whole-case freshness limits.
5. Re-perform the case rather than trusting a presenter-supplied record digest.
6. Require separate exact-action authority and durable one-time consumption in
   Gate.
7. Map every alternate executor path before making a prevention claim.
8. Preserve `INDETERMINATE` after uncertain provider entry and reconcile before
   any retry.
