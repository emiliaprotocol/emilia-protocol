# CAP-1 coverage composition v1

Status: experimental composition profile. It does not change CAP-1.

`EP-CAP1-COVERAGE-COMPOSITION-v1` joins three separately evaluated facts:

1. A relying-party-selected CAP-1 verifier says the producer's exact CAP-1
   document conforms to the pinned `-00` prose.
2. A separate examined-set verifier checks explicit eligible membership and
   per-result bindings. Its negative controls cover duplicate units, count and
   root mismatches, non-eligible results, examined/unexamined overlap, and the
   unresolved `withheld` examined semantics.
3. An `EP-COVERAGE-RECONCILIATION-ATTESTATION-v3` hybrid signature binds that
   exact CAP-1 document digest to the supplied population roots and counts, the
   relying party, the coverage report hash, and the named reconciliation
   program.

The CAP-1 subject digest also commits to both eligible-set and examined-set
roots, a stable claim class, and a pinned technique/depth profile. Those fields
are composition requirements because CAP-1 `-00` cannot express them
normatively.

## Digest and source pin

The CAP-1 document digest uses `EP-CANONICAL-JSON-SHA256-v1`, EMILIA's existing
recursively key-sorted canonical JSON plus SHA-256. CAP-1 `-00` does not define
a canonical byte representation.

The exact reviewed public bundle is recorded in
`conformance/composition/cap1-emilia-v0.1/source-lock.json`. This is an EMILIA
reproduction pin. It does not claim that CAP-1 `-00` normatively identifies the
repository schema, vectors, implementations, or fixtures.
The subject commitment includes both the lock fields and their EMILIA canonical
digest, so replacing a path, commit, or file digest changes the subject.

## Verification order

1. Verify native CAP-1 conformance locally.
2. Verify examined-set evidence locally.
3. Recompute the CAP-1 document digest and subject commitment.
4. Verify the coverage report hash and both hybrid signature legs.
5. Match the exact relying party, program, roots, counts, claim class, and
   technique/depth profile supplied by verifier policy.

Native CAP-1 refusal is reported as `cap1_native_refused`. Strict set-evidence
refusal is `cap1_examined_set_refused`. The two are never collapsed.

## Claim boundary

An accepted composition authenticates a producer's CAP-1 statement and the
supplied set commitments under a pinned reconciliation program. It does not
prove:

- that the source population was complete;
- that enumeration was honest or resistant to post hoc narrowing;
- that the examination technique or depth was adequate;
- that underlying source claims were true;
- authorization, execution, or physical effect.

Enumeration and derived-population transformation receipts, pre-window
population pins, and outer workflow states such as `not_reached` and
`aborted_before_dispatch` remain future strict-profile inputs. Until those are
pinned, callers must not upgrade this profile's supplied-population claim.

## Native verifier adapter

The composition accepts local callbacks rather than importing an implementation
chosen by the presented artifact. The native adapter returns `CONFORMS` or
`REFUSES`, its exact source lock, violations, and the EMILIA canonical document
digest. The examined-set adapter returns `SATISFIED` only with exactly one root
pair and result count for every composition stratum. The Gate then matches those
values against verifier-owned population pins.
