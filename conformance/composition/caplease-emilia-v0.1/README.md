<!-- SPDX-License-Identifier: Apache-2.0 -->
# CapLease and EMILIA comparison v0.1

This package executes a bounded technical comparison between CapLease's durable
authorization-consumption state and EMILIA's exact-action capability admission,
consumption, unknown-outcome, and reconciliation state.

It is not a marketing crosswalk. A row passes when the runner reproduces the
stated overlap, difference, or unsupported boundary. Unsupported behavior is
not counted as interoperability.

## Source boundary

The CapLease side is pinned to arXiv `2608.01710v1`, including the PDF, TeX
source archive, and top-level `main.tex` hashes in `source-lock.json`. The arXiv
v1 metadata and source archive identify no official code repository and include
no supplement. The package therefore executes a small paper-derived model of
the relevant Issue-Prepare-Commit transitions. It does not execute or claim to
reproduce author-supplied CapLease code.

The EMILIA side imports the pinned repository runtime in
`packages/gate/capability-receipt.js`. It uses the actual capability scope
verifier, atomic in-memory reference store, revocation path, provider-entry and
commit transitions, action fence, and authenticated reconciliation API. The
in-memory store is explicitly non-durable; this run establishes runtime
semantics, not production persistence or deployment evidence.

## Executed comparison

| Case | CapLease v1 | EMILIA runtime | Relation |
| --- | --- | --- | --- |
| Positive exact action | One slot reaches `Committed` | One operation reaches `committed/executed` | Compatible |
| Fresh-identifier replay | Reuses the unique `(sigma, confirmation event)` record | Refuses a fresh operation under the same action fence | Compatible result, different identity keys |
| Material substitution | Action-identity mismatch | Capability action out of scope | Compatible refusal |
| Expiry | Refuses preparation | Refuses reservation | Compatible refusal |
| Pre-admission revocation | `Issued` becomes `Revoked` | Revoked capability cannot reserve | Compatible refusal |
| Lost acknowledgement | Keeps `Prepared`; retries the same stable sink key | Commits `indeterminate`; refuses blind replay | Different recovery contract |
| Evidence-only reconciliation | Not specified by the paper | Verifies same-action provider evidence without reexecution | Unsupported by CapLease paper |
| Authorization identity | Unique over action plus confirmation event | Fenced over operation namespace plus action-fence digest | Not equivalent |

CapLease's external-effect bound depends on an idempotent sink. The lost-ack
fixture therefore records two sink calls but one effect. EMILIA instead records
one provider entry, consumes the operation as indeterminate, refuses a second
entry, and later records an `executed` reconciliation from an Ed25519-signed
provider statement bound to the same operation and action digest.

Neither behavior is described here as exactly-once physical execution.

## Run

```bash
npm run conformance:composition:caplease-emilia
```

Direct commands:

```bash
node --test conformance/composition/caplease-emilia-v0.1/run.test.mjs
node conformance/composition/caplease-emilia-v0.1/run.mjs --check
```

To regenerate the deterministic reference report deliberately:

```bash
node conformance/composition/caplease-emilia-v0.1/run.mjs --emit
```

## Non-claims

- No official CapLease implementation, supplement, or repository was executed.
- EMILIA's action fence is not proof of CapLease's `(sigma, confirmation event)`
  uniqueness property.
- CapLease v1 does not specify EMILIA's authenticated evidence-only
  reconciliation transition.
- EMILIA does not adopt CapLease's blind same-key sink retry behavior.
- The fixtures do not prove production durability, complete mediation, sink
  truthfulness, legal authorization, action wisdom, or physical outcome.
