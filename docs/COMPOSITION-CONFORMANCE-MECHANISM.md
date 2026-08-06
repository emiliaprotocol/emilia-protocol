<!-- SPDX-License-Identifier: Apache-2.0 -->
# Cross-Slot Conformance Mechanism for Agent Accountability Composition

**Candidate contribution to `draft-mih-sato-agent-accountability-composition`**
**Contributor:** Iman Schrock, EMILIA Protocol
**Runnable pack:**
[`examples/composition/cross-slot-conformance-v1`](../examples/composition/cross-slot-conformance-v1/README.md)

## 1. Boundary

The mechanism tests whether an implementation preserves the declared
boundaries and joins of the Composition Model. It does not define native
conformance for CAN, WHO, WHAT, or AUDIT. Each slot owner maintains the rules
and vectors for that slot. Composition imports the native reports without
weakening, relabeling, or overwriting them.

A run reports the CAN, WHO, WHAT, and AUDIT results separately, followed by
each cross-slot check. It never collapses those results into one opaque
`trusted`, `authorized`, `executed`, or `verified` boolean.

CAID, AEC, and AEB enter at distinct interfaces rather than becoming new slot
definitions:

- CAID supplies the declared exact-action digest context.
- AEC preserves native evidence verification and reports whether a named
  relying-party requirement is satisfied.
- AEB remains the executor-side authorization, reserve/consume, invocation,
  and post-dispatch uncertainty lifecycle.
- Agent Action Capsule supplies a candidate WHAT record under its own native
  Class 1 and Class 2 conformance rules.

The cross-slot mechanism tests those interfaces. It does not replace their
specifications or move enforcement into an evidence record.

## 2. Bundle requirements

Every bundle pins:

1. the Composition revision and digest;
2. each populated slot's profile and serialization-suite revision;
3. the exact action bytes and complete digest context;
4. every native record as bytes, with its native identifier and digest;
5. each additional binding, purpose, context, and verification expectation;
6. every protected cross-reference and the exact referenced bytes;
7. each compared field's declared basis and any pinned mapping;
8. the expected result of every native and join check; and
9. the expected terminal composition report.

A runner evaluates the supplied bytes. It does not substitute a reconstructed
fixture, upgrade an unknown profile, or infer an absent mapping, field basis,
purpose label, or digest representation.

## 3. Result vocabulary

Every named check returns exactly one of:

- `pass` — evaluated and the condition held;
- `fail` — evaluated and the condition did not hold;
- `not_evaluated` — a prerequisite failed or the check was not attempted;
- `unsupported` — the pinned required profile or semantics are not
  implemented; or
- `indeterminate` — the records are readable, but the comparison cannot be
  resolved from the declared inputs.

Only `pass` is a pass. The other four values are never silently upgraded. A
rejected prerequisite does not turn unexecuted downstream checks into extra
failures.

An unknown optional binding may remain structurally readable. It cannot
satisfy a policy that requires understood semantics for that binding.

## 4. Run report

A report contains:

- implementation owner, name, version, and source revision;
- bundle and input-artifact digests;
- each native slot result unchanged;
- each native slot and join's expected and actual result;
- divergence located to a named field, including both values and bases;
- the terminal composition result;
- deterministic report digest computed over the report with the
  `report_digest` member omitted; and
- known shared dependencies that limit independence.

Matching a bundle proves conformance only to those pinned vectors. It does not
certify an agent, prove every action was recorded, establish an external
effect, or replace a relying party's policy decision.

## 5. Positive, negative, and condition-removed vectors

The first pack contains one positive four-slot vector and the following
negative cases. Every negative has a condition-removed twin that changes only
the tested defect and returns to `pass`.

| ID | Changed condition | Required result |
|---|---|---|
| `COMP-BIND-01` | Different action bytes retain the positive digest | `fail` |
| `COMP-BIND-02` | Incompatible digest context or action projection | `indeterminate` |
| `COMP-BIND-03` | Raw bytes and lowercase hexadecimal are confused | `fail` |
| `COMP-BIND-04` | Protected reference names different slot bytes | `fail` |
| `COMP-BIND-05` | Additional binding omits its context | `fail` |
| `COMP-BIND-06` | Unknown optional semantics are required by policy | `unsupported`, binding remains readable |
| `COMP-BASIS-01` | Compared field lacks a declared basis | `indeterminate` |
| `COMP-BASIS-02` | Incompatible bases lack a pinned mapping | `indeterminate` |
| `COMP-RESULT-01` | Native and join results are collapsed | `fail` |
| `COMP-RESULT-02` | Composition overwrites a native result | `fail` |
| `COMP-JOIN-01` | Valid records identify different actions | `fail` |
| `COMP-JOIN-02` | `not_evaluated` is relabeled as verifier failure | `fail` |
| `COMP-UNKNOWN-01` | Unknown required profile is treated as accepted | `unsupported` |

The runnable pack therefore contains 27 cases: one positive, thirteen
negatives, and thirteen condition-removed controls.

## 6. Freeze rule

A vector freezes only after two implementations maintained by different
parties consume the same published bytes and produce reports matching every
pinned expectation. Sharing a library, generated fixture, or expected-output
file does not establish independent recomputation unless that dependency is
the declared object under test.

Changing an input byte, profile pin, expectation, canonicalization rule, or
mapping creates a new bundle and restarts the independent-run requirement.

## 7. Delivered and open

EMILIA delivers:

- the mechanism in this document;
- the manifest and exact four-slot input bytes;
- the 27-case bundle and executable runner;
- the EMILIA report and checksums; and
- an external-report template for the second implementation.

The pack is a candidate, not a frozen independent result. The remaining step
is an external implementation run over the same bytes. Capsule Class 2 remains
native to the Capsule implementation and requires its producer manifest and
bound private evidence; the cross-slot harness does not manufacture those
inputs.
