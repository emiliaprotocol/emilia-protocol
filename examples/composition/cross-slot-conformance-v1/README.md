<!-- SPDX-License-Identifier: Apache-2.0 -->
# Cross-slot Composition conformance harness v1

This directory is the runnable EMILIA contribution to the conformance method
for `draft-mih-sato-agent-accountability-composition-00`.

It delivers the boundary promised in the collaboration draft:

- one positive vector populated across CAN, WHO, WHAT, and AUDIT;
- thirteen cross-slot negative cases;
- one condition-removed control for every negative;
- separately preserved native profile and join results;
- the five-value result vocabulary `pass`, `fail`, `not_evaluated`,
  `unsupported`, and `indeterminate`;
- a deterministic run report, exact checksums, and an independent-run slot.

Run and regenerate it with:

```bash
node examples/composition/cross-slot-conformance-v1/run.mjs
node examples/composition/cross-slot-conformance-v1/run.mjs --emit
(cd examples/composition/cross-slot-conformance-v1 && shasum -a 256 -c CHECKSUMS.sha256)
```

The CAID/AEC/AEB/Capsule profile-specific vector lives next door under
`caid-aec-aeb-capsule-v1`. The generic harness does not absorb or redefine
native conformance for any slot. It imports native results, preserves them,
and checks only the cross-slot boundaries.

## Freeze boundary

This repository contains EMILIA's candidate implementation and report. It is
not a frozen independent conformance result yet. Freeze requires a second
implementation, maintained by another party, to consume the same `bundle.json`
bytes and complete `external-report.template.json` with matching expectations.
