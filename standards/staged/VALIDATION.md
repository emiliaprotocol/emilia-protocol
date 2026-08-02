# Validation record

Validated on 2026-08-02 from clean committed packet bytes at
`ad45d76ac2485fd12d7ccc4a7246246a93f80113`. The XML dates are 2026-08-03
for the intended upload day. This record-only follow-up does not alter an XML,
render, or checksum from that packet commit.

## Submission artifacts

- `xmllint --noout` passed for all six XML sources.
- `xml2rfc 3.34.0` generated TXT and HTML for all six sources.
- `idnits 3.1.0 -m submission` reported `PASS - No nit found` for every TXT
  rendering.
- Every source explicitly declares `submissionType="IETF"`.
- `standards/STATUS.json` and `ADDITIONAL-RESOURCES.json` parse as JSON.
- Every XML `docName` equals its upload filename.
- `npm run check:standards-staged` verified the exact six-file inventory,
  twelve-render inventory, dates, submission types, JSON metadata, exact
  checksum-manifest coverage, and all eighteen artifact digests.
- `git diff --check` passed.

## Implementation evidence checked

- AEB, legacy AEC, and the FIDO/AP2 composition suite: 61 passed, 0 failed
  (59 Node tests plus 2 Vitest corpus tests).
- Reliance Agreement and Model-to-Matter Vitest suites: 63 passed, 0 failed.
- Model-to-Matter conformance: 15 of 15 vectors passed.
- Bounded Capability and Bounded Execution focused runtime suites: 69 passed,
  0 failed. The generated bounded-execution artifacts checked at 27 syntax
  cases, 17 runtime traces, one known answer, and 5 hostile report cases.
- Protocol discipline: 0 critical findings, 13 pre-existing complexity
  warnings.
- Write discipline passed.
- Repository-boundary check passed.

The AEC and Model-to-Matter sources explicitly disclose the two new normative
pieces not yet wired into their respective reference evaluators. These results
therefore support the implementation claims actually made; they do not erase
those stated gaps.

## Focused test commands

```bash
node --test \
  packages/verify/aeb-adapter-contract.test.js \
  packages/verify/evidence-chain.test.js \
  packages/gate/fido-ap2-bridge.test.js
npx vitest run tests/fido-ap2-bridge-corpus.test.ts

npx vitest run \
  tests/reliance-agreement.test.ts \
  tests/model-to-matter.test.ts \
  tests/model-to-matter-security-branches.test.ts

node --test \
  packages/gate/capability-receipt.test.js \
  packages/gate/authority-allocation.test.js \
  packages/gate/capability-gate.test.js \
  packages/gate/bounded-execution-program.test.js \
  packages/gate/bounded-execution-report.test.js \
  packages/gate/bounded-execution-package-resolution.test.mjs
```
