# Validation record

Validated on 2026-08-02 from clean `main` at
`c240f978b89d0bab00cd4e7c2adf9bfd6707e4ac`, immediately before the packet
commit. The XML dates are 2026-08-03 for the intended upload day.

## Submission artifacts

- `xmllint --noout` passed for all six XML sources.
- `xml2rfc 3.34.0` generated TXT and HTML for all six sources.
- `idnits 3.1.0 -m submission` reported `PASS - No nit found` for every TXT
  rendering.
- Every source explicitly declares `submissionType="IETF"`.
- `standards/STATUS.json` and `ADDITIONAL-RESOURCES.json` parse as JSON.
- Every XML `docName` equals its upload filename.
- `git diff --check` passed.

## Implementation evidence checked

- AEB, legacy AEC, and the FIDO/AP2 composition suite: 60 passed, 0 failed.
- Reliance Agreement and Model-to-Matter Vitest suites: 63 passed, 0 failed.
- Model-to-Matter conformance: 15 of 15 vectors passed.
- Bounded Capability and Bounded Execution focused runtime suites: 75 passed,
  0 failed. The generated bounded-execution artifacts checked at 27 syntax
  cases, 17 runtime traces, one known answer, and 5 hostile report cases.
- Protocol discipline: 0 critical findings, 12 pre-existing complexity
  warnings.
- Write discipline passed.
- Repository-boundary check passed.

The AEC and Model-to-Matter sources explicitly disclose the two new normative
pieces not yet wired into their respective reference evaluators. These results
therefore support the implementation claims actually made; they do not erase
those stated gaps.
