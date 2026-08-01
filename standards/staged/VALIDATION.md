# Validation record

Validated on 2026-08-01 from branch
`codex/ietf-four-draft-wave-20260801`, based on origin/main commit
`50b5af670f4a2a3444a9ecc98662cfdd82d20128`.

## Submission artifacts

- `xmllint --noout` passed for all four XML sources.
- `xml2rfc 3.34.0` generated TXT and HTML for all four sources.
- `idnits 3.1.0 -m submission` reported `PASS - No nit found` for every TXT
  rendering.
- `draft-schrock-action-evidence-boundary-03` intentionally retains the stream
  metadata behavior of the existing series. `xml2rfc` reports that it defaults
  the absent stream to IETF; submission-mode `idnits` passes.
- `standards/STATUS.json` and `ADDITIONAL-RESOURCES.json` parse as JSON.
- Every XML `docName` equals its upload filename.
- `git diff --check` passed.

## Implementation evidence checked

- AEB and legacy AEC focused suites: 41 passed, 0 failed.
- Reliance Agreement and Model-to-Matter Vitest suites: 53 passed, 0 failed.
- Model-to-Matter conformance: 15 of 15 vectors passed.
- Protocol discipline: 0 critical findings, 12 pre-existing complexity
  warnings.
- Write discipline passed.
- Repository-boundary check passed.

The AEC and Model-to-Matter sources explicitly disclose the two new normative
pieces not yet wired into their respective reference evaluators. These results
therefore support the implementation claims actually made; they do not erase
those stated gaps.
