# Validation record

Date: 2026-09-23

Status: staged coauthor-review candidate; not submitted to the IETF.

## Results

- The published `-00` RFCXML remains byte-for-byte unchanged at SHA-256
  `0c656d9cbdb0701a23668420460a6d1143efcf74db8919f4a9c24f4fd5697ba6`.
- xml2rfc 3.34.0 generated the text and HTML renders successfully.
- Google Chrome generated the review PDF from the xml2rfc HTML render.
- `node scripts/check-grace-01-candidate.mjs` passed.
- The existing `check:grace-curtailment-profile` suite passed against the
  unchanged published `-00` packet.
- The existing Modbus, DNP3, and OPC-UA command-binding suites passed all 56
  focused tests. They validate the companion transport mechanics already in
  the repository; they do not establish that the thirteen new end-to-end -01
  conformance cases have been implemented.
- No energized actuation test was performed or claimed.

## idnits note

idnits 3.1.0 completed all content checks but reported
`MULTIPLE_REFERENCES_SECTION_TITLES`. The same diagnostic occurs on the
published `-00` text because both drafts use xml2rfc's normal separate
Normative References and Informative References groups. No additional idnits
warning or error was introduced by this candidate.

## Scope

These checks establish packet integrity, renderability, the agreed
cross-layer claim boundaries, and preservation of the no-energized-test limit.
They do not establish interoperability, physical actuation, meter truth,
complete mediation, utility adoption, or coauthor approval.
