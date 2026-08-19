# Source register

Access date for all web sources: 2026-08-16 unless stated otherwise. Primary or
first-party sources are preferred for claims about their own work, route, or
event. Independent reporting is used only to correlate the public incident
record, not to replace primary papers.

## AIUC-1 route and cadence

### A1. AIUC-1, Provide input on AIUC-1

- URL: https://www.aiuc-1.com/learn/contribute
- Role: official contribution route.
- Read: the page welcomes feedback, ideas, suggestions, and criticism. The
  first-party page's action button identifies Typeform `DgTl55CN`. The page
  also states a quarterly update schedule of January 15, April 15, July 15,
  and October 15.
- Limit: the page does not publish an external-input deadline.

### A2. AIUC-1 changelog

- URL: https://www.aiuc-1.com/changelog
- Role: official release history and future release statement.
- Read: the page says the most recent version was released July 15, 2026 and
  the next will be released October 15, 2026. Its tenets repeat the January 15,
  April 15, July 15, and October 15 quarterly cadence. Standard history lists
  October 1, 2025 as one historical version date.
- Limit: a release date is not a submission deadline; the page publishes no
  contribution cutoff.

### A3. AIUC-1 public input form endpoint

- URL: https://form.typeform.com/to/DgTl55CN
- Role: form opened by the official contribution page.
- Read: endpoint returned HTTP 200 during a read-only check.
- Limit: no fields were entered and no submission was made.

## Primary prior art

### P1. Hao-Hsuan Chen, Insuring Every Action

- Abstract and versions: https://arxiv.org/abs/2605.25632
- Full text: https://arxiv.org/html/2605.25632
- DOI: https://doi.org/10.48550/arXiv.2605.25632
- Version read: arXiv v1, submitted 2026-05-25.
- Relevant parts: Sections 3.1 (seven action classes), 3.2
  (quote-bind-commit), 3.8 (separate operational, audit, and pricing streams),
  6 (stress-test boundary), and 7 (scope and limitations).
- Source role: primary paper by the author.

### P2. Kevin Wei and Lennart Heim, Designing Incident Reporting Systems

- Full version: https://arxiv.org/abs/2511.05914
- AAAI article: https://ojs.aaai.org/index.php/AAAI/article/view/41139
- AAAI PDF: https://ojs.aaai.org/index.php/AAAI/article/download/41139/45100
- DOI: https://doi.org/10.1609/aaai.v40i44.41139
- Version read: full arXiv text and AAAI-26 paper.
- Relevant parts: incident and near-miss definition; seven institutional
  design dimensions; Section 4.7 on information sharing, standardization, and
  interoperability; Section 5 limitations; and the stated exclusion of
  operational-level details.
- Source role: primary paper by the authors.

## Worked incident

### I1. AI Incident Database Incident 1152

- URL: https://incidentdatabase.ai/cite/1152
- Role: canonical identifier, incident date, allegation posture, description,
  applied MIT taxonomy, and five-report aggregation.
- Read: AIID describes reported deletion of a live production database during
  an active code freeze despite repeated no-change instructions. It records
  Incident ID 1152 and incident date 2025-07-18.
- Limit: AIID is a curated public incident record, not an execution log.

### I2. Jason Lemkin public incident account

- URL: https://x.com/jasonlk/status/1946069562723897802
- Role: affected-party account and screenshots linked from the AIID report
  chain.
- Publication date: 2025-07-18.
- Limit: party-published screenshots are attestation evidence, not a complete
  independently verifiable action-authority artifact.

### I3. Amjad Masad public operator acknowledgement

- URL: https://x.com/amasad/status/1946986468586721478
- Role: Replit CEO acknowledgement that an in-development Replit agent deleted
  production data, plus response measures.
- Publication date: 2025-07-20.
- Limit: the post does not publish the exact command, instruction record,
  action identity, state diff, or recovery log.

### I4. Replit, Inside Replit's Snapshot Engine

- URL: https://replit.com/blog/inside-replits-snapshot-engine
- Role: later first-party architecture description.
- Publication date: 2025-12-17; updated 2025-12-18.
- Read: Replit describes the risk of direct agent database access, snapshot
  rollback, development/production separation, and restricting agent access to
  the development database.
- Limit: this later architecture article is not evidence of the exact July 2025
  action or of complete recovery in Incident 1152.

## Citation and interpretation rules

1. A source supports only the claim stated in its entry.
2. AIUC-1 release dates are not converted into submission deadlines.
3. Chen's action classes are not called authorization-status codes.
4. Wei and Heim's institutional framework is not described as an operational
   evidence schema.
5. AIID and public posts retain allegation and source limitations.
6. A source's use of "verified" or similar language does not by itself satisfy
   `E3_artifact_verifiable`.
