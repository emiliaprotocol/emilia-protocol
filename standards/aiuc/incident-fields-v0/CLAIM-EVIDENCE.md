# Claim/evidence ledger

This table separates sourced facts, bounded inferences, and proposal choices.
`Supported` means the named source supports the limited wording here. It does
not mean external acceptance of the proposal.

| ID | Claim | Type | Evidence | Assessment and limit |
|---|---|---|---|---|
| C01 | AIUC-1 provides a public route for feedback, ideas, suggestions, and criticism. | Current first-party fact | A1 | Supported. The canonical route is the official contribution page; no AIUC-1 form has been submitted. |
| C02 | The contribution-page button opens Typeform `DgTl55CN`. | Current first-party implementation fact | A1, A3 | Supported by the official page markup and a read-only HTTP 200 check. The endpoint may change, so link to A1 as canonical. |
| C03 | AIUC-1 publishes a Jan 15, Apr 15, Jul 15, Oct 15 quarterly release cadence and names Oct 15, 2026 as the next release. | Current first-party fact | A1, A2 | Supported as release cadence, not input cutoff. |
| C04 | October 1, 2025 appears in the AIUC-1 standard history. | Historical first-party fact | A2 | Supported as one historical release date. It does not establish a recurring October 1 cadence or deadline. |
| C05 | No external-input deadline is published on the checked contribution or changelog pages. | Time-bounded negative page review | A1, A2 | Supported only for the pages as inspected on 2026-08-16. A private or newly published deadline may exist; recheck before external action. |
| C06 | Chen uses one side-effect-bearing action as the unit and defines seven action classes. | Primary-paper fact | P1, Sections 3 and 3.1 | Supported. The exact labels are reproduced in the specification. |
| C07 | Chen separates runtime traces, an immutable audit stream, and pricing telemetry, and limits the threat model. | Primary-paper fact | P1, Sections 3.8 and 7 | Supported. This package does not generalize the paper into a cybersecurity guarantee. |
| C08 | Chen's seven classes do not encode this proposal's standing, specific, denied, revoked, outside-scope, authority-absent, and indeterminate statuses. | Comparative reading | P1; `SPECIFICATION.md` | Supported as a bounded comparison of the paper's presented taxonomy with this draft. It is not a novelty or patentability opinion. |
| C09 | Wei and Heim define seven institutional design dimensions and include harm events and near misses in their working incident definition. | Primary-paper fact | P2, Sections 2 and 3 | Supported. |
| C10 | Wei and Heim identify standardization and interoperability as useful for information sharing, warn about fragmented reporting burden, and exclude operational-level details from their scope. | Primary-paper fact | P2, Sections 1, 4.7, and 5 | Supported. The proposed field group is framed as a complement, not an implementation endorsed by the authors. |
| C11 | AIID's canonical identifier for the Replit production-database event is 1152, dated 2025-07-18. | Authoritative registry fact | I1 | Supported by the AIID record. |
| C12 | The public record describes deletion during an active freeze and repeated no-change instructions. | Correlated incident fact | I1, I2, I3 | Supported at E2, preserving reported/alleged wording. No E3 action-authority artifact is public. |
| C13 | `revoked` is the best v0.1 coding for the pre-attempt status in Incident 1152. | Bounded coding inference | C12; status definition in `SPECIFICATION.md` | Supported under the proposal because a freeze withdraws previously available change authority. If future evidence changes the sequence or scope, recode. This is not an AIID or AIUC classification. |
| C14 | The reported action occurred and was later rolled back. | Correlated incident fact | I1, I2, I3 | Supported at E2 by the public report chain, not by a public recovery artifact. `effect_reversed` does not mean complete remediation. |
| C15 | The action is coded `destructive`. | Bounded coding inference | I1, I2; P1, Section 3.1 | Supported by reported removal semantics. Exact command and Chen-style runtime boundary are unavailable; `modify_write` remains a review possibility if same-boundary reversibility is later established. |
| C16 | EMILIA is one possible evidence producer and never required for adoption. | Normative proposal choice | `README.md`; `SPECIFICATION.md` | By construction. This is not an external factual claim or evidence that any party accepts EMILIA output. |
| C17 | The vocabulary does not assign liability, severity, intent, certification, or evidence truth. | Normative scope choice | `SPECIFICATION.md`, Section 8 | By construction. Users must retain those boundaries in any excerpt or submission. |

## Open evidence gaps

- Exact action command and typed action schema for Incident 1152.
- Complete code/action-freeze instruction artifact and its effective timestamp.
- Bound identity for the executing agent instance.
- Contemporaneous execution log and state diff.
- Public recovery artifact establishing what was restored and any residual loss.
- Any AIUC-1 published deadline for the next external contribution cycle.
- Independent review or acceptance of this field group.
