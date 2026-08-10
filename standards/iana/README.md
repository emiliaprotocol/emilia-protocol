# standards/iana — IANA registration templates

Completed registration templates for the IANA actions the EP draft set names.
Built 2026-07-04 from a full inventory of the IANA Considerations sections of
the then-current public draft corpus and updated as publication paths become
known. Current published source is under `standards/posted/`; submission
packets for unposted revisions are under `standards/staged/`.

**The rule this directory lives by:** a registration is prepared *for* a
string only where a draft's own text carries that string, citing that draft.
Where a draft only anticipates a registration, the template is marked
**PROPOSED, requires draft text in next rev** and must not be filed until a
revision backs it. Nothing here invents a name that contradicts posted text.

## Files

- `http-problem-type-registration.md` — RFC 9457 registration template for
  the transport-neutral AE Challenge HTTP binding.
- `media-type-registration.md` — the active RFC 6838 §5.6 templates for
  `application/ep-authorization-receipt+json` and
  `application/ep-authorization-bundle+json`, plus the retired AE Challenge
  media-type request retained as process history.
- `well-known-uri-registration.md` — RFC 8615 template for
  `agent-action-control.json`, which a published draft already requests.
- `http-field-registration.md` — RFC 9110 §16.3.1 templates for
  `Receipt-Required` and `X-EMILIA-Receipt` (both PROPOSED; includes the
  RFC 6648 "X-" note).

## Status tracker

| # | Registration | IANA registry | Backing draft (section) | Draft text status | Template status | Gate to filing |
|---|---|---|---|---|---|---|
| 1 | `agent-action-control.json` | Well-Known URIs | draft-schrock-agent-action-manifest-00 (§3, §9) | **Requests registration** (fields in §9) | READY-ON-POST | Draft live on datatracker [verify posting after the 2026-07-06 batch upload] |
| 2 | `authorization-evidence-required` | HTTP Problem Types | draft-schrock-ae-challenge-05 (§3, §6; published 2026-08-10) | **Requests registration** under Specification Required; reuses `application/problem+json` | CARRIED-BY-DRAFT | Continue focused HTTP and Independent Stream review; do not file a conflicting direct request |
| 3 | `application/ep-authorization-receipt+json` | Media Types (standards tree) | draft-schrock-ep-authorization-receipts-11 (§13) | **Requests registration** and carries the complete RFC 6838 template | CARRIED-BY-DRAFT | Process with the Standards Track document; do not file a conflicting direct request |
| 4 | `application/ep-authorization-bundle+json` | Media Types (standards tree) | draft-schrock-ep-authorization-receipts-11 (§13) | **Requests registration** and carries the complete RFC 6838 template | CARRIED-BY-DRAFT | Process with the Standards Track document; do not file a conflicting direct request |
| 5 | `Receipt-Required` | HTTP Field Names | draft-schrock-agent-action-manifest-00 (§5 + example control object) | Field *named*, not normatively defined; no registration request | PROPOSED, requires draft text in next rev | Next-rev field definition + IANA request |
| 6 | `X-EMILIA-Receipt` | HTTP Field Names | draft-schrock-agent-action-manifest-00 (§5 + example control object) | Field *named*, not normatively defined; RFC 6648 disfavors permanent "X-" registrations | PROPOSED, requires draft text in next rev | Next-rev field definition; draft decides on any unprefixed successor |
| 7 | `application/ep-aec+json` | Media Types | draft-schrock-ep-authorization-evidence-chain-01 (§10) | Illustrative only ("e.g.") | NOT PREPARED | Chain draft must pick and fix the string first |
| 8 | `application/ep-eye-advisory+json` + SET event-type URI | Media Types / SET event URI | posted/draft-schrock-emilia-eye-00 | "may register" | NOT PREPARED | A revision committing to it |
| 9 | JWT/CWT claim names | JWT Claims / CWT Claims | draft-schrock-human-authorization-binding-00 (§8) | "anticipated for a future revision, after host-format feedback" | NOT PREPARED | Host-format feedback, then next rev |

Not IANA actions (no filing anywhere): the EP **profile registry** entries the
drafts declare — `grid.curtailment` (draft-schrock-kintzele-grid-curtailment-00),
`control_mode` values (partner-triggered human-oversight profile), historical
PQC algorithm identifiers, and the render-profile / display-attestation
identifiers the presentation-binding draft anticipates. Those live in EP's own
registry, not IANA's.

## Submission channels, per registry

### HTTP Problem Types (entry 2)

- **Registry page:** <https://www.iana.org/assignments/http-problem-types>.
- **Policy:** Specification Required with designated-expert review (RFC 9457
  §4.2 and RFC 8126 §4.6), not IETF Review or Standards Action.
- **AE Challenge:** current revision -05 retains the -03 withdrawal of the dedicated standards-tree media
  type and requests the common problem type
  `authorization-evidence-required`, recommended status 403. Process the
  registration with the Independent Stream document after focused HTTP
  review; do not reopen tickets #1456851 or #1456611.

### Media types (entries 3-4)

- **Registry pages:** <https://www.iana.org/assignments/media-types> and, where
  a provisional path is appropriate,
  <https://www.iana.org/assignments/provisional-standard-media-types>.
- **Community review (RFC 6838 §5.1):** post the completed template to the
  **media-types@iana.org** mailing list for review before or alongside the
  request. For standards-tree names this review is expected.
- **Receipt media types:** revision -11 requests
  `application/ep-authorization-receipt+json` and
  `application/ep-authorization-bundle+json`, and carries complete templates
  for both. Process them with the Standards Track document; do not revive the
  older `application/ep-receipt+json` preparation or file conflicting direct
  requests.

### Well-known URIs (entry 1)

- **Registry page:** <https://www.iana.org/assignments/well-known-uris>.
- **Policy:** Specification Required with designated-expert review
  (RFC 8615 §3.1) — the specification must be publicly available, which is
  why entry 1 waits for the datatracker posting.
- **Community review:** the **wellknown-uri-review@ietf.org** mailing list
  (named in RFC 8615) for feedback before filing.
- **Filing:** send the completed template to **iana@iana.org** referencing
  the Well-Known URIs registry; IANA routes it to the designated expert.

### HTTP field names (entries 5-6)

- **Registry page:** <https://www.iana.org/assignments/http-fields>
  (RFC 9110 §18.4; registration requirements in §16.3.1).
- **Filing:** send the completed template to **iana@iana.org** referencing
  the HTTP Field Name Registry; a designated expert reviews. Provisional
  entries are the lane for in-progress specifications.
- The HTTP WG has historically handled expert review of this registry via a
  GitHub request queue [verify — if
  <https://github.com/protocol-registries/http-fields> is active, file there;
  otherwise the iana@iana.org route stands].
- **Do not file either field** until a draft revision carries a normative
  field definition; see the PROPOSED markings in `http-field-registration.md`.

## Order of operations

1. Verify each backing draft is live on Datatracker before citing it to IANA.
2. For entry 2, continue Agent2Agent, AgentProto, HTTP-specific, and
   Independent Stream review of the published AE Challenge -05. The
   only IANA allocation is Specification Required; do not reopen the retired
   media-type tickets or file a vendor-tree substitute.
3. **File entry 1** (`agent-action-control.json`) only after re-verifying its
   current backing-draft and registry state. Optional heads-up to
   wellknown-uri-review@ietf.org first.
4. Process entries 3 and 4 with Authorization Receipts through its Standards
   Track publication path; do not file parallel direct requests.
5. **Everything else waits for draft text.** When a revision commits to a
   PROPOSED entry, update its template here to cite the new revision, flip
   the tracker row, then file.
6. After any filing, record the IANA ticket/outcome in the tracker row.

## Honesty register (applies to every template here)

- The backing documents are **active INDIVIDUAL Internet-Drafts, not
  IETF-adopted or endorsed**; "posted" means accepted and published on the
  datatracker, nothing more.
- Reference verifiers are **JavaScript, Python, and Go in one repository — a
  consistency check, not independent implementations. A separately authored
  Rust verifier is rebuilt from a pinned public commit and tree and passes the
  pinned 16-suite/164-vector clean-room bundle plus 359 hostile cases. Strict independently attested
  construction acceptance remains zero**.
- Formal models (TLA+/Alloy) cover the core state machine and quorum, **not**
  WebAuthn binding or log checkpoints.
- Verification proves signature, binding, and log integrity — **never
  business correctness**. EP is not an auditor, regulator, or insurer; its
  documents support decisions, they do not conclude them.
- A registered name is a name. It confers no adoption, no endorsement, and
  no security property.
