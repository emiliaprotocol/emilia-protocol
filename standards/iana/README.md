# standards/iana — IANA registration templates

Completed, paste-ready registration templates for the IANA actions the EP
draft set names. Built 2026-07-04 from a full inventory of the IANA
Considerations sections of every draft in `standards/` (the 9-draft IETF 126
batch at top level), `standards/posted/`, and `standards/staged/`.

**The rule this directory lives by:** a registration is prepared *for* a
string only where a draft's own text carries that string, citing that draft.
Where a draft only anticipates a registration, the template is marked
**PROPOSED, requires draft text in next rev** and must not be filed until a
revision backs it. Nothing here invents a name that contradicts posted text.

## Files

- `media-type-registration.md` — RFC 6838 §5.6 templates (provisional
  standard media type path) for `application/authorization-evidence-challenge+json`
  and `application/ep-receipt+json`; explicit not-prepared list.
- `well-known-uri-registration.md` — RFC 8615 templates for
  `agent-action-control.json` (the one registration a draft already requests)
  and `ep-authority.json` (PROPOSED).
- `http-field-registration.md` — RFC 9110 §16.3.1 templates for
  `Receipt-Required` and `X-EMILIA-Receipt` (both PROPOSED; includes the
  RFC 6648 "X-" note).

## Status tracker

| # | Registration | IANA registry | Backing draft (section) | Draft text status | Template status | Gate to filing |
|---|---|---|---|---|---|---|
| 1 | `agent-action-control.json` | Well-Known URIs | draft-schrock-agent-action-manifest-00 (§3, §9) | **Requests registration** (fields in §9) | READY-ON-POST | Draft live on datatracker [verify posting after the 2026-07-06 batch upload] |
| 2 | `application/authorization-evidence-challenge+json` | Media Types (provisional, standards tree) | draft-schrock-authorization-evidence-challenge-00 (§2, §5) | String specified in §2; §5 says "a future revision will register" | READY-ON-POST (provisional); permanent registration needs the -01 to carry the template | Draft live on datatracker; -01 for permanent |
| 3 | `application/ep-receipt+json` | Media Types (provisional, standards tree) | draft-schrock-ep-authorization-receipts-05 (§12) | String specified; "may register" only | PROPOSED, requires draft text in next rev | A -06 (or later) IANA Considerations committing to it |
| 4 | `ep-authority.json` | Well-Known URIs | draft-schrock-ep-authority-introduction-00 (§8) | String specified; "anticipated for a future revision"; -00 declares no IANA actions | PROPOSED, requires draft text in next rev | Next revision carrying the request |
| 5 | `Receipt-Required` | HTTP Field Names | draft-schrock-agent-action-manifest-00 (§5 + example control object) | Field *named*, not normatively defined; no registration request | PROPOSED, requires draft text in next rev | Next-rev field definition + IANA request |
| 6 | `X-EMILIA-Receipt` | HTTP Field Names | draft-schrock-agent-action-manifest-00 (§5 + example control object) | Field *named*, not normatively defined; RFC 6648 disfavors permanent "X-" registrations | PROPOSED, requires draft text in next rev | Next-rev field definition; draft decides on any unprefixed successor |
| 7 | `application/ep-aec+json` | Media Types | draft-schrock-ep-authorization-evidence-chain-01 (§10) | Illustrative only ("e.g.") | NOT PREPARED | Chain draft must pick and fix the string first |
| 8 | `application/ep-eye-advisory+json` + SET event-type URI | Media Types / SET event URI | posted/draft-schrock-emilia-eye-00 | "may register" | NOT PREPARED | A revision committing to it |
| 9 | JWT/CWT claim names | JWT Claims / CWT Claims | draft-schrock-human-authorization-binding-00 (§8) | "anticipated for a future revision, after host-format feedback" | NOT PREPARED | Host-format feedback, then next rev |

Not IANA actions (no filing anywhere): the EP **profile registry** entries the
drafts declare — `grid.curtailment` (draft-schrock-kintzele-grid-curtailment-00),
`control_mode` values (staged human-oversight-profile), PQC algorithm
identifiers (staged ep-pqc), and the render-profile / display-attestation
identifiers the presentation-binding draft anticipates. Those live in EP's own
registry, not IANA's.

## Submission channels, per registry

### Media types (entries 2, 3)

- **Registry pages:** <https://www.iana.org/assignments/media-types> and, for
  the provisional path,
  <https://www.iana.org/assignments/provisional-standard-media-types>.
- **Community review (RFC 6838 §5.1):** post the completed template to the
  **media-types@iana.org** mailing list for review before or alongside the
  request. For standards-tree names this review is expected.
- **Filing:** the IANA media type application form at
  <https://www.iana.org/form/media-types>; select the provisional standard
  media type option for these [verify the form's current option labels — the
  form exists, the exact wording of its provisional option may have changed].
  Fallback channel: iana@iana.org.
- **Why provisional:** these subtypes are unfaceted (standards-tree) names
  defined in individual Internet-Drafts. Permanent standards-tree
  registration requires approval the drafts do not have; the provisional
  registry exists to hold a name while the specification is in development,
  and the entry is replaced or dropped when the document's fate is decided.

### Well-known URIs (entries 1, 4)

- **Registry page:** <https://www.iana.org/assignments/well-known-uris>.
- **Policy:** Specification Required with designated-expert review
  (RFC 8615 §3.1) — the specification must be publicly available, which is
  why entry 1 waits for the datatracker posting.
- **Community review:** the **wellknown-uri-review@ietf.org** mailing list
  (named in RFC 8615) for feedback before filing.
- **Filing:** send the completed template to **iana@iana.org** referencing
  the Well-Known URIs registry; IANA routes it to the designated expert.

### HTTP field names (entries 5, 6)

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

1. **Batch posts** (IETF 126 cutoff 2026-07-06). Verify each backing draft is
   live on the datatracker before citing it to IANA — a registration citing
   an unposted draft is exactly the overclaim this repo refuses to make.
2. **File entry 1** (`agent-action-control.json`) — the only registration
   whose draft text already requests it. Optional heads-up to
   wellknown-uri-review@ietf.org first.
3. **File entry 2 provisionally** (challenge media type), and put the full
   §5.6 template into the challenge draft's -01 so the permanent registration
   has draft backing.
4. **Everything else waits for draft text.** When a revision commits to a
   PROPOSED entry, update its template here to cite the new revision, flip
   the tracker row, then file.
5. After any filing, record the IANA ticket/outcome in the tracker row.

## Honesty register (applies to every template here)

- The backing documents are **active INDIVIDUAL Internet-Drafts, not
  IETF-adopted or endorsed**; "posted" means accepted and published on the
  datatracker, nothing more.
- Reference verifiers are **JavaScript, Python, and Go in one repository — a
  consistency check, not independent implementations; an externally
  authored from-spec Rust implementation (source public) agrees on all 162
  published vectors, with construction independence the implementer's
  attestation, auditable in the public source**.
- Formal models (TLA+/Alloy) cover the core state machine and quorum, **not**
  WebAuthn binding or log checkpoints.
- Verification proves signature, binding, and log integrity — **never
  business correctness**. EP is not an auditor, regulator, or insurer; its
  documents support decisions, they do not conclude them.
- A registered name is a name. It confers no adoption, no endorsement, and
  no security property.
