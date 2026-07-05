# IANA Well-Known URIs registrations — EMILIA Protocol

Completed registration templates for the "Well-Known URIs" registry
established by RFC 8615 (registry:
<https://www.iana.org/assignments/well-known-uris>). See `README.md` in this
directory for submission channels and the status tracker.

**Consistency rule applied throughout:** each suffix below is the exact string
a draft carries. The backing documents are **active INDIVIDUAL
Internet-Drafts, not IETF-adopted or endorsed**.

---

## 1. agent-action-control.json

**Status: READY-ON-POST.** This is the one registration a draft's own IANA
Considerations already *requests*:
`draft-schrock-agent-action-manifest-00`, Section 9, "requests registration of
the following well-known URI in the 'Well-Known URIs' registry established by
[RFC8615]" with exactly the fields below. File it once the draft is live on
the datatracker (a Specification Required registry needs a publicly available
specification document to point at).

### Registration template (RFC 8615 §3.1)

**URI suffix:** agent-action-control.json

**Change controller:** IETF

**Specification document(s):**
draft-schrock-agent-action-manifest-00, "The Agent Action Control Manifest: A
Public Effect-Boundary Control Plane for Machine Actions" — Section 3 defines
the location and serving requirements (`/.well-known/agent-action-control.json`,
served with media type `application/json` over a transport providing server
authentication and integrity); Section 9 makes the registration request. An
active individual Internet-Draft, not IETF-adopted or endorsed; intended
status Informational.

**Status:** permanent *(as declared in the draft's Section 9. The designated
expert may prefer "provisional" for a suffix whose specification is an
individual Internet-Draft; if so, accept the provisional entry and align the
draft text in the next revision rather than arguing the point — the suffix
string is what matters.)*

**Related information:** An earlier, declaration-only predecessor document
(`EP-ACTION-RISK-MANIFEST-v0.1`, served at `/.well-known/agent-actions.json`)
is superseded by this manifest (draft Section 3) and was **never registered —
do not register the predecessor suffix**. The manifest is discovery and
declaration only; the draft is explicit (Section 6) that enforcement at the
effect boundary is authoritative and the manifest cannot relax it.

---

## 2. ep-authority.json

**Status: PROPOSED, requires draft text in next rev.**
`draft-schrock-ep-authority-introduction-00`, Section 8 (IANA Considerations):
"This document has no IANA actions. A well-known URI registration
(ep-authority.json) is anticipated for a future revision." The suffix string
is draft-specified, but the -00 explicitly declares no IANA actions, so do
**not** file this until a revision carries the registration request. The
template below is prepared so that revision can paste it in.

### Registration template (RFC 8615 §3.1)

**URI suffix:** ep-authority.json

**Change controller:** IETF

**Specification document(s):**
draft-schrock-ep-authority-introduction (revision carrying the registration
request; -00 is current: "Authority Documents and Graded Introduction: Trust
Establishment for Agent-Action Evidence Without Prior Federation", Section 2
defines the Authority Document, `EP-AUTHORITY-DOC-v1`). An active individual
Internet-Draft, not IETF-adopted or endorsed.

**Status:** provisional *(suggested for the initial filing; move to permanent
if the specification's standing later warrants it)*

**Related information:** The document served at this location introduces an
authority's keys and continuity chain for graded, replayable acceptance
(draft Sections 3-5). Serving it at a well-known location is discovery, not
trust: acceptance remains graded under the relying party's policy, and a
fetched authority document proves nothing by itself beyond what its
signatures and continuity checks verify.

---

## Explicitly NOT registered

| Suffix | Why not |
|---|---|
| `agent-actions.json` | Superseded predecessor (`EP-ACTION-RISK-MANIFEST-v0.1`); draft-schrock-agent-action-manifest-00 Section 3 supersedes it and its deployment surface (`packages/require-receipt`) is legacy. Registering it would enshrine the old name. |
