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

## Explicitly not registered

| Suffix | Why not |
|---|---|
| `agent-actions.json` | Superseded predecessor (`EP-ACTION-RISK-MANIFEST-v0.1`); draft-schrock-agent-action-manifest-00 Section 3 supersedes it and its deployment surface (`packages/require-receipt`) is legacy. Registering it would enshrine the old name. |
