<!-- SPDX-License-Identifier: Apache-2.0 -->
# The land map — July 2026 fleet sweep

Source: 20-agent adversarial audit + landscape sweep (2026-07-02; 15 adjacent
documents read end-to-end, every land claim cited to the section that leaves
it open). Companion to `AGENT-AUTHORIZATION-LANDSCAPE-2026.md` (June survey).

## The meta-finding: one slot, stubbed eleven times

Every adjacent draft reserves a place for "the human authorization" and then
declines to define it. The named, empty slots:

| Host document | The stubbed slot |
|---|---|
| mih capsule | `disposition.approver='human'` — authority kept opaque, out of scope |
| munoz permit | `authority_context` — explicit stub, author declines semantics |
| sharif audit-trail | `human_override` field + undefined "Agent Passport" slot |
| bates ATP | optional `actor` field; profile governance punted (§16.4) |
| aylward AIGA | X.509 OID extension literally `1.3.6.1.4.1.99999.1` TBD |
| nelson DRP | single-signer by design; multi-party declared out of scope |
| rosenberg CHEQ | signature / multi-signature syntax "TBD" |
| yossif PSEA | Verifier/Attestation-Result layer out of scope (3 sections) |
| kuehlewind audit-arch | WI-5 "signed grant" — required, format unassigned |
| ACP charter | "confirmation and evidence requirements" named, no owner |
| SPICE intent-chain | `approval_ref` — field name with zero semantics |

**Flag #1 (the multiplier): `draft-schrock-human-authorization-binding-00`** —
ONE short universal profile: how any host record binds a named-human
authorization receipt (or quorum) by content digest, with verified-vs-accepted
semantics — plus a per-host mapping appendix covering the eleven slots above.
Eleven companion profiles collapse into one document. Base text already exists
(`docs/EP-HUMAN-AUTHORIZATION-CLAIM.md`). Effort: days. File first post-126.

## The WIMSE parcel, stated precisely (Iman, 2026-07-03)

WIMSE's charter is the deed: it scopes the WG to runtime workload identity
and security context and EXPLICITLY will not define personal identities. So
WIMSE can say "workload X from trust domain Y proved possession of key K,
calling this service, optionally carrying user/transaction context" — and
structurally cannot say "this named human, with authority under this org
policy, approved this exact irreversible action, once, before execution,
offline-verifiable." That second sentence needs a different trust root
(human key, approver authority, policy hash, action digest, validity
window, one-time consumption, reliance semantics) — which is EP. Carrying
a user identifier != a portable, non-repudiable human authorization
receipt. The seam:

    WIT/WPT:    which workload is calling, and did it prove possession?
    EP receipt: which accountable human authorized this exact action?
    Together:   this workload made this tool call, and this human
                authorized the action it is about to perform.

Any WIMSE expansion into named-human authorization would require
recharter/SECDISPATCH — i.e., the boundary is procedural as well as
architectural. Claimed in binding-00's appendix (carry-capable JWT claim,
distinct from the eleven slot-hosts). Wave-2 follow-through: the WIT +
receipt dual-proof demo vector (days).

## The second pattern: nobody specifies revocation

WIMSE creds (none, named as unaddressed), kuehlewind (time-evolving authz,
zero revocation semantics), GAR (lifecycle events, no schema), sharif (L4
registry stub, no payload), DRP (cascade revocation: section heading, no
algorithm), txn-tokens (expiry only, by design), AIGA (one-line MUST, no
format), PSEA (lifecycle states, propagation punted), klrc (CAEP for
sessions, not human grants).

**Flag #2: generalized `draft-schrock-credential-revocation-statement-00`** —
EP's shipped revocation-statement primitive, generalized to revoke ANY
digest-addressed artifact (receipt, grant, workload credential, delegation,
PSEA enrollment), offline-verifiable, bounded-staleness. Code exists. Days.
Plus **Flag #2b (tiny)**: register a CAEP/SSF event type
`human-authorization-revoked` so the signal flows through existing Shared
Signals plumbing. Days, IANA-style process work.

## The third pattern: the decision layer really is empty everywhere

kuehlewind defines what an Auditor collects, never how it decides; GAR stops
at "export the package"; sharif has no relying-party logic; SPICE's policy
step is prose. EP-AEG (filed) claims this. The follow-through is ADAPTERS:
each host record type becomes an AEG evidence-node type with a verifier —
capsule, GAR session block, sharif chain segment, ATP DAG node, DRP receipt.
Weeks total, incremental, each one deepens the moat.

## Named one-off parcels (naming rights available)

- **SPICE actor-chain**: inference-chain + intent-chain drafts name a "Truth
  Stack" third leg — the actor chain — and leave it unwritten. Author or
  co-author `actor-chain` with them: EP's WHO becomes the named leg of a
  second cluster (SPICE) beyond SCITT. Weeks; do via co-authorship.
- **kuehlewind WI-5 "signed grant"**: required work item, unassigned. The EP
  receipt IS a signed grant; claim via a short profile + offer as WI-5 input.
- **AIGA risk classes 0-3**: undefined; map to EP evidence tiers (single
  receipt / quorum / AEG verdict) — naming-rights registry play. Days.
- **ACP gap-analysis**: the WG plans an informational gap/requirements doc;
  early contribution sets the vocabulary (named-human root, quorum,
  evidence sufficiency). Days; email-sized.
- **Morgan R1-R9 mechanism slot**: requirements draft explicitly declines to
  cite mechanisms; the emailed mapping becomes a short companion draft.

## Soft land: conformance suites for OTHER people's drafts

Almost no adjacent draft ships vectors or a reference implementation. EP owns
the tri-language conformance tooling. Publishing the vector suite for munoz's
15-check permit verification, CHEQ's accept/reject/replay flows, PSEA's
token profile, DRP's verification order, capsule's Class-1 verifier = EP
becomes the interop bar for documents it doesn't own. Days each. This is how
a small company becomes load-bearing.

## Sequencing (post-cutoff)

1. Week of Jul 7: Flag #1 (binding profile) + Flag #2 (revocation statement)
   drafted and render-clean — file when datatracker reopens (~Jul 18-20).
2. Vienna week: WHO leg lands in the co-authored composition; announcement
   threads carry the flags' existence.
3. Week of Jul 21: architecture -01 (map catches up); SPICE actor-chain
   outreach (co-author offer); CAEP event registration; ACP gap-analysis note.
4. Rolling: AEG adapters + conformance suites, one per week, announced as
   implementation reports, not new drafts (no flood).

Full per-document scan data: fleet run wf_7cbf311a-f32 (20 agents, 15 docs).
