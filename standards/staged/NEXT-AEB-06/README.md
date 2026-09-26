# AEB-06 publication provenance packet

Status: posted on 2026-09-24 as
`draft-schrock-action-evidence-boundary-06` through Datatracker submission
169466 (Datatracker time 2026-09-25T02:15:03Z). It is an individual
Internet-Draft. It is not a working-group item, an RFC, or IETF endorsement,
and posting is not review by the referenced protocol owners.

The XML under `UPLOAD-THIS/` is the exact submitted -06 source and matches the
immutable IETF archive byte-for-byte. The text under `RENDERS/` also matches
the archive byte-for-byte. The packet is retained for publication provenance,
not as an upload candidate. The posted snapshot, superseded by -07, is
retained at
[`../../archive/draft-schrock-action-evidence-boundary-06.xml`](../../archive/draft-schrock-action-evidence-boundary-06.xml);
AEB-05 is also retained in `../../archive/`.

The revision was built from the exact published
`draft-schrock-action-evidence-boundary-05` source. That base XML has SHA-256
`53b09b275fd3868dfbea11340a71e4827c38ad3cba2fdd12595cdcf42eb6c240`.

The revision narrows AEB to the consequence-admission lifecycle after a native
authorization path has made its decision. In particular, it:

- composes after the native identity and authorization systems in use, such
  as OAuth, AuthZEN, COAZ, AP2, or local authorization, including deployments
  that follow the WIMSE AIMS profile of existing standards;
- leaves COAZ authoritative for operation-to-SARC mapping and PEP enforcement;
- uses CAID only when independently encoded action formats must be joined;
- uses AEC only when local policy requires multiple evidence legs;
- does not require a second PDP or define a universal token;
- distinguishes an authorized MCP or API request from a downstream provider
  effect; and
- defines the post-permit sequence as stable replay identity, durable consume
  or reserve, provider entry, terminal or indeterminate outcome, and
  authenticated reconciliation without blind retry.

Every one-time native replay identity is fenced independently of the operation
record, so changing an operation identifier cannot make the same authority
spendable again.

## Known gaps in the posted text

Review after posting found gaps that this packet does not amend. Two examples:
the text has no same-action fence that refuses a second attempt for the same
action while an earlier attempt is still in flight, and it does not specify the
signed gateway handoff that the reference packages use for the direct native
path. Its wording also describes AIMS as owning identity and authorization
semantics, although AIMS is an Informational WIMSE working-group document that
profiles existing standards. These items are carried to the next revision.

References to AP2 describe composition with its native artifacts and do not
claim AP2 interoperability.
