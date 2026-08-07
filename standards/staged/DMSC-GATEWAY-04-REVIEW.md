# DMSC Agent Gateway -04 coauthor review

Status: coauthor review note; not a Datatracker upload packet.

Source reviewed: `draft-dunbar-dmsc-gw-scenarios-gap-analysis-03`, published
6 August 2026 by Linda Dunbar, YiFei Wang, Iman Schrock, and Bing Liu.

## What -03 added

- human-approval evidence carried inline or by reference across gateways;
- binding to a canonical action representation or digest;
- receiving-gateway evaluation under its own trust anchors and policy;
- refusal for missing, unverifiable, expired, revoked, stale, or mismatched
  evidence;
- separate records for evidence verification and the local authorization
  decision; and
- atomic reservation and consumption for single-use evidence, with no silent
  retry after an indeterminate outcome.

This is the first coauthored revision and materially strengthens Sections 6.7,
6.9, and 7.7. It is an active individual Internet-Draft, not a DMSC-adopted
document or IETF endorsement.

## Corrections for -04

1. Regenerate the document with current Internet-Draft boilerplate. The -03
   plaintext fails submission-mode `idnits` on the ID indication, expiration
   line, required draft-status paragraph, and current-drafts pointer.
2. Make the expiration date internally consistent. The cover says 6 February
   2027, the body says 6 February 2026, and page footers say 6 December 2027.
3. Add the missing RFC 8174 normative reference used by the BCP 14 paragraph.
4. Add informative related-work references for the mechanisms named in the new
   text: CAID-02 for exact-action identification and mapping, Authorization
   Receipts-10 for action-bound approval evidence, and AEB-03 for executor-side
   refusal, atomic consumption, and indeterminate-outcome handling. These
   references identify available mechanisms; they do not make them mandatory
   or claim DMSC adoption.
5. Replace the `TBD` Security Considerations with explicit failure cases for
   compromised evidence issuers, stale or revoked evidence, action-parameter
   substitution, replay across gateways, split-brain consumption domains, and
   false assumptions that a sending gateway's decision authorizes the receiver.
6. Correct the punctuation and editorial defects (`cross-domain deployments..`,
   the missing period after `physical-world consequences`, and inconsistent
   Gateway/gateway capitalization).

## Filing rule

Coordinate these corrections with Linda and the other coauthors. Do not file
an independent -04 or represent the mechanism-neutral profile as an EMILIA
wire-format mandate.
