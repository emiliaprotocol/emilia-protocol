<!-- SPDX-License-Identifier: Apache-2.0 -->

# AEB-05 publication provenance packet

Status: published on 2026-08-31 as
`draft-schrock-action-evidence-boundary-05` through Datatracker submission
168394.

The XML under `UPLOAD-THIS/` is the exact submitted -05 source and matches the
immutable IETF archive byte-for-byte. It is retained for publication
provenance, not as an upload candidate. The revision is built around the native
compilation contract. An AuthZEN-derived local
PEP-observation path, an OAuth
transaction-challenge path, and a strict WPT-02 plus Transaction Tokens -11
path pass locally. OAuth transaction challenge and WPT/Transaction Tokens are
direct external-native candidates. The two-profile gate remains open pending
native-owner review, the full paired-control audit, and an explicit judgment
that the two OAuth-adjacent candidates provide enough protocol diversity.
Those open items limit conformance claims; they did not block publication of the
proposed contract for review. The maintainer made the explicit filing decision
on 2026-08-31.

## Headline change

The candidate makes AEB the neutral compile target for consequence-bearing
actions. Native protocols keep their formats, verifiers, trust models, and
result ownership. An adapter must disclose semantic loss, bind the exact
action, expose a stable native replay unit, and preserve every AEB lifecycle
axis without inventing missing native semantics.

No new credential, permit, receipt, registry, or universal evidence envelope
is introduced.

## Files

- `UPLOAD-THIS/draft-schrock-action-evidence-boundary-05.xml`: exact submitted
  and published source retained for provenance. It is not an upload candidate.
- `RENDERS/`: checksum-pinned local text and HTML renderings. The text matches
  the immutable IETF archive byte-for-byte. The clean local HTML is retained
  because the archive delivery path injects request-specific Cloudflare markup.
- `NATIVE-COMPILATION-CONTRACT.md`: contribution-ready source text and review
  boundary for the new section.
- `ORIGIN-LABELS-NATIVE-INPUT.md`: a separate candidate considered for -05.
- `VALIDATION.md`: exact local toolchain, focused results, and remaining claim
  boundaries.
- `SHA256SUMS`: reproducible hashes for the staged source and renderings.
- `../../../conformance/composition/oauth-txn-challenge-aeb-v0.1/`: the first
  source-pinned external-native candidate and its deterministic report.
- `../../../conformance/composition/wimse-wpt02-oauth-txn-aeb-v0.1/`: the
  second source-pinned external-native candidate and its strict request-only
  conformance pack.

The origin-label candidate is not included in the current -05 XML. It is a
useful implemented input profile, but it is not the interoperability headline.
It should be added only if review shows it belongs in this revision without
turning AEB into an origin taxonomy.

## Publication and claim boundaries

1. The native compiler SDK and focused hostile tests pass.
2. Two materially unrelated external-native families compile without invented
   load-bearing semantics, with every required hostile vector and paired
   condition-removed control published. OAuth transaction challenge is the
   first candidate, and WPT-02 plus Transaction Tokens -11 is the second
   candidate. The AuthZEN-derived path uses an EMILIA-signed local PEP
   observation and does not count as a native AuthZEN artifact. Native-owner
   review, the paired-control audit, and the protocol-diversity judgment remain
   open.
3. The XML renders cleanly and the rendered text matches the intended claim
   boundary.
4. Source locks and reference reports name exact bytes and implementation
   revisions.
5. The native protocol owners have had a fair chance to review the mapping and
   nonclaims. Review is not endorsement.
6. No external protocol is described as endorsing or adopting AEB.
7. The filing decision, submission, author confirmation, and posting occurred
   on 2026-08-31. The live Datatracker record is authoritative for publication
   and status.
