# Validation record

Validated on 2026-09-24 from the isolated CAID -03 working packet.

- `xmllint --noout` passed for the XML source.
- `xml2rfc 3.34.0` generated the TXT and HTML renderings. The generated HTML's
  non-semantic trailing spaces were normalized before checksums were recorded.
- `idnits 3.1.0 -m submission` reported `PASS - No nit found` for the
  authoritative TXT rendering.
- The source intentionally omits `submissionType` because this remains an
  individual draft with no adopted document stream. `xml2rfc` uses its IETF
  rendering default and emits an informational warning. It also renders the
  Standards Track category with the required consensus default.
- `npm run caid:conformance` passed the registry identity check and all 55
  core, 23 mapping, and 100 consequential-action vectors in JavaScript,
  Python, and Go.
- The core corpus includes positive USD and XAD cases plus fail-closed
  `NOT-A-CURRENCY`, bare-reference, unresolved-reference, digest-mismatch,
  and inline-enum cases.
- `xmllint --noout` and `xml2rfc 3.34.0` generated the staged source and
  renderings. xml2rfc reports only its pre-existing submissionType/consensus
  warnings.

Datatracker has not published this packet. Author review and submission are
still required; the published -02 archive remains authoritative until then.
