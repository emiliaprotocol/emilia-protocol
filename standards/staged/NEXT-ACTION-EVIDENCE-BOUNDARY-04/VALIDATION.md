# Validation record

Validated on 2026-08-16:

- `xmllint --noout` accepted the candidate XML.
- `xml2rfc` generated the retained TXT and HTML renderings.
- `idnits 3.1.0 -m submission` reported `PASS - No nit found`.
- The candidate keeps the field-origin processing contract generic and keeps
  `EP-FIELD-ORIGIN-v0.1` informative.
- The cited implementation profile is pinned to the merge commit that carries
  the 14 deterministic Gap 6 cases.
- Datatracker submission 167790 was author-confirmed and posted.
- The immutable archive XML SHA-256 is
  `83f97307a51e7f62200df243f765cb28ee436faae70871df9cb02b15c8d43dd5`
  and matches the submitted XML byte-for-byte.

The retained packet is publication provenance. Posting is not working-group
adoption, RFC status, IETF endorsement, or external reproduction.
