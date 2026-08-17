# Validation record

Validated on 2026-08-16:

- `xmllint --noout` accepted the candidate XML.
- `xml2rfc` generated the retained TXT and HTML renderings.
- `idnits 3.1.0 -m submission` reported `PASS - No nit found`.
- `formal/tamarin/run-receipt-core.sh` verified five receipt-core obligations,
  including `acceptance_prefix_integrity_after_later_reveal` at 12 steps.
- The deliberate no-consumption model remained falsified with an 11-step
  trace, preserving the expected negative result.
- Datatracker submission 167791 was author-confirmed and posted.
- The immutable archive XML SHA-256 is
  `66eaa988d974f8535063b35efadc5140331006679b5946bc372d50a16efef52d`
  and matches the submitted XML byte-for-byte.

The same-repository Tamarin model is formal evidence for the stated symbolic
property, not an independent implementation, a computational proof, trusted
time, or proof of current authorization. The retained packet is publication
provenance; posting is not working-group adoption, RFC status, or IETF
endorsement.
