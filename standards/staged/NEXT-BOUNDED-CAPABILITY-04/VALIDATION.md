# Validation

- `xml2rfc 3.34.0 --no-network`: TXT and HTML rendered successfully from the locally cached official RFC bibliography entries.
- `idnits 3.1.0 -m submission`: PASS, no nits.
- `node scripts/check-bounded-capability-04.mjs`: PASS, including heterogeneous-relation, off-domain, untrusted-runner, stale-context, single-edge, capability-scoped operation-key, atomic root-registration, and reconciliation controls.
- `SHA256SUMS.txt`: source and both renders are pinned.

The Implementation Status section says explicitly that the new per-component relation, mechanical-establishment provenance, composition reporting, and atomic root-issuance registration rule are not yet implemented as conforming protocol operations. It separately identifies the capability-scoped operation key and terminal `not_entered` behavior that are implemented. This packet makes no independent implementation or interoperability claim for the -04 additions.
