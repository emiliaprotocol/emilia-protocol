# Synthetic Claim Assurance reference

This fixture demonstrates the full Claim Case to Assurance Record path without using customer data, a production deployment, or a real institutional source.

Everything in the scenario is fictional. `VERIFIED` means only that two synthetic artifacts satisfied the exact, caller-pinned synthetic profile at the fixed evaluation time. The record is not a certificate, does not report a customer outcome, and cannot authorize an action. Its required `authorizes_action` field is `false`.

The profile pins the SHA-256 digest of `reference-verifier.mjs`. The generator recomputes that digest, replays the case with the pinned profile and verifier, checks the resulting content-addressed record, and rejects byte drift.

```sh
npm --prefix packages/verify run build
node examples/claim-assurance-reference/generate.mjs --check
```

The public resolver exposes only the exact committed record ID. It has no list, search, upload, database, customer, or private-data surface.
