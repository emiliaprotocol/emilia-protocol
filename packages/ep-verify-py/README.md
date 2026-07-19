# ep-verify

One-line offline verifier for EMILIA Protocol authorization receipts
(EP-RECEIPT-v1). A thin CLI over [`emilia-verify`](https://pypi.org/project/emilia-verify/),
so `ep-verify` is the same verb on PyPI and npm.

```bash
pip install ep-verify
ep-verify receipt.json --keys keys.json
```

Prints `VERIFIED` or `REFUSED` plus one machine-readable JSON line;
exit code 0 only on VERIFIED. Fully offline, fail closed: a missing key,
unreadable file, or verifier error is a refusal, never a pass.

What VERIFIED means: the Ed25519 signature over the canonical (RFC 8785)
payload validates against a key **you** pinned, and any Merkle anchor is
consistent. What it does NOT mean: that the action was correct, sufficient,
or accepted by any relying party; acceptance is a relying-party decision.

Apache-2.0. Part of the EMILIA Protocol reference tooling:
https://github.com/emiliaprotocol/emilia-protocol
