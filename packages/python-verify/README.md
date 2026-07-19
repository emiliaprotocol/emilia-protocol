# emilia-verify (Python)

Zero-infrastructure verification of **EMILIA Protocol** trust receipts — pure Python,
one dependency (`cryptography`). A faithful port of [`@emilia-protocol/verify`](https://www.npmjs.com/package/@emilia-protocol/verify):
recursive canonical JSON + Ed25519 (SPKI-DER public key) + sorted-pair Merkle anchors.

**The guarantee:** a receipt signed on the Node side verifies here, and vice versa —
proven by a cross-language test (`tests/test_verify.py` verifies a JS-signed fixture).
No EP account, no API key. Just math.

## Install
```bash
pip install emilia-verify        # once published
# or, from the repo:  pip install packages/python-verify
```

## Use
```python
from emilia_verify import verify_receipt

result = verify_receipt(receipt_doc, signer_public_key_base64url)
if result.valid:
    print("authorized by", receipt_doc["payload"]["claim"]["approver"])
else:
    print("rejected:", result.checks, result.error)
```

`verify_receipt(doc, public_key_base64url) -> VerifyResult(valid, checks, error)` checks
the version, the Ed25519 signature over the canonical payload, and (when present) the
Merkle anchor. It never raises on bad input — a malformed receipt returns `valid=False`.

Also exported: `verify_merkle_anchor(leaf_hash, proof, expected_root)` and
`canonicalize(value)` (the exact canonical-JSON used for signing).

## Why this exists
A trust receipt is only as useful as the number of places that can check it. Shipping a
verifier in the Python agent ecosystem (LangChain, CrewAI, AutoGen, LlamaIndex) means a
receipt minted anywhere can be verified offline, in the language your agent already speaks.

## Publishing (maintainers)

Direct local upload is intentionally unsupported. Create the version-matching
`python-verify-v<version>` tag from merged `main`, then manually dispatch
`publish-python-verify.yml` with the exact typed confirmation and approve the
protected `registry-publishing-approval` job. The workflow builds twice,
attests the exact wheel and source distribution, publishes through PyPI OIDC,
and byte-compares both registry artifacts.

Apache-2.0.
