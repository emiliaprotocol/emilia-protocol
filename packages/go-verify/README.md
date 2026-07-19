# emilia-verify (Go)

Zero-dependency, **offline** verification of [EMILIA Protocol](https://www.emiliaprotocol.ai) trust receipts in Go. Standard library only — no EP account, no API key, no network. Just math.

It is a faithful port of [`@emilia-protocol/verify`](https://www.npmjs.com/package/@emilia-protocol/verify) (JavaScript) and [`emilia-verify`](https://pypi.org/project/emilia-verify/) (Python), and is **byte-compatible** with both: a receipt signed on the Node or Python side verifies here, and vice versa.

## Install

```bash
go get github.com/emiliaprotocol/emilia-protocol/packages/go-verify/v2
```

## Use

```go
import (
	"fmt"
	"os"

	emiliaverify "github.com/emiliaprotocol/emilia-protocol/packages/go-verify/v2"
)

func main() {
	raw, _ := os.ReadFile("receipt.json")
	pub := "MCowBQYDK2Vw..." // signer's Ed25519 public key, base64url SPKI DER

	res := emiliaverify.VerifyReceiptJSON(raw, pub)
	fmt.Println(res.Valid)            // true if every present check passed
	fmt.Println(res.Checks.Version)   // format is EP-RECEIPT-v1
	fmt.Println(res.Checks.Signature) // Ed25519 over the canonical payload
	fmt.Println(res.Checks.Anchor)    // *bool: nil if no Merkle anchor
}
```

## What it checks

`VerifyReceiptJSON` (or `VerifyReceipt` for an already-decoded `map[string]any`) runs up to three independent checks on an `EP-RECEIPT-v1` document:

1. **Version** — the document is a supported receipt format.
2. **Signature** — Ed25519 over the **recursive canonical JSON** of `payload`, using the signer's SPKI-DER public key.
3. **Anchor** *(if present)* — the Merkle inclusion proof folds (sorted-pair SHA-256) back to the claimed root.

`Valid` is true when the version and signature pass and the anchor is either absent or valid.

Also exported: `VerifyMerkleAnchor` and `Canonicalize` for lower-level use.
The v2 fixed-arity `VerifyWebAuthnSignoff` and `VerifyQuorum` APIs remain
source-compatible. Relying parties that pin browser origins use
`VerifyWebAuthnSignoffWithOrigins` and `VerifyQuorumWithOrigins`.

## Cross-language guarantee

`go test ./...` verifies the **same JS-signed receipt fixture** that the Python
suite checks (`packages/python-verify/tests/fixtures`), and confirms tampering,
a wrong key, and a broken anchor are all rejected. Agreement on the shared
corpus is evidence of implementation consistency; it is not a proof that every
possible canonicalization input is correct.

These are same-team ports in one repository. Agreement is a cross-language
consistency check, not evidence of independent implementation.

## Release integrity

`go-release.json` binds the module path, version, and required submodule tag.
The owner-dispatched release workflow tests and attests the exact dispatched
`main` commit without write credentials. After human approval, an isolated API
job creates that tag; a final read-only job validates the public proxy origin,
checksums, and complete source tree. Direct manual tag publication is not the
supported release path.

## License

Apache-2.0
