// The Go conformance runner for the EP hybrid post-quantum VERIFICATION
// vectors. It is a SEPARATE module from packages/go-verify on purpose: that
// module promises "Zero-dependency ... Standard library only", ships without a
// go.sum, and its release chain diffs the checked-out tree against the bytes
// the Go module proxy serves. A live FIPS 204 ML-DSA-65 backend needs a
// third-party implementation, so it is pinned here instead.
module github.com/emiliaprotocol/emilia-protocol/conformance/go

go 1.22.0

toolchain go1.26.6

require (
	github.com/cloudflare/circl v1.6.1
	github.com/emiliaprotocol/emilia-protocol/packages/go-verify/v2 v2.0.0
)

require golang.org/x/sys v0.10.0 // indirect

replace github.com/emiliaprotocol/emilia-protocol/packages/go-verify/v2 => ../../packages/go-verify
