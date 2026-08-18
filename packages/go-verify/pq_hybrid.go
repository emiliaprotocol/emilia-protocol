// SPDX-License-Identifier: Apache-2.0

// EP-HYBRID-v1 -- hybrid classical + post-quantum signature envelope for EP
// INFRASTRUCTURE keys (transparency-log, directory, checkpoint signing keys),
// ported from packages/verify/src/pq-hybrid.ts. Verification only.
//
// ENVELOPE
//
//	{
//	  "alg": "EP-HYBRID-v1",
//	  "signature_algos": ["Ed25519", "ML-DSA-65"],
//	  "sigs": { "Ed25519": "<base64url>", "ML-DSA-65": "<base64url>" }
//	}
//
// ANTI-STRIPPING (the property this file exists for). BOTH signatures are
// computed over a domain-separated signing input that INCLUDES a canonical
// encoding of signature_algos:
//
//	signing_input = UTF8("emilia-protocol/pq-hybrid/v1") || 0x00
//	             || UTF8(JSON(signature_algos))          || 0x00
//	             || message
//
// An attacker who strips the ML-DSA-65 signature and presents the Ed25519
// signature as a plain classical signature fails: the Ed25519 signature does
// not verify over the bare message, nor over a signing input committing to a
// reduced algorithm set. Removing an algorithm from the set changes what was
// signed, so every remaining signature fails. VerifyHybridEnvelope
// additionally requires the PRESENTED signature_algos to equal the registered
// set exactly (order-sensitive) and requires one signature per committed
// algorithm, no more and no fewer.
//
// FAIL-CLOSED. Missing, malformed, tampered, or reduced input refuses with a
// named reason. With no ML-DSA backend the result is a refusal with reason
// "pq_backend_unavailable": the PQ leg is never skipped and the envelope never
// verifies on the classical leg alone.
package emiliaverify

import "crypto/ed25519"

// HybridAlg is the envelope's alg marker.
const HybridAlg = "EP-HYBRID-v1"

// HybridSignatureAlgos is the registered algorithm set for EP-HYBRID-v1, in
// canonical order. v1 is a FIXED two-algorithm hybrid. Treat as read-only.
var HybridSignatureAlgos = []string{"Ed25519", "ML-DSA-65"}

// HybridDomain is the domain-separation label. The 0x00 separators keep label,
// algorithm set, and message unambiguous (JSON never contains a raw 0x00).
const HybridDomain = "emilia-protocol/pq-hybrid/v1"

// Named refusals. Byte-identical strings to HYBRID_REASONS in
// packages/verify/src/pq-hybrid.ts.
const (
	HybridReasonInvalidInput           = "invalid_input"
	HybridReasonInvalidEnvelope        = "invalid_envelope"
	HybridReasonAlgoSetMismatch        = "algo_set_mismatch"
	HybridReasonMissingSignature       = "missing_signature"
	HybridReasonMissingKey             = "missing_key"
	HybridReasonAlgorithmKeyMismatch   = "algorithm_key_mismatch"
	HybridReasonSignatureLengthInvalid = "signature_length_invalid"
	HybridReasonPublicKeyLengthInvalid = "public_key_length_invalid"
	HybridReasonClassicalInvalid       = "classical_signature_invalid"
	HybridReasonPQInvalid              = "pq_signature_invalid"
	HybridReasonPQBackendUnavailable   = "pq_backend_unavailable"
)

// HybridEnvelope is the EP-HYBRID-v1 wire shape.
type HybridEnvelope struct {
	Alg            string            `json:"alg"`
	SignatureAlgos []string          `json:"signature_algos"`
	Sigs           map[string]string `json:"sigs"`
}

// HybridVerificationKeys pins one key per leg. Ed25519PublicKey is base64url
// SPKI DER; MldsaPublicKey is base64url of the raw 1952-byte encoding.
type HybridVerificationKeys struct {
	Ed25519PublicKey string
	MldsaPublicKey   string
}

// HybridEnvelopeChecks records each independent step. A nil pointer means the
// step was never reached, which is distinct from false.
type HybridEnvelopeChecks struct {
	Envelope           bool  `json:"envelope"`
	AlgoSet            bool  `json:"algo_set"`
	ClassicalSignature *bool `json:"classical_signature"`
	PQSignature        *bool `json:"pq_signature"`
}

// HybridEnvelopeResult is the verdict. Reason is "" when the envelope
// verified.
type HybridEnvelopeResult struct {
	Verified bool                 `json:"verified"`
	Reason   string               `json:"reason"`
	Checks   HybridEnvelopeChecks `json:"checks"`
}

// HybridSigningInput builds the domain-separated signing input BOTH legs sign.
// It commits to the full signatureAlgos array; changing the array in any way
// (strip, reorder, substitute) changes these bytes. Returns nil when message
// is nil or signatureAlgos is empty or contains an empty string, mirroring the
// TypeError the JavaScript implementation raises for the same inputs.
func HybridSigningInput(message []byte, signatureAlgos []string) []byte {
	if message == nil || len(signatureAlgos) == 0 {
		return nil
	}
	algos := make([]any, 0, len(signatureAlgos))
	for _, a := range signatureAlgos {
		if a == "" {
			return nil
		}
		algos = append(algos, a)
	}
	out := make([]byte, 0, len(HybridDomain)+len(message)+64)
	out = append(out, HybridDomain...)
	out = append(out, 0x00)
	out = append(out, Canonicalize(algos)...)
	out = append(out, 0x00)
	out = append(out, message...)
	return out
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// VerifyHybridEnvelope verifies an EP-HYBRID-v1 envelope. Verified is true
// only when ALL of the following hold:
//
//   - the envelope is well formed and carries alg "EP-HYBRID-v1";
//   - the presented signature_algos EXACTLY equals ["Ed25519","ML-DSA-65"],
//     order included (this is also what both signatures commit to, so
//     tampering fails twice);
//   - there is exactly one signature per committed algorithm, no extras;
//   - the Ed25519 signature is valid over the committed signing input, under a
//     CURVE-PINNED Ed25519 key and an exact 64-byte length pin;
//   - the ML-DSA-65 signature is valid over the committed signing input, under
//     a 1952-byte length-pinned key and an exact 3309-byte signature length
//     pin, checked by a REAL backend. With no backend the result is a refusal
//     with reason "pq_backend_unavailable"; the PQ leg is never skipped.
//
// It never panics on caller input. A nil message refuses with "invalid_input";
// a nil envelope refuses with "invalid_envelope".
func VerifyHybridEnvelope(message []byte, envelope *HybridEnvelope, keys *HybridVerificationKeys, opts AgilityOptions) HybridEnvelopeResult {
	checks := HybridEnvelopeChecks{}
	refuse := func(reason string) HybridEnvelopeResult {
		return HybridEnvelopeResult{Verified: false, Reason: reason, Checks: checks}
	}

	if message == nil {
		return refuse(HybridReasonInvalidInput)
	}

	// 1. Envelope shape (fail closed on anything unexpected).
	if envelope == nil {
		return refuse(HybridReasonInvalidEnvelope)
	}
	if envelope.Alg != HybridAlg {
		return refuse(HybridReasonInvalidEnvelope)
	}
	if envelope.Sigs == nil {
		return refuse(HybridReasonInvalidEnvelope)
	}
	checks.Envelope = true

	// 2. Algorithm-set commitment: the presented set must EXACTLY equal the
	//    registered set. Both signatures also commit to it cryptographically.
	if !stringSlicesEqual(envelope.SignatureAlgos, HybridSignatureAlgos) {
		return refuse(HybridReasonAlgoSetMismatch)
	}
	checks.AlgoSet = true

	// 3. Exactly one signature per committed algorithm; extras refuse.
	if len(envelope.Sigs) != len(HybridSignatureAlgos) {
		if len(envelope.Sigs) < len(HybridSignatureAlgos) {
			return refuse(HybridReasonMissingSignature)
		}
		return refuse(HybridReasonInvalidEnvelope)
	}
	for _, algo := range HybridSignatureAlgos {
		if envelope.Sigs[algo] == "" {
			return refuse(HybridReasonMissingSignature)
		}
	}

	// 4. Key material. The classical key is CURVE-PINNED to Ed25519 and the PQ
	//    key LENGTH-PINNED to the FIPS 204 parameter set, so neither leg can be
	//    verified under a substituted algorithm.
	if keys == nil || keys.Ed25519PublicKey == "" || keys.MldsaPublicKey == "" {
		return refuse(HybridReasonMissingKey)
	}
	edDER, err := b64urlDecode(keys.Ed25519PublicKey)
	if err != nil {
		return refuse(HybridReasonMissingKey)
	}
	edKey, mismatch := parsePinnedEd25519(edDER)
	if mismatch {
		return refuse(HybridReasonAlgorithmKeyMismatch)
	}
	if edKey == nil {
		return refuse(HybridReasonMissingKey)
	}
	pqKey, err := b64urlDecode(keys.MldsaPublicKey)
	if err != nil || len(pqKey) == 0 {
		return refuse(HybridReasonMissingKey)
	}
	if len(pqKey) != MLDSA65PublicKeyBytes {
		return refuse(HybridReasonPublicKeyLengthInvalid)
	}

	// Decode both signatures and pin their lengths to the declared algorithms
	// BEFORE any verify call. A relabeled Ed448 signature is 114 bytes, not 64;
	// the length pin is the second half of the anti-masquerade control and the
	// curve pin above is the first.
	edSig, err := b64urlDecode(envelope.Sigs["Ed25519"])
	if err != nil || len(edSig) != Ed25519SignatureBytes {
		return refuse(HybridReasonSignatureLengthInvalid)
	}
	pqSig, err := b64urlDecode(envelope.Sigs["ML-DSA-65"])
	if err != nil || len(pqSig) != MLDSA65SignatureBytes {
		return refuse(HybridReasonSignatureLengthInvalid)
	}

	signingInput := HybridSigningInput(message, envelope.SignatureAlgos)
	if signingInput == nil {
		return refuse(HybridReasonInvalidInput)
	}

	// 5. Classical leg (Ed25519) over the committed signing input.
	edOK := ed25519.Verify(edKey, signingInput, edSig)
	checks.ClassicalSignature = boolPtr(edOK)
	if !edOK {
		return refuse(HybridReasonClassicalInvalid)
	}

	// 6. PQ leg (ML-DSA-65). No backend means REFUSE. Never skip, never pass.
	if opts.Mldsa == nil {
		return refuse(HybridReasonPQBackendUnavailable)
	}
	pqOK := opts.Mldsa.Verify(pqSig, signingInput, pqKey)
	checks.PQSignature = boolPtr(pqOK)
	if !pqOK {
		return refuse(HybridReasonPQInvalid)
	}

	return HybridEnvelopeResult{Verified: true, Reason: "", Checks: checks}
}
