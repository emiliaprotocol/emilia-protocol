// SPDX-License-Identifier: Apache-2.0

// EP-SIG-AGILITY-v1 -- per-artifact signature-algorithm agility for EP
// evidence, ported from packages/verify/src/pq-signature-agility.ts.
//
// VERIFICATION ONLY. This module deliberately does not port signAgile /
// signAgileSet: emiliaverify is an offline verifier and never holds private
// key material.
//
// CLOSED ALGORITHM REGISTRY. Exactly {Ed25519, ML-DSA-65} in v1. An algorithm
// outside the registry is a REFUSAL with reason "unknown_algorithm", never a
// pass-through: an INDETERMINATE algorithm never authorizes anything.
//
// FAIL-CLOSED. VerifyAgileSignature and VerifyAgileSignatureSet never panic on
// caller input: malformed message, signature, or key material returns a
// structured refusal naming the reason.
//
// DEPENDENCY POSTURE (why the ML-DSA backend is an interface). This module is
// part of a module whose README promises "Zero-dependency ... Standard library
// only". Go's standard library has no exported ML-DSA-65 implementation
// (crypto/internal/fips140/mldsa exists but is internal), so the PQ leg is a
// caller-supplied MldsaBackend. ABSENCE OF A BACKEND IS A REFUSAL with reason
// "pq_backend_unavailable" -- never a skipped check and never a pass. Every
// structural control (closed registry, algorithm/key tagging, exact length
// pins, curve pin, set policy) runs to completion whether or not a backend is
// present, so a backend-less verifier still refuses every malformed or
// stripped artifact for the same named reason the JavaScript implementation
// gives. A live backend lives outside this module in conformance/go.
package emiliaverify

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
)

// SignatureAgilityVersion is the profile marker this module implements.
const SignatureAgilityVersion = "EP-SIG-AGILITY-v1"

// AgileSignatureAlgorithms is the closed v1 algorithm registry, in canonical
// order. Treat as read-only.
var AgileSignatureAlgorithms = []string{"Ed25519", "ML-DSA-65"}

// Fixed sizes, in bytes. RFC 8032 for Ed25519; FIPS 204 ML-DSA-65 parameter
// set for the rest. These are enforced, not advisory: without the length pin a
// signature made under a DIFFERENT algorithm (an Ed448 signature relabeled
// "Ed25519", 114 bytes) could be smuggled past a verifier that only checks the
// curve, and vice versa. Both pins are required; neither alone closes it.
const (
	Ed25519SignatureBytes = 64
	MLDSA65PublicKeyBytes = 1952
	MLDSA65SecretKeyBytes = 4032
	MLDSA65SignatureBytes = 3309
)

// Named refusals. Byte-identical strings to AGILITY_REASONS in
// packages/verify/src/pq-signature-agility.ts.
const (
	AgilityReasonMalformedInput           = "malformed_input"
	AgilityReasonUnknownAlgorithm         = "unknown_algorithm"
	AgilityReasonUnknownPolicy            = "unknown_policy"
	AgilityReasonMalformedKey             = "malformed_key"
	AgilityReasonMalformedSignature       = "malformed_signature"
	AgilityReasonAlgorithmKeyMismatch     = "algorithm_key_mismatch"
	AgilityReasonSignatureInvalid         = "signature_invalid"
	AgilityReasonPQBackendUnavailable     = "pq_backend_unavailable"
	AgilityReasonDuplicateAlgorithm       = "duplicate_algorithm"
	AgilityReasonMissingRequiredAlgorithm = "missing_required_algorithm"
	AgilityReasonEmptySignatureSet        = "empty_signature_set"
)

// MldsaBackend is the ML-DSA-65 verification surface this package consumes.
// Verify reports whether signature is a valid FIPS 204 ML-DSA-65 signature by
// publicKey over message, with an EMPTY context string. Implementations MUST
// return false rather than panic on malformed input.
//
// A caller that injects a bogus always-true backend owns the PQ leg's honesty:
// the classical leg, the length pins, and the algorithm-set controls are still
// enforced independently, but "verified" then means only as much as that
// backend.
type MldsaBackend interface {
	Verify(signature, message, publicKey []byte) bool
}

// AgilitySetPolicy selects how a signature SET is collapsed into a verdict.
type AgilitySetPolicy string

const (
	// PolicyHybridAll requires every required algorithm to be present and
	// every presented signature to verify.
	PolicyHybridAll AgilitySetPolicy = "hybrid_all"
	// PolicyPerAlgorithm reports each algorithm's verdict separately and
	// leaves the top-level verdict nil. VERIFIED stays per-algorithm and is
	// never collapsed; nil never authorizes.
	PolicyPerAlgorithm AgilitySetPolicy = "per_algorithm"
)

// AgilityOptions carries the ML-DSA backend. A nil Mldsa is not an error at
// construction time; it becomes a "pq_backend_unavailable" refusal at the
// exact point the PQ leg would have been checked.
type AgilityOptions struct {
	Mldsa MldsaBackend
	// RequiredAlgorithms applies to PolicyHybridAll only: the algorithms the
	// relying party REQUIRES to be present. Empty means the FULL registry
	// (fail-closed); the default never narrows itself to what was presented.
	RequiredAlgorithms []string
	// Policy defaults to PolicyHybridAll when empty.
	Policy AgilitySetPolicy
}

// AgileSignature is one agile signature: the explicit alg field threaded
// through verification. Sig is base64url without padding.
type AgileSignature struct {
	Alg   string `json:"alg"`
	Sig   string `json:"sig"`
	KeyID string `json:"key_id,omitempty"`
}

// AgileVerificationKey is one pinned verification key, tagged with the
// algorithm it belongs to. PublicKey is base64url: SPKI DER for Ed25519, raw
// 1952-byte encoding for ML-DSA-65.
type AgileVerificationKey struct {
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
	KeyID     string `json:"key_id,omitempty"`
}

// AgileVerifyChecks records each independent step. A nil pointer means the
// step was never reached (JSON null in the JavaScript implementation), which
// is distinct from false.
type AgileVerifyChecks struct {
	AlgorithmKnown      bool  `json:"algorithm_known"`
	KeyWellformed       *bool `json:"key_wellformed"`
	SignatureWellformed *bool `json:"signature_wellformed"`
	SignatureValid      *bool `json:"signature_valid"`
}

// AgileVerifyResult is the verdict for one signature. Reason is "" when the
// signature verified (JSON null in the JavaScript implementation).
type AgileVerifyResult struct {
	Verified bool              `json:"verified"`
	Reason   string            `json:"reason"`
	Alg      string            `json:"alg"`
	KeyID    string            `json:"key_id"`
	Checks   AgileVerifyChecks `json:"checks"`
}

// AgileSetResult is the verdict for a signature SET. Verified is nil under
// PolicyPerAlgorithm, where the verdicts live in Results and are never
// collapsed.
type AgileSetResult struct {
	Policy   AgilitySetPolicy    `json:"policy"`
	Verified *bool               `json:"verified"`
	Reason   string              `json:"reason"`
	Results  []AgileVerifyResult `json:"results"`
}

func boolPtr(b bool) *bool { return &b }

// parsePinnedEd25519 resolves a CURVE-PINNED Ed25519 public key from SPKI DER.
// It returns (key, false) for a well-formed Ed25519 key, (nil, true) when the
// input is a well-formed public key of a DIFFERENT type (Ed448, P-256, RSA)
// so the caller can refuse that specifically, and (nil, false) when the input
// is not a parseable public key at all.
//
// The curve pin is the anti-masquerade control: crypto verification picks the
// algorithm from the key, so an Ed448 key relabeled "Ed25519" would otherwise
// verify an Ed448 signature.
func parsePinnedEd25519(der []byte) (ed25519.PublicKey, bool) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		// crypto/x509 refuses some SPKI algorithms that OpenSSL, and therefore
		// the Node reference implementation, parses happily -- most
		// importantly Ed448. Those must refuse as algorithm_key_mismatch, not
		// as unparseable: a well-formed public key of the WRONG algorithm is
		// exactly the masquerade the curve pin exists to name.
		if spkiNamesRecognizedNonEd25519Algorithm(der) {
			return nil, true
		}
		return nil, false
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, true
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, false
	}
	return pub, false
}

// recognizedNonEd25519SPKIOIDs lists RFC 8410 algorithm identifiers that
// crypto/x509 does not decode into a public key but OpenSSL does. The list is
// closed and standards-fixed on purpose: an OID outside it stays
// "unparseable", which is what crypto.createPublicKey does with one.
var recognizedNonEd25519SPKIOIDs = []asn1.ObjectIdentifier{
	{1, 3, 101, 110}, // id-X25519
	{1, 3, 101, 111}, // id-X448
	{1, 3, 101, 113}, // id-Ed448
}

// spkiNamesRecognizedNonEd25519Algorithm reports whether der is a well-formed
// SubjectPublicKeyInfo whose AlgorithmIdentifier names a recognized public-key
// algorithm that is not Ed25519.
func spkiNamesRecognizedNonEd25519Algorithm(der []byte) bool {
	var spki struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		PublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil || len(rest) != 0 {
		return false
	}
	for _, oid := range recognizedNonEd25519SPKIOIDs {
		if spki.Algorithm.Algorithm.Equal(oid) {
			return true
		}
	}
	return false
}

// ed25519PublicKeyFromBase64URL resolves a curve-pinned Ed25519 public key
// from base64url SPKI DER, collapsing "unparseable" and "wrong curve" into a
// single nil. EP-SIG-AGILITY-v1 refuses both with "malformed_key"; EP-HYBRID-v1
// distinguishes them and uses parsePinnedEd25519 directly.
func ed25519PublicKeyFromBase64URL(s string) ed25519.PublicKey {
	der, err := b64urlDecode(s)
	if err != nil {
		return nil
	}
	pub, _ := parsePinnedEd25519(der)
	return pub
}

func isKnownAgileAlgorithm(alg string) bool {
	for _, a := range AgileSignatureAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}

func expectedAgileSignatureBytes(alg string) int {
	if alg == "Ed25519" {
		return Ed25519SignatureBytes
	}
	return MLDSA65SignatureBytes
}

// VerifyAgileSignature verifies one agile signature over canonical artifact
// bytes. FAIL-CLOSED: every malformed or unknown input is a structured refusal
// naming the reason; an unknown algorithm NEVER verifies.
//
// A nil message is the Go analogue of the JavaScript "messageBytes is not a
// Uint8Array" guard and refuses with "malformed_input"; an empty non-nil
// message is legitimate signed material. A nil signature likewise refuses with
// "malformed_input", and a nil key refuses with "algorithm_key_mismatch"
// (matching the JavaScript ordering, where the key is checked only after the
// algorithm is known).
func VerifyAgileSignature(message []byte, signature *AgileSignature, key *AgileVerificationKey, opts AgilityOptions) AgileVerifyResult {
	checks := AgileVerifyChecks{}
	res := AgileVerifyResult{Checks: checks}
	refuse := func(reason string) AgileVerifyResult {
		res.Verified = false
		res.Reason = reason
		res.Checks = checks
		return res
	}

	if message == nil {
		return refuse(AgilityReasonMalformedInput)
	}
	if signature == nil {
		return refuse(AgilityReasonMalformedInput)
	}
	res.Alg = signature.Alg
	res.KeyID = signature.KeyID

	// 1. Algorithm: closed registry, explicit field. Unknown refuses.
	if !isKnownAgileAlgorithm(signature.Alg) {
		return refuse(AgilityReasonUnknownAlgorithm)
	}
	checks.AlgorithmKnown = true

	// 2. The key must be tagged with the SAME algorithm the signature
	//    declares. Verifying a signature under a key pinned for a different
	//    algorithm is exactly the confusion this field exists to prevent.
	if key == nil || key.Alg != signature.Alg {
		checks.KeyWellformed = boolPtr(false)
		return refuse(AgilityReasonAlgorithmKeyMismatch)
	}

	// 3. Signature bytes: strict base64url, exact expected length.
	sigBytes, err := b64urlDecode(signature.Sig)
	if err != nil || len(sigBytes) != expectedAgileSignatureBytes(signature.Alg) {
		checks.SignatureWellformed = boolPtr(false)
		return refuse(AgilityReasonMalformedSignature)
	}
	checks.SignatureWellformed = boolPtr(true)

	if signature.Alg == "Ed25519" {
		pub := ed25519PublicKeyFromBase64URL(key.PublicKey)
		if pub == nil {
			checks.KeyWellformed = boolPtr(false)
			return refuse(AgilityReasonMalformedKey)
		}
		checks.KeyWellformed = boolPtr(true)
		ok := ed25519.Verify(pub, message, sigBytes)
		checks.SignatureValid = boolPtr(ok)
		if !ok {
			return refuse(AgilityReasonSignatureInvalid)
		}
		res.Verified = true
		res.Reason = ""
		res.Checks = checks
		return res
	}

	// ML-DSA-65
	pk, err := b64urlDecode(key.PublicKey)
	if err != nil || len(pk) != MLDSA65PublicKeyBytes {
		checks.KeyWellformed = boolPtr(false)
		return refuse(AgilityReasonMalformedKey)
	}
	checks.KeyWellformed = boolPtr(true)
	if opts.Mldsa == nil {
		// No backend is a REFUSAL, never a skipped check and never a pass.
		return refuse(AgilityReasonPQBackendUnavailable)
	}
	ok := opts.Mldsa.Verify(sigBytes, message, pk)
	checks.SignatureValid = boolPtr(ok)
	if !ok {
		return refuse(AgilityReasonSignatureInvalid)
	}
	res.Verified = true
	res.Reason = ""
	res.Checks = checks
	return res
}

// VerifyAgileSignatureSet verifies a SET of agile signatures over the same
// message bytes.
//
// PolicyHybridAll (the default): Verified is true only when every algorithm in
// opts.RequiredAlgorithms (empty means the FULL registry) is present exactly
// once AND every presented signature verifies. A missing required algorithm
// refuses with "missing_required_algorithm"; that is relying-party POLICY, not
// a cryptographic set commitment. For an envelope whose signatures themselves
// commit to the full set, use EP-HYBRID-v1 (VerifyHybridEnvelope) or
// EP-RECEIPT-HYBRID-v1 (VerifyHybridReceipt).
//
// PolicyPerAlgorithm: Verified is ALWAYS nil; each algorithm's verdict is
// reported separately in Results and never collapsed.
//
// A nil signatures or keys slice is the Go analogue of the JavaScript
// "not an array" guard and refuses with "malformed_input"; an empty non-nil
// signatures slice refuses with "empty_signature_set".
func VerifyAgileSignatureSet(message []byte, signatures []*AgileSignature, keys []*AgileVerificationKey, opts AgilityOptions) AgileSetResult {
	policy := opts.Policy
	if policy == "" {
		policy = PolicyHybridAll
	}
	refuse := func(reason string, results []AgileVerifyResult) AgileSetResult {
		return AgileSetResult{Policy: policy, Verified: boolPtr(false), Reason: reason, Results: results}
	}

	if policy != PolicyHybridAll && policy != PolicyPerAlgorithm {
		return refuse(AgilityReasonUnknownPolicy, nil)
	}
	if message == nil {
		return refuse(AgilityReasonMalformedInput, nil)
	}
	if signatures == nil {
		return refuse(AgilityReasonMalformedInput, nil)
	}
	if len(signatures) == 0 {
		return refuse(AgilityReasonEmptySignatureSet, nil)
	}
	if keys == nil {
		return refuse(AgilityReasonMalformedInput, nil)
	}

	// Pinned keys by algorithm; a duplicate pin for one algorithm is malformed.
	keyByAlg := make(map[string]*AgileVerificationKey, len(keys))
	for _, k := range keys {
		if k == nil {
			return refuse(AgilityReasonMalformedKey, nil)
		}
		if _, dup := keyByAlg[k.Alg]; dup {
			return refuse(AgilityReasonDuplicateAlgorithm, nil)
		}
		keyByAlg[k.Alg] = k
	}

	// Duplicate presented algorithms refuse: one verdict per algorithm.
	presented := make(map[string]bool, len(signatures))
	for _, s := range signatures {
		alg := ""
		if s != nil {
			alg = s.Alg
		}
		if presented[alg] {
			return refuse(AgilityReasonDuplicateAlgorithm, nil)
		}
		presented[alg] = true
	}

	results := make([]AgileVerifyResult, 0, len(signatures))
	for _, s := range signatures {
		var key *AgileVerificationKey
		if s != nil {
			key = keyByAlg[s.Alg]
		}
		results = append(results, VerifyAgileSignature(message, s, key, opts))
	}

	if policy == PolicyPerAlgorithm {
		// Never collapse: verdicts stay per-algorithm; nil never authorizes.
		return AgileSetResult{Policy: policy, Verified: nil, Reason: "", Results: results}
	}

	required := opts.RequiredAlgorithms
	if len(required) == 0 {
		required = AgileSignatureAlgorithms
	}
	for _, alg := range required {
		if !presented[alg] {
			return refuse(AgilityReasonMissingRequiredAlgorithm, results)
		}
	}
	for _, r := range results {
		if !r.Verified {
			alg := r.Alg
			if alg == "" {
				alg = "unknown"
			}
			return refuse(alg+":"+r.Reason, results)
		}
	}
	return AgileSetResult{Policy: policy, Verified: boolPtr(true), Reason: "", Results: results}
}
