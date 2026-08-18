// SPDX-License-Identifier: Apache-2.0

// EP-RECEIPT-HYBRID-v1 -- verification of ISSUED receipts carrying BOTH an
// Ed25519 and an ML-DSA-65 (FIPS 204) signature over one set of canonical
// bytes. Ported from the verification half of
// packages/issue/src/hybrid-issuance.ts. This module never issues; emiliaverify
// holds no private key material.
//
// WHAT THE PROFILE SIGNS. The bytes both legs sign are NOT
// Canonicalize(payload). They are:
//
//	signed_material = {
//	  "@version":            "EP-RECEIPT-HYBRID-v1",
//	  "payload":             <the receipt payload>,
//	  "required_algorithms": ["Ed25519", "ML-DSA-65"]
//	}
//	message_bytes   = UTF8(Canonicalize(signed_material))
//
// The required algorithm set is INSIDE the signed bytes. That is the
// anti-stripping property and it holds two independent ways. Remove the ML-DSA
// leg and narrow required_algorithms to ["Ed25519"] so the receipt looks
// complete: the surviving Ed25519 signature no longer verifies, because the
// bytes changed, and the narrowed set is refused structurally first with
// "algorithm_set_mismatch". Leave the set intact and the missing leg is
// "hybrid_leg_missing".
//
// WHY A DISTINCT @version. EP-RECEIPT-v1 verifiers pin SupportedVersions and
// read a single signature object. Handed a hybrid receipt they refuse on the
// version check before any signature is inspected, rather than accepting it on
// the strength of the one leg they understand. VerifyReceipt in this package
// behaves exactly that way; verified by TestHybridReceiptRefusedByV1Verifier.
//
// FAIL-CLOSED. Every malformed, unknown, or stripped input returns a named
// refusal; nothing panics on caller input. With no ML-DSA backend the result
// is a refusal with reason "pq_backend_unavailable", never a pass on the
// classical leg alone.
package emiliaverify

import "strings"

// HybridReceiptProfile is used as both @version and profile.id.
const HybridReceiptProfile = "EP-RECEIPT-HYBRID-v1"

// HybridReceiptRequiredAlgorithms is the registered required algorithm set, in
// canonical order. This array is what goes into the signed material, so its
// exact contents and order are part of what every leg commits to. Treat as
// read-only.
var HybridReceiptRequiredAlgorithms = []string{"Ed25519", "ML-DSA-65"}

// Named refusals. Byte-identical strings to HYBRID_RECEIPT_REASONS in
// packages/issue/src/hybrid-issuance.ts. The JavaScript
// "agility_module_unavailable" reason has no Go counterpart: EP-SIG-AGILITY-v1
// is compiled into this package rather than resolved by dynamic import, so
// that failure mode cannot occur here.
const (
	HybridReceiptReasonMalformedReceipt     = "malformed_receipt"
	HybridReceiptReasonMalformedPayload     = "malformed_payload"
	HybridReceiptReasonUnknownProfile       = "unknown_profile"
	HybridReceiptReasonAlgorithmSetMismatch = "algorithm_set_mismatch"
	HybridReceiptReasonHybridLegMissing     = "hybrid_leg_missing"
	HybridReceiptReasonUnexpectedAlgorithm  = "unexpected_algorithm"
	HybridReceiptReasonDuplicateAlgorithm   = "duplicate_algorithm"
	HybridReceiptReasonMissingKey           = "missing_key"
	HybridReceiptReasonSignatureInvalid     = "signature_invalid"
	HybridReceiptReasonPQBackendUnavailable = "pq_backend_unavailable"
)

// HybridReceiptKeys pins one verification key per leg. Ed25519PublicKey is
// base64url SPKI DER; MldsaPublicKey is base64url of the raw 1952-byte
// encoding.
type HybridReceiptKeys struct {
	Ed25519PublicKey string
	Ed25519KeyID     string
	MldsaPublicKey   string
	MldsaKeyID       string
}

// HybridReceiptChecks records each independent step. A nil pointer means the
// step was never reached, which is distinct from false.
type HybridReceiptChecks struct {
	Profile         bool  `json:"profile"`
	AlgorithmSet    *bool `json:"algorithm_set"`
	LegsPresent     *bool `json:"legs_present"`
	SignaturesValid *bool `json:"signatures_valid"`
}

// HybridReceiptResult is the verdict. Reason is "" when the receipt verified.
// FailedAlgorithm names the leg a failure is attributable to, or "" when it is
// not attributable to one.
type HybridReceiptResult struct {
	Verified        bool                `json:"verified"`
	Reason          string              `json:"reason"`
	FailedAlgorithm string              `json:"failed_algorithm"`
	Checks          HybridReceiptChecks `json:"checks"`
	// SetResult is the raw EP-SIG-AGILITY-v1 set verdict, when the set
	// verifier ran. Nil when the refusal happened before that point.
	SetResult *AgileSetResult `json:"set_result"`
}

// HybridReceiptSignedMaterial builds the object both legs sign. It returns nil
// when the payload is outside the EP canonicalization profile or the algorithm
// set is not the registered one, mirroring the errors the JavaScript
// hybridSignedMaterial raises for the same inputs.
func HybridReceiptSignedMaterial(payload map[string]any, requiredAlgorithms []string) map[string]any {
	if payload == nil || !IsCanonicalizable(payload) {
		return nil
	}
	if !stringSlicesEqual(requiredAlgorithms, HybridReceiptRequiredAlgorithms) {
		return nil
	}
	algos := make([]any, 0, len(requiredAlgorithms))
	for _, a := range requiredAlgorithms {
		algos = append(algos, a)
	}
	return map[string]any{
		"@version":            HybridReceiptProfile,
		"payload":             payload,
		"required_algorithms": algos,
	}
}

// HybridReceiptSignedBytes returns UTF-8 canonical bytes of the signed
// material, or nil when the material could not be built.
func HybridReceiptSignedBytes(payload map[string]any, requiredAlgorithms []string) []byte {
	material := HybridReceiptSignedMaterial(payload, requiredAlgorithms)
	if material == nil {
		return nil
	}
	return []byte(Canonicalize(material))
}

// VerifyHybridReceiptJSON decodes raw EP-RECEIPT-HYBRID-v1 JSON and verifies
// it. This is the recommended entry point: it decodes with UseNumber so
// numeric tokens canonicalize exactly as the issuer produced them.
func VerifyHybridReceiptJSON(data []byte, keys *HybridReceiptKeys, opts AgilityOptions) HybridReceiptResult {
	doc, err := decodeJSON(data)
	if err != nil {
		return HybridReceiptResult{Reason: HybridReceiptReasonMalformedReceipt}
	}
	return VerifyHybridReceipt(doc, keys, opts)
}

// VerifyHybridReceipt verifies an already-decoded EP-RECEIPT-HYBRID-v1
// receipt. Decode the document with json.Decoder.UseNumber (or use
// VerifyHybridReceiptJSON) so canonicalization is byte-exact.
//
// Order of checks, and why:
//
//  1. Structure and profile marker. An unknown @version or profile.id refuses
//     with "unknown_profile": this is not a general receipt verifier and never
//     guesses at another format.
//  2. profile.required_algorithms must EXACTLY equal the registered set, order
//     included ("algorithm_set_mismatch"). A narrowed set is the stripping
//     attack's cover story, so it is refused structurally, before the (also
//     failing) signature check.
//  3. Exactly one signature per required algorithm: a missing leg is
//     "hybrid_leg_missing", an extra one "unexpected_algorithm", a repeat
//     "duplicate_algorithm".
//  4. The bytes are rebuilt from doc.payload and the REGISTERED set, never
//     from anything the document could have narrowed, then handed to
//     EP-SIG-AGILITY-v1 under policy hybrid_all with RequiredAlgorithms pinned
//     to the full set. Every leg must verify over identical bytes.
func VerifyHybridReceipt(doc map[string]any, keys *HybridReceiptKeys, opts AgilityOptions) HybridReceiptResult {
	checks := HybridReceiptChecks{}
	refuse := func(reason, failedAlgorithm string, setResult *AgileSetResult) HybridReceiptResult {
		return HybridReceiptResult{
			Verified:        false,
			Reason:          reason,
			FailedAlgorithm: failedAlgorithm,
			Checks:          checks,
			SetResult:       setResult,
		}
	}

	// 1. Structure and profile marker.
	if doc == nil || !IsCanonicalizable(doc) {
		return refuse(HybridReceiptReasonMalformedReceipt, "", nil)
	}
	if v, _ := doc["@version"].(string); v != HybridReceiptProfile {
		return refuse(HybridReceiptReasonUnknownProfile, "", nil)
	}
	profile, ok := doc["profile"].(map[string]any)
	if !ok {
		return refuse(HybridReceiptReasonMalformedReceipt, "", nil)
	}
	if id, _ := profile["id"].(string); id != HybridReceiptProfile {
		return refuse(HybridReceiptReasonUnknownProfile, "", nil)
	}
	checks.Profile = true

	// 2. Committed algorithm set, exact and order-sensitive.
	declared, ok := stringsFromAny(profile["required_algorithms"])
	if !ok || !stringSlicesEqual(declared, HybridReceiptRequiredAlgorithms) {
		checks.AlgorithmSet = boolPtr(false)
		return refuse(HybridReceiptReasonAlgorithmSetMismatch, "", nil)
	}
	checks.AlgorithmSet = boolPtr(true)

	// 3. Exactly one signature per required algorithm.
	rawSignatures, ok := doc["signatures"].([]any)
	if !ok || len(rawSignatures) == 0 {
		checks.LegsPresent = boolPtr(false)
		return refuse(HybridReceiptReasonHybridLegMissing, "", nil)
	}
	signatures := make([]*AgileSignature, 0, len(rawSignatures))
	presented := make(map[string]bool, len(rawSignatures))
	order := make([]string, 0, len(rawSignatures))
	for _, raw := range rawSignatures {
		entry, ok := raw.(map[string]any)
		if !ok {
			checks.LegsPresent = boolPtr(false)
			return refuse(HybridReceiptReasonMalformedReceipt, "", nil)
		}
		alg, algOK := entry["alg"].(string)
		sig, sigOK := entry["sig"].(string)
		if !algOK || !sigOK {
			checks.LegsPresent = boolPtr(false)
			return refuse(HybridReceiptReasonMalformedReceipt, "", nil)
		}
		if presented[alg] {
			checks.LegsPresent = boolPtr(false)
			return refuse(HybridReceiptReasonDuplicateAlgorithm, alg, nil)
		}
		presented[alg] = true
		order = append(order, alg)
		keyID, _ := entry["key_id"].(string)
		signatures = append(signatures, &AgileSignature{Alg: alg, Sig: sig, KeyID: keyID})
	}
	for _, alg := range HybridReceiptRequiredAlgorithms {
		if !presented[alg] {
			checks.LegsPresent = boolPtr(false)
			return refuse(HybridReceiptReasonHybridLegMissing, alg, nil)
		}
	}
	for _, alg := range order {
		if !containsString(HybridReceiptRequiredAlgorithms, alg) {
			checks.LegsPresent = boolPtr(false)
			return refuse(HybridReceiptReasonUnexpectedAlgorithm, alg, nil)
		}
	}
	checks.LegsPresent = boolPtr(true)

	// 4. Rebuild the bytes and delegate the set verdict.
	payload, ok := doc["payload"].(map[string]any)
	if !ok || !IsCanonicalizable(payload) {
		return refuse(HybridReceiptReasonMalformedPayload, "", nil)
	}
	if keys == nil || keys.Ed25519PublicKey == "" || keys.MldsaPublicKey == "" {
		return refuse(HybridReceiptReasonMissingKey, "", nil)
	}

	// The REGISTERED set, never profile.required_algorithms: the document does
	// not get to choose what it is checked against.
	messageBytes := HybridReceiptSignedBytes(payload, HybridReceiptRequiredAlgorithms)
	if messageBytes == nil {
		return refuse(HybridReceiptReasonMalformedPayload, "", nil)
	}

	verificationKeys := []*AgileVerificationKey{
		{Alg: "Ed25519", PublicKey: keys.Ed25519PublicKey, KeyID: keys.Ed25519KeyID},
		{Alg: "ML-DSA-65", PublicKey: keys.MldsaPublicKey, KeyID: keys.MldsaKeyID},
	}
	setOpts := opts
	setOpts.Policy = PolicyHybridAll
	setOpts.RequiredAlgorithms = HybridReceiptRequiredAlgorithms
	setResult := VerifyAgileSignatureSet(messageBytes, signatures, verificationKeys, setOpts)

	if setResult.Verified != nil && *setResult.Verified {
		checks.SignaturesValid = boolPtr(true)
		return HybridReceiptResult{Verified: true, Checks: checks, SetResult: &setResult}
	}

	checks.SignaturesValid = boolPtr(false)
	failedAlgorithm := ""
	failedReason := ""
	for _, r := range setResult.Results {
		if !r.Verified {
			failedAlgorithm = r.Alg
			failedReason = r.Reason
			break
		}
	}

	// Map the set verifier's reason onto this profile's named vocabulary. The
	// full agility result stays attached in SetResult so nothing is lost.
	switch {
	case setResult.Reason == AgilityReasonMissingRequiredAlgorithm:
		return refuse(HybridReceiptReasonHybridLegMissing, failedAlgorithm, &setResult)
	case strings.HasSuffix(setResult.Reason, AgilityReasonPQBackendUnavailable) || failedReason == AgilityReasonPQBackendUnavailable:
		return refuse(HybridReceiptReasonPQBackendUnavailable, failedAlgorithm, &setResult)
	case failedReason == AgilityReasonMalformedKey || failedReason == AgilityReasonAlgorithmKeyMismatch:
		return refuse(HybridReceiptReasonMissingKey, failedAlgorithm, &setResult)
	}
	return refuse(HybridReceiptReasonSignatureInvalid, failedAlgorithm, &setResult)
}

func stringsFromAny(v any) ([]string, bool) {
	raw, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
