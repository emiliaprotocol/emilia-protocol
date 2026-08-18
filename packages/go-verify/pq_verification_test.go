// SPDX-License-Identifier: Apache-2.0

// Refusal-parity tests for the EP hybrid post-quantum VERIFICATION port.
//
// This module is stdlib-only, so no ML-DSA backend is present here. That is
// deliberate and it is the property under test: every STRUCTURAL control
// (closed registry, algorithm/key tagging, exact length pins, curve pin,
// algorithm-set commitment, set policy) must run to completion and produce the
// SAME named refusal the JavaScript implementation produces, and the PQ leg
// must refuse with "pq_backend_unavailable" rather than be skipped or passed.
//
// The live-backend half of the suite (where the ML-DSA legs actually verify)
// lives in conformance/go, which pins github.com/cloudflare/circl. Keeping it
// out of this module preserves the "Zero-dependency ... Standard library only"
// promise in README.md and the no-go.sum property the release chain checks.
package emiliaverify

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const (
	pqAgilityVectorsPath   = "../../conformance/pq-agility/vectors.json"
	hybridReceiptsVectPath = "../../conformance/hybrid-receipts/vectors.json"
)

// ---------------------------------------------------------------------------
// conformance/pq-agility/vectors.json (EP-SIG-AGILITY-v1)
// ---------------------------------------------------------------------------

type pqAgilityDoc struct {
	CanonicalPayload       string          `json:"canonical_payload"`
	CanonicalPayloadSHA256 string          `json:"canonical_payload_sha256"`
	Payload                json.RawMessage `json:"payload"`
	Keys                   struct {
		Ed25519 AgileVerificationKey `json:"ed25519"`
		MLDSA65 AgileVerificationKey `json:"ml_dsa_65"`
	} `json:"keys"`
	Vectors []struct {
		ID         string            `json:"id"`
		Kind       string            `json:"kind"`
		Policy     string            `json:"policy"`
		Signature  *AgileSignature   `json:"signature"`
		Signatures []*AgileSignature `json:"signatures"`
		Expect     struct {
			Verified     *bool           `json:"verified"`
			Reason       *string         `json:"reason"`
			PerAlgorithm map[string]bool `json:"per_algorithm"`
		} `json:"expect"`
	} `json:"vectors"`
}

func loadPQAgilityVectors(t *testing.T) pqAgilityDoc {
	t.Helper()
	raw, err := os.ReadFile(pqAgilityVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", pqAgilityVectorsPath, err)
	}
	var doc pqAgilityDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode %s: %v", pqAgilityVectorsPath, err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatalf("%s carries no vectors", pqAgilityVectorsPath)
	}
	return doc
}

// TestPQAgilityCanonicalPayloadMatches proves the Go canonicalizer reproduces
// the exact message bytes the vectors were signed over. Every later assertion
// in this file rests on that, so it is checked first and by digest.
func TestPQAgilityCanonicalPayloadMatches(t *testing.T) {
	doc := loadPQAgilityVectors(t)
	payload, err := decodeJSON(doc.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	got := Canonicalize(payload)
	if got != doc.CanonicalPayload {
		t.Fatalf("canonicalization drift\n got: %s\nwant: %s", got, doc.CanonicalPayload)
	}
	sum := sha256.Sum256([]byte(got))
	if hex.EncodeToString(sum[:]) != doc.CanonicalPayloadSHA256 {
		t.Fatalf("canonical payload digest = %s, want %s", hex.EncodeToString(sum[:]), doc.CanonicalPayloadSHA256)
	}
}

// TestPQAgilityVectorsBackendAbsent runs every checked-in EP-SIG-AGILITY-v1
// vector with NO ML-DSA backend. Ed25519 vectors must match the JavaScript
// verdict exactly. ML-DSA vectors must refuse with "pq_backend_unavailable",
// never pass and never be skipped.
func TestPQAgilityVectorsBackendAbsent(t *testing.T) {
	doc := loadPQAgilityVectors(t)
	message := []byte(doc.CanonicalPayload)
	keys := []*AgileVerificationKey{&doc.Keys.Ed25519, &doc.Keys.MLDSA65}

	for _, v := range doc.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			switch v.Kind {
			case "single":
				var key *AgileVerificationKey
				for _, k := range keys {
					if k.Alg == v.Signature.Alg {
						key = k
					}
				}
				got := VerifyAgileSignature(message, v.Signature, key, AgilityOptions{})
				wantVerified := v.Expect.Verified != nil && *v.Expect.Verified
				wantReason := ""
				if v.Expect.Reason != nil {
					wantReason = *v.Expect.Reason
				}
				// Without a backend an ML-DSA vector that JavaScript verifies
				// (or refuses for a cryptographic reason) refuses earlier, at
				// the backend, and NEVER passes.
				if v.Signature.Alg == "ML-DSA-65" {
					wantVerified = false
					wantReason = AgilityReasonPQBackendUnavailable
				}
				if got.Verified != wantVerified || got.Reason != wantReason {
					t.Fatalf("verified=%v reason=%q, want verified=%v reason=%q",
						got.Verified, got.Reason, wantVerified, wantReason)
				}

			case "set":
				opts := AgilityOptions{Policy: AgilitySetPolicy(v.Policy)}
				got := VerifyAgileSignatureSet(message, v.Signatures, keys, opts)
				if v.Policy == "per_algorithm" {
					if got.Verified != nil {
						t.Fatalf("per_algorithm verdict collapsed to %v; it must stay nil", *got.Verified)
					}
					if len(got.Results) != len(v.Expect.PerAlgorithm) {
						t.Fatalf("got %d per-algorithm results, want %d", len(got.Results), len(v.Expect.PerAlgorithm))
					}
					for _, r := range got.Results {
						jsVerdict, known := v.Expect.PerAlgorithm[r.Alg]
						if !known {
							t.Fatalf("unexpected per-algorithm result for %q", r.Alg)
						}
						if r.Alg == "ML-DSA-65" {
							if r.Verified || r.Reason != AgilityReasonPQBackendUnavailable {
								t.Fatalf("ML-DSA-65 leg: verified=%v reason=%q, want false/%s",
									r.Verified, r.Reason, AgilityReasonPQBackendUnavailable)
							}
							return
						}
						if r.Verified != jsVerdict {
							t.Fatalf("%s leg verified=%v, want %v", r.Alg, r.Verified, jsVerdict)
						}
					}
					return
				}

				// hybrid_all
				if got.Verified == nil || *got.Verified {
					t.Fatalf("hybrid_all verdict = %v; no set containing an ML-DSA leg may verify without a backend", got.Verified)
				}
				wantReason := ""
				if v.Expect.Reason != nil {
					wantReason = *v.Expect.Reason
				}
				if wantReason == "" {
					// JavaScript verifies this set. Without a backend the set
					// must refuse naming the PQ leg, never pass.
					wantReason = "ML-DSA-65:" + AgilityReasonPQBackendUnavailable
				}
				if got.Reason != wantReason {
					t.Fatalf("reason=%q, want %q", got.Reason, wantReason)
				}

			default:
				t.Fatalf("unknown vector kind %q", v.Kind)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// conformance/hybrid-receipts/vectors.json (EP-RECEIPT-HYBRID-v1)
// ---------------------------------------------------------------------------

type hybridReceiptDoc struct {
	Profile            string   `json:"profile"`
	RequiredAlgorithms []string `json:"required_algorithms"`
	Keys               map[string]struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	} `json:"keys"`
	SignedBytesSHA256 string          `json:"signed_bytes_sha256"`
	Payload           json.RawMessage `json:"payload"`
	Vectors           []struct {
		ID      string          `json:"id"`
		Receipt json.RawMessage `json:"receipt"`
		Expect  struct {
			Verified        bool    `json:"verified"`
			Reason          *string `json:"reason"`
			FailedAlgorithm *string `json:"failed_algorithm"`
		} `json:"expect"`
	} `json:"vectors"`
	V1VerifierBehaviour struct {
		HybridUnderV1 struct {
			Result struct {
				Valid bool   `json:"valid"`
				Error string `json:"error"`
			} `json:"result"`
		} `json:"hybrid-receipt-under-v1-verifier"`
	} `json:"v1_verifier_behaviour"`
}

func loadHybridReceiptVectors(t *testing.T) hybridReceiptDoc {
	t.Helper()
	raw, err := os.ReadFile(hybridReceiptsVectPath)
	if err != nil {
		t.Fatalf("read %s: %v", hybridReceiptsVectPath, err)
	}
	var doc hybridReceiptDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode %s: %v", hybridReceiptsVectPath, err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatalf("%s carries no vectors", hybridReceiptsVectPath)
	}
	return doc
}

func hybridReceiptKeys(t *testing.T, doc hybridReceiptDoc) *HybridReceiptKeys {
	t.Helper()
	ed, ok := doc.Keys["Ed25519"]
	if !ok {
		t.Fatal("vector file has no Ed25519 key")
	}
	pq, ok := doc.Keys["ML-DSA-65"]
	if !ok {
		t.Fatal("vector file has no ML-DSA-65 key")
	}
	return &HybridReceiptKeys{
		Ed25519PublicKey: ed.PublicKey,
		Ed25519KeyID:     ed.KeyID,
		MldsaPublicKey:   pq.PublicKey,
		MldsaKeyID:       pq.KeyID,
	}
}

// TestHybridReceiptSignedBytesMatch proves the Go reconstruction of the
// anti-stripping signed material is byte-identical to what the issuer signed.
// This is the whole basis of the profile: the required algorithm SET is inside
// the signed bytes, so the digest must match exactly.
func TestHybridReceiptSignedBytesMatch(t *testing.T) {
	doc := loadHybridReceiptVectors(t)
	payload, err := decodeJSON(doc.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	bytes := HybridReceiptSignedBytes(payload, HybridReceiptRequiredAlgorithms)
	if bytes == nil {
		t.Fatal("HybridReceiptSignedBytes refused a well-formed payload")
	}
	sum := sha256.Sum256(bytes)
	if hex.EncodeToString(sum[:]) != doc.SignedBytesSHA256 {
		t.Fatalf("signed bytes digest = %s, want %s\nbytes: %s",
			hex.EncodeToString(sum[:]), doc.SignedBytesSHA256, bytes)
	}
}

// TestHybridReceiptAntiStrippingReconstruction proves the narrowed algorithm
// set produces DIFFERENT signed bytes, which is why stripping a leg and
// rewriting the set cannot repair the surviving signature. It also proves the
// verifier never rebuilds the bytes from the document's own (possibly
// narrowed) claim.
func TestHybridReceiptAntiStrippingReconstruction(t *testing.T) {
	doc := loadHybridReceiptVectors(t)
	payload, err := decodeJSON(doc.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	full := HybridReceiptSignedBytes(payload, HybridReceiptRequiredAlgorithms)
	if full == nil {
		t.Fatal("registered set produced no signed bytes")
	}
	if narrowed := HybridReceiptSignedBytes(payload, []string{"Ed25519"}); narrowed != nil {
		t.Fatal("a narrowed algorithm set must never produce signable material")
	}
	if reordered := HybridReceiptSignedBytes(payload, []string{"ML-DSA-65", "Ed25519"}); reordered != nil {
		t.Fatal("a reordered algorithm set must never produce signable material")
	}
	// EP-HYBRID-v1's independent commitment: the signing input changes when the
	// committed set changes, so a stripped envelope's surviving leg fails.
	msg := []byte("shared canonical bytes")
	fullInput := string(HybridSigningInput(msg, HybridSignatureAlgos))
	narrowInput := string(HybridSigningInput(msg, []string{"Ed25519"}))
	if fullInput == narrowInput {
		t.Fatal("EP-HYBRID-v1 signing input does not commit to the algorithm set")
	}
	if !strings.HasPrefix(fullInput, HybridDomain+"\x00[\"Ed25519\",\"ML-DSA-65\"]\x00") {
		t.Fatalf("EP-HYBRID-v1 signing input prefix drift: %q", fullInput[:64])
	}
}

// TestHybridReceiptVectorsBackendAbsent runs every checked-in
// EP-RECEIPT-HYBRID-v1 vector with NO ML-DSA backend. Structural refusals must
// match JavaScript exactly, because they are decided before any signature is
// touched. Vectors that reach the cryptographic stage must refuse; the only
// place the verdict may differ from JavaScript is where the ML-DSA leg would
// have been checked, and there it must be "pq_backend_unavailable".
func TestHybridReceiptVectorsBackendAbsent(t *testing.T) {
	doc := loadHybridReceiptVectors(t)
	keys := hybridReceiptKeys(t, doc)

	// Structural refusals are decided before the first signature is inspected,
	// so they are backend-independent and must be byte-identical to JavaScript.
	structural := map[string]bool{
		"ed25519-leg-stripped":                 true,
		"ml-dsa-leg-stripped":                  true,
		"ml-dsa-leg-stripped-and-set-narrowed": true,
		"duplicate-classical-leg":              true,
		"algorithm-outside-committed-set":      true,
		"hybrid-relabelled-as-classical":       true,
	}
	// Refusals decided by the CLASSICAL leg, which is live in this module and
	// fails before the PQ leg is reached, so they too must match JavaScript.
	classical := map[string]bool{
		"classical-leg-over-different-bytes": true,
		"payload-tampered":                   true,
	}

	for _, v := range doc.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			got := VerifyHybridReceiptJSON(v.Receipt, keys, AgilityOptions{})
			if got.Verified {
				t.Fatal("a receipt verified with no ML-DSA backend; the PQ leg was skipped")
			}
			wantReason := ""
			if v.Expect.Reason != nil {
				wantReason = *v.Expect.Reason
			}
			wantAlg := ""
			if v.Expect.FailedAlgorithm != nil {
				wantAlg = *v.Expect.FailedAlgorithm
			}

			if structural[v.ID] || classical[v.ID] {
				if got.Reason != wantReason || got.FailedAlgorithm != wantAlg {
					t.Fatalf("reason=%q failed_algorithm=%q, want %q/%q",
						got.Reason, got.FailedAlgorithm, wantReason, wantAlg)
				}
				return
			}

			// Everything else is decided at the ML-DSA leg.
			if got.Reason != HybridReceiptReasonPQBackendUnavailable {
				t.Fatalf("reason=%q, want %q (JavaScript verdict here is %q)",
					got.Reason, HybridReceiptReasonPQBackendUnavailable, wantReason)
			}
			if got.FailedAlgorithm != "ML-DSA-65" {
				t.Fatalf("failed_algorithm=%q, want ML-DSA-65", got.FailedAlgorithm)
			}
		})
	}
}

// TestHybridReceiptRefusedByV1Verifier proves the EP-RECEIPT-v1 path in this
// package refuses a hybrid receipt on the VERSION check, before any signature
// is inspected, and reproduces the refusal recorded in the vector file from
// running verifyReceipt() in packages/verify. An old verifier must not accept
// a hybrid receipt on the strength of the one leg it understands.
func TestHybridReceiptRefusedByV1Verifier(t *testing.T) {
	doc := loadHybridReceiptVectors(t)
	keys := hybridReceiptKeys(t, doc)
	var hybridValid json.RawMessage
	for _, v := range doc.Vectors {
		if v.ID == "hybrid-valid" {
			hybridValid = v.Receipt
		}
	}
	if hybridValid == nil {
		t.Fatal("vector hybrid-valid not found")
	}
	res := VerifyReceiptJSON(hybridValid, keys.Ed25519PublicKey)
	want := doc.V1VerifierBehaviour.HybridUnderV1.Result
	if res.Valid != want.Valid || res.Error != want.Error {
		t.Fatalf("v1 verifier: valid=%v error=%q, want valid=%v error=%q",
			res.Valid, res.Error, want.Valid, want.Error)
	}
	if res.Checks.Version || res.Checks.Signature {
		t.Fatal("v1 verifier passed a check it must fail on a hybrid receipt")
	}
}

// ---------------------------------------------------------------------------
// Named refusal parity, exercised directly against the exact bad input
// ---------------------------------------------------------------------------

// TestAgilityNamedRefusals covers the five refusals the port is required to
// mirror by name, each against the specific malformed input that produces it.
// "fail-closed" means a refusal with a reason, so each case is proven against
// the bad input rather than asserted.
func TestAgilityNamedRefusals(t *testing.T) {
	doc := loadPQAgilityVectors(t)
	message := []byte(doc.CanonicalPayload)
	edKey := doc.Keys.Ed25519
	pqKey := doc.Keys.MLDSA65

	var edSig, pqSig *AgileSignature
	for _, v := range doc.Vectors {
		if v.Kind != "single" {
			continue
		}
		switch v.ID {
		case "ed25519-valid":
			edSig = v.Signature
		case "ml-dsa-65-valid":
			pqSig = v.Signature
		}
	}
	if edSig == nil || pqSig == nil {
		t.Fatal("vector file is missing the valid Ed25519 or ML-DSA-65 signature")
	}

	t.Run("algorithm_key_mismatch", func(t *testing.T) {
		// A valid Ed25519 signature checked against the key pinned for
		// ML-DSA-65. The tagging check refuses before any crypto runs.
		got := VerifyAgileSignature(message, edSig, &pqKey, AgilityOptions{})
		if got.Verified || got.Reason != AgilityReasonAlgorithmKeyMismatch {
			t.Fatalf("verified=%v reason=%q, want false/%s", got.Verified, got.Reason, AgilityReasonAlgorithmKeyMismatch)
		}
		if got.Checks.KeyWellformed == nil || *got.Checks.KeyWellformed {
			t.Fatal("key_wellformed must be false, not null, once the tagging check fails")
		}
	})

	t.Run("malformed_signature", func(t *testing.T) {
		// Right algorithm, right key, base64url that decodes to the wrong
		// length. The exact length pin refuses it.
		short := &AgileSignature{Alg: "Ed25519", Sig: edSig.Sig[:len(edSig.Sig)-4], KeyID: edSig.KeyID}
		got := VerifyAgileSignature(message, short, &edKey, AgilityOptions{})
		if got.Verified || got.Reason != AgilityReasonMalformedSignature {
			t.Fatalf("verified=%v reason=%q, want false/%s", got.Verified, got.Reason, AgilityReasonMalformedSignature)
		}
		// Non-base64url input is the same refusal, not a panic.
		bad := &AgileSignature{Alg: "ML-DSA-65", Sig: "not base64url!!", KeyID: pqSig.KeyID}
		got = VerifyAgileSignature(message, bad, &pqKey, AgilityOptions{})
		if got.Verified || got.Reason != AgilityReasonMalformedSignature {
			t.Fatalf("verified=%v reason=%q, want false/%s", got.Verified, got.Reason, AgilityReasonMalformedSignature)
		}
	})

	t.Run("pq_backend_unavailable", func(t *testing.T) {
		// A genuinely valid ML-DSA-65 signature under its own pinned key.
		// With no backend this REFUSES; it is never skipped and never passes.
		got := VerifyAgileSignature(message, pqSig, &pqKey, AgilityOptions{})
		if got.Verified || got.Reason != AgilityReasonPQBackendUnavailable {
			t.Fatalf("verified=%v reason=%q, want false/%s", got.Verified, got.Reason, AgilityReasonPQBackendUnavailable)
		}
		if got.Checks.SignatureWellformed == nil || !*got.Checks.SignatureWellformed {
			t.Fatal("the structural checks must complete before the backend refusal")
		}
		if got.Checks.KeyWellformed == nil || !*got.Checks.KeyWellformed {
			t.Fatal("the key length pin must complete before the backend refusal")
		}
		if got.Checks.SignatureValid != nil {
			t.Fatal("signature_valid must stay null when no backend ran")
		}
	})

	t.Run("missing_required_algorithm", func(t *testing.T) {
		// The PQ leg stripped. The required set defaults to the FULL registry
		// and never narrows itself to what was presented.
		got := VerifyAgileSignatureSet(message, []*AgileSignature{edSig},
			[]*AgileVerificationKey{&edKey, &pqKey}, AgilityOptions{})
		if got.Verified == nil || *got.Verified || got.Reason != AgilityReasonMissingRequiredAlgorithm {
			t.Fatalf("verified=%v reason=%q, want false/%s", got.Verified, got.Reason, AgilityReasonMissingRequiredAlgorithm)
		}
	})

	t.Run("unknown_algorithm_never_authorizes", func(t *testing.T) {
		got := VerifyAgileSignature(message, &AgileSignature{Alg: "Ed448", Sig: edSig.Sig}, &edKey, AgilityOptions{})
		if got.Verified || got.Reason != AgilityReasonUnknownAlgorithm {
			t.Fatalf("verified=%v reason=%q, want false/%s", got.Verified, got.Reason, AgilityReasonUnknownAlgorithm)
		}
	})

	t.Run("fail_closed_on_nil_and_empty_input", func(t *testing.T) {
		cases := []struct {
			name   string
			verify func() (bool, string)
		}{
			{name: "nil message", verify: func() (bool, string) {
				r := VerifyAgileSignature(nil, edSig, &edKey, AgilityOptions{})
				return r.Verified, r.Reason
			}},
			{name: "nil signature", verify: func() (bool, string) {
				r := VerifyAgileSignature(message, nil, &edKey, AgilityOptions{})
				return r.Verified, r.Reason
			}},
		}
		for _, c := range cases {
			verified, reason := c.verify()
			if verified || reason != AgilityReasonMalformedInput {
				t.Fatalf("%s: verified=%v reason=%q, want false/%s", c.name, verified, reason, AgilityReasonMalformedInput)
			}
		}
		empty := VerifyAgileSignatureSet(message, []*AgileSignature{}, []*AgileVerificationKey{&edKey}, AgilityOptions{})
		if empty.Verified == nil || *empty.Verified || empty.Reason != AgilityReasonEmptySignatureSet {
			t.Fatalf("empty set: reason=%q, want %s", empty.Reason, AgilityReasonEmptySignatureSet)
		}
		unknown := VerifyAgileSignatureSet(message, []*AgileSignature{edSig},
			[]*AgileVerificationKey{&edKey}, AgilityOptions{Policy: "hybrid_any"})
		if unknown.Verified == nil || *unknown.Verified || unknown.Reason != AgilityReasonUnknownPolicy {
			t.Fatalf("unknown policy: reason=%q, want %s", unknown.Reason, AgilityReasonUnknownPolicy)
		}
		dup := VerifyAgileSignatureSet(message, []*AgileSignature{edSig, edSig},
			[]*AgileVerificationKey{&edKey, &pqKey}, AgilityOptions{})
		if dup.Verified == nil || *dup.Verified || dup.Reason != AgilityReasonDuplicateAlgorithm {
			t.Fatalf("duplicate algorithm: reason=%q, want %s", dup.Reason, AgilityReasonDuplicateAlgorithm)
		}
	})
}

// TestHybridEnvelopeNamedRefusals covers EP-HYBRID-v1's own refusal vocabulary
// against the exact bad envelope, including the two halves of the
// anti-masquerade control (curve pin and length pin).
func TestHybridEnvelopeNamedRefusals(t *testing.T) {
	doc := loadPQAgilityVectors(t)
	message := []byte(doc.CanonicalPayload)
	keys := &HybridVerificationKeys{
		Ed25519PublicKey: doc.Keys.Ed25519.PublicKey,
		MldsaPublicKey:   doc.Keys.MLDSA65.PublicKey,
	}
	var edSigB64, pqSigB64 string
	for _, v := range doc.Vectors {
		if v.Kind != "single" {
			continue
		}
		switch v.ID {
		case "ed25519-valid":
			edSigB64 = v.Signature.Sig
		case "ml-dsa-65-valid":
			pqSigB64 = v.Signature.Sig
		}
	}

	full := func() *HybridEnvelope {
		return &HybridEnvelope{
			Alg:            HybridAlg,
			SignatureAlgos: []string{"Ed25519", "ML-DSA-65"},
			Sigs:           map[string]string{"Ed25519": edSigB64, "ML-DSA-65": pqSigB64},
		}
	}

	cases := []struct {
		name     string
		envelope *HybridEnvelope
		keys     *HybridVerificationKeys
		want     string
	}{
		{"nil envelope", nil, keys, HybridReasonInvalidEnvelope},
		{"wrong alg marker", &HybridEnvelope{Alg: "EP-HYBRID-v2", SignatureAlgos: HybridSignatureAlgos, Sigs: map[string]string{"Ed25519": edSigB64, "ML-DSA-65": pqSigB64}}, keys, HybridReasonInvalidEnvelope},
		{"narrowed algo set", &HybridEnvelope{Alg: HybridAlg, SignatureAlgos: []string{"Ed25519"}, Sigs: map[string]string{"Ed25519": edSigB64, "ML-DSA-65": pqSigB64}}, keys, HybridReasonAlgoSetMismatch},
		{"reordered algo set", &HybridEnvelope{Alg: HybridAlg, SignatureAlgos: []string{"ML-DSA-65", "Ed25519"}, Sigs: map[string]string{"Ed25519": edSigB64, "ML-DSA-65": pqSigB64}}, keys, HybridReasonAlgoSetMismatch},
		{"stripped pq signature", &HybridEnvelope{Alg: HybridAlg, SignatureAlgos: HybridSignatureAlgos, Sigs: map[string]string{"Ed25519": edSigB64}}, keys, HybridReasonMissingSignature},
		{"extra signature", &HybridEnvelope{Alg: HybridAlg, SignatureAlgos: HybridSignatureAlgos, Sigs: map[string]string{"Ed25519": edSigB64, "ML-DSA-65": pqSigB64, "RSA-PSS": "AAAA"}}, keys, HybridReasonInvalidEnvelope},
		{"missing keys", full(), nil, HybridReasonMissingKey},
		{"pq key wrong length", full(), &HybridVerificationKeys{Ed25519PublicKey: keys.Ed25519PublicKey, MldsaPublicKey: doc.Keys.MLDSA65.PublicKey[:100]}, HybridReasonPublicKeyLengthInvalid},
		{"classical key is unparseable", full(), &HybridVerificationKeys{Ed25519PublicKey: doc.Keys.MLDSA65.PublicKey, MldsaPublicKey: keys.MldsaPublicKey}, HybridReasonMissingKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := VerifyHybridEnvelope(message, c.envelope, c.keys, AgilityOptions{})
			if got.Verified || got.Reason != c.want {
				t.Fatalf("verified=%v reason=%q, want false/%s", got.Verified, got.Reason, c.want)
			}
		})
	}

	t.Run("signature_length_invalid", func(t *testing.T) {
		// The length pin is the second half of the anti-masquerade control: a
		// relabeled Ed448 signature is 114 bytes, not 64. Here the ML-DSA leg
		// is swapped for the 64-byte Ed25519 signature.
		env := full()
		env.Sigs["ML-DSA-65"] = edSigB64
		got := VerifyHybridEnvelope(message, env, keys, AgilityOptions{})
		if got.Verified || got.Reason != HybridReasonSignatureLengthInvalid {
			t.Fatalf("verified=%v reason=%q, want false/%s", got.Verified, got.Reason, HybridReasonSignatureLengthInvalid)
		}
	})

	t.Run("classical_signature_invalid_before_pq_backend", func(t *testing.T) {
		// The Ed25519 signature in these vectors is over the bare canonical
		// payload, NOT over the EP-HYBRID-v1 signing input, so it must fail the
		// classical leg. That is the anti-stripping property observed from the
		// other side: bytes that commit to the algorithm set are different
		// bytes.
		got := VerifyHybridEnvelope(message, full(), keys, AgilityOptions{})
		if got.Verified || got.Reason != HybridReasonClassicalInvalid {
			t.Fatalf("verified=%v reason=%q, want false/%s", got.Verified, got.Reason, HybridReasonClassicalInvalid)
		}
		if got.Checks.ClassicalSignature == nil || *got.Checks.ClassicalSignature {
			t.Fatal("classical_signature must be recorded false")
		}
		if got.Checks.PQSignature != nil {
			t.Fatal("pq_signature must stay null when the classical leg already failed")
		}
	})

	t.Run("pq_backend_unavailable_reached_only_after_classical_leg", func(t *testing.T) {
		// Build an envelope whose classical leg genuinely verifies over the
		// EP-HYBRID-v1 signing input, so the PQ leg is the next thing checked.
		// Without a backend that is a refusal, never a pass on the classical
		// leg alone.
		env, edPub := signedHybridEnvelopeForTest(t, message, pqSigB64)
		got := VerifyHybridEnvelope(message, env, &HybridVerificationKeys{
			Ed25519PublicKey: edPub,
			MldsaPublicKey:   keys.MldsaPublicKey,
		}, AgilityOptions{})
		if got.Verified || got.Reason != HybridReasonPQBackendUnavailable {
			t.Fatalf("verified=%v reason=%q, want false/%s", got.Verified, got.Reason, HybridReasonPQBackendUnavailable)
		}
		if got.Checks.ClassicalSignature == nil || !*got.Checks.ClassicalSignature {
			t.Fatal("the classical leg must have been checked and passed")
		}
		if got.Checks.PQSignature != nil {
			t.Fatal("pq_signature must stay null when no backend ran")
		}
	})
}

// signedHybridEnvelopeForTest mints an EP-HYBRID-v1 envelope whose CLASSICAL
// leg genuinely verifies over the committed signing input, pairing it with a
// real 3309-byte ML-DSA-65 signature so every length pin is satisfied and the
// PQ leg is the next thing the verifier reaches. The ML-DSA leg is not valid
// over these bytes; this helper exists to prove the classical leg passes and
// the PQ leg then refuses for want of a backend, not to fake a PQ pass.
// Returns the envelope and the base64url SPKI DER of the test public key.
func signedHybridEnvelopeForTest(t *testing.T, message []byte, pqSigB64 string) (*HybridEnvelope, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test Ed25519 key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal test public key: %v", err)
	}
	input := HybridSigningInput(message, HybridSignatureAlgos)
	if input == nil {
		t.Fatal("HybridSigningInput refused well-formed input")
	}
	return &HybridEnvelope{
		Alg:            HybridAlg,
		SignatureAlgos: []string{"Ed25519", "ML-DSA-65"},
		Sigs: map[string]string{
			"Ed25519":   base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, input)),
			"ML-DSA-65": pqSigB64,
		},
	}, base64.RawURLEncoding.EncodeToString(der)
}

// TestHybridCurvePinRefusesSubstitutedCurve proves the anti-masquerade curve
// pin against a REAL well-formed public key of another algorithm, not merely
// against unparseable bytes. Verification picks the algorithm from the key, so
// without this pin a P-256 (or Ed448) key relabelled "Ed25519" would be handed
// to a verifier that never questioned it. EP-HYBRID-v1 names this refusal
// specifically; EP-SIG-AGILITY-v1 folds it into "malformed_key".
func TestHybridCurvePinRefusesSubstitutedCurve(t *testing.T) {
	doc := loadPQAgilityVectors(t)
	message := []byte(doc.CanonicalPayload)

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	if err != nil {
		t.Fatalf("marshal P-256 key: %v", err)
	}
	substituted := base64.RawURLEncoding.EncodeToString(der)

	var edSigB64, pqSigB64 string
	for _, v := range doc.Vectors {
		if v.Kind != "single" {
			continue
		}
		switch v.ID {
		case "ed25519-valid":
			edSigB64 = v.Signature.Sig
		case "ml-dsa-65-valid":
			pqSigB64 = v.Signature.Sig
		}
	}

	env := &HybridEnvelope{
		Alg:            HybridAlg,
		SignatureAlgos: []string{"Ed25519", "ML-DSA-65"},
		Sigs:           map[string]string{"Ed25519": edSigB64, "ML-DSA-65": pqSigB64},
	}
	got := VerifyHybridEnvelope(message, env, &HybridVerificationKeys{
		Ed25519PublicKey: substituted,
		MldsaPublicKey:   doc.Keys.MLDSA65.PublicKey,
	}, AgilityOptions{})
	if got.Verified || got.Reason != HybridReasonAlgorithmKeyMismatch {
		t.Fatalf("EP-HYBRID-v1: verified=%v reason=%q, want false/%s",
			got.Verified, got.Reason, HybridReasonAlgorithmKeyMismatch)
	}

	agile := VerifyAgileSignature(message,
		&AgileSignature{Alg: "Ed25519", Sig: edSigB64},
		&AgileVerificationKey{Alg: "Ed25519", PublicKey: substituted},
		AgilityOptions{})
	if agile.Verified || agile.Reason != AgilityReasonMalformedKey {
		t.Fatalf("EP-SIG-AGILITY-v1: verified=%v reason=%q, want false/%s",
			agile.Verified, agile.Reason, AgilityReasonMalformedKey)
	}
}

// ---------------------------------------------------------------------------
// conformance/vectors/pq-hybrid-envelope.v1.json (EP-HYBRID-v1)
// ---------------------------------------------------------------------------

type hybridEnvelopeVectorDoc struct {
	Keys map[string]struct {
		SPKIB64URL      string `json:"spki_b64url"`
		PublicKeyB64URL string `json:"public_key_b64url"`
	} `json:"keys"`
	Vectors []struct {
		ID       string          `json:"id"`
		Message  string          `json:"message"`
		Envelope *HybridEnvelope `json:"envelope"`
		Keys     struct {
			Ed25519 string `json:"ed25519"`
			Mldsa   string `json:"mldsa"`
		} `json:"keys"`
		Backend string `json:"backend"`
		Expect  struct {
			Verified bool    `json:"verified"`
			Reason   *string `json:"reason"`
		} `json:"expect"`
	} `json:"vectors"`
}

// TestHybridEnvelopeVectorsBackendAbsent runs every checked-in EP-HYBRID-v1
// envelope vector with NO ML-DSA backend. Every refusal decided before the PQ
// leg -- envelope shape, the algorithm-set commitment, both length pins, the
// curve pin, the classical leg -- must be byte-identical to the JavaScript
// reason. The two vectors whose verdict is decided AT the PQ leg must refuse
// with "pq_backend_unavailable"; nothing may verify.
func TestHybridEnvelopeVectorsBackendAbsent(t *testing.T) {
	const path = "../../conformance/vectors/pq-hybrid-envelope.v1.json"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("EP-HYBRID-v1 envelope vectors not present at %s: %v", path, err)
	}
	var doc hybridEnvelopeVectorDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatalf("%s carries no vectors", path)
	}

	for _, v := range doc.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			edKey, ok := doc.Keys[v.Keys.Ed25519]
			if !ok {
				t.Fatalf("vector names unknown Ed25519 key %q", v.Keys.Ed25519)
			}
			pqKey, ok := doc.Keys[v.Keys.Mldsa]
			if !ok {
				t.Fatalf("vector names unknown ML-DSA key %q", v.Keys.Mldsa)
			}
			got := VerifyHybridEnvelope([]byte(v.Message), v.Envelope, &HybridVerificationKeys{
				Ed25519PublicKey: edKey.SPKIB64URL,
				MldsaPublicKey:   pqKey.PublicKeyB64URL,
			}, AgilityOptions{})

			if got.Verified {
				t.Fatal("an envelope verified with no ML-DSA backend; the PQ leg was skipped")
			}
			wantReason := ""
			if v.Expect.Reason != nil {
				wantReason = *v.Expect.Reason
			}
			// The two verdicts decided AT the PQ leg become the backend
			// refusal; every earlier refusal is backend-independent and must
			// match exactly.
			if v.Expect.Verified || wantReason == HybridReasonPQInvalid {
				wantReason = HybridReasonPQBackendUnavailable
			}
			if got.Reason != wantReason {
				t.Fatalf("reason=%q, want %q", got.Reason, wantReason)
			}
			if got.Checks.PQSignature != nil {
				t.Fatal("pq_signature must stay null when no backend ran")
			}
		})
	}
}
