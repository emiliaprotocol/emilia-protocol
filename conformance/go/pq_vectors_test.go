// SPDX-License-Identifier: Apache-2.0

// Live-backend conformance for the EP hybrid post-quantum VERIFICATION port.
//
// Everything here runs the SAME checked-in vectors the JavaScript suites run,
// against packages/go-verify, with a real ML-DSA-65 backend wired in. The
// backend-absent half of the suite lives in
// packages/go-verify/pq_verification_test.go; together they cover every vector
// twice, once with the PQ leg live and once proving it refuses rather than
// being skipped when no backend is present.
package epgoconformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	emiliaverify "github.com/emiliaprotocol/emilia-protocol/packages/go-verify/v2"
)

const (
	pqAgilityVectors  = "../pq-agility/vectors.json"
	hybridRcptVectors = "../hybrid-receipts/vectors.json"
	hybridEnvVectors  = "../vectors/pq-hybrid-envelope.v1.json"
)

func live() emiliaverify.AgilityOptions {
	return emiliaverify.AgilityOptions{Mldsa: Backend{}}
}

func readVectors(t *testing.T, path string, into any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

// ---------------------------------------------------------------------------
// EP-SIG-AGILITY-v1 -- conformance/pq-agility/vectors.json
// ---------------------------------------------------------------------------

type agilityDoc struct {
	CanonicalPayload string `json:"canonical_payload"`
	Keys             struct {
		Ed25519 emiliaverify.AgileVerificationKey `json:"ed25519"`
		MLDSA65 emiliaverify.AgileVerificationKey `json:"ml_dsa_65"`
	} `json:"keys"`
	Vectors []struct {
		ID         string                         `json:"id"`
		Kind       string                         `json:"kind"`
		Policy     string                         `json:"policy"`
		Signature  *emiliaverify.AgileSignature   `json:"signature"`
		Signatures []*emiliaverify.AgileSignature `json:"signatures"`
		Expect     struct {
			Verified     *bool           `json:"verified"`
			Reason       *string         `json:"reason"`
			PerAlgorithm map[string]bool `json:"per_algorithm"`
		} `json:"expect"`
	} `json:"vectors"`
}

// TestPQAgilityVectorsLive runs every EP-SIG-AGILITY-v1 vector with a live
// ML-DSA-65 backend and requires the exact JavaScript verdict, including the
// two vectors whose ML-DSA signatures must genuinely verify.
func TestPQAgilityVectorsLive(t *testing.T) {
	var doc agilityDoc
	readVectors(t, pqAgilityVectors, &doc)
	if len(doc.Vectors) == 0 {
		t.Fatalf("%s carries no vectors", pqAgilityVectors)
	}
	message := []byte(doc.CanonicalPayload)
	keys := []*emiliaverify.AgileVerificationKey{&doc.Keys.Ed25519, &doc.Keys.MLDSA65}

	verifiedCount := 0
	for _, v := range doc.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			wantVerified := v.Expect.Verified != nil && *v.Expect.Verified
			wantReason := ""
			if v.Expect.Reason != nil {
				wantReason = *v.Expect.Reason
			}

			switch v.Kind {
			case "single":
				var key *emiliaverify.AgileVerificationKey
				for _, k := range keys {
					if k.Alg == v.Signature.Alg {
						key = k
					}
				}
				got := emiliaverify.VerifyAgileSignature(message, v.Signature, key, live())
				if got.Verified != wantVerified || got.Reason != wantReason {
					t.Fatalf("verified=%v reason=%q, want verified=%v reason=%q",
						got.Verified, got.Reason, wantVerified, wantReason)
				}
				if got.Verified {
					verifiedCount++
				}

			case "set":
				opts := live()
				opts.Policy = emiliaverify.AgilitySetPolicy(v.Policy)
				got := emiliaverify.VerifyAgileSignatureSet(message, v.Signatures, keys, opts)
				if v.Policy == "per_algorithm" {
					if got.Verified != nil {
						t.Fatalf("per_algorithm verdict collapsed to %v; it must stay nil", *got.Verified)
					}
					if len(got.Results) != len(v.Expect.PerAlgorithm) {
						t.Fatalf("got %d results, want %d", len(got.Results), len(v.Expect.PerAlgorithm))
					}
					for _, r := range got.Results {
						want, known := v.Expect.PerAlgorithm[r.Alg]
						if !known {
							t.Fatalf("unexpected per-algorithm result for %q", r.Alg)
						}
						if r.Verified != want {
							t.Fatalf("%s leg verified=%v reason=%q, want %v", r.Alg, r.Verified, r.Reason, want)
						}
					}
					return
				}
				if got.Verified == nil {
					t.Fatal("hybrid_all verdict must never be nil")
				}
				if *got.Verified != wantVerified || got.Reason != wantReason {
					t.Fatalf("verified=%v reason=%q, want verified=%v reason=%q",
						*got.Verified, got.Reason, wantVerified, wantReason)
				}
				if *got.Verified {
					verifiedCount++
				}

			default:
				t.Fatalf("unknown vector kind %q", v.Kind)
			}
		})
	}
	// Guard against a suite that passes because everything refuses: the ML-DSA
	// leg must actually verify somewhere.
	if verifiedCount == 0 {
		t.Fatal("no EP-SIG-AGILITY-v1 vector verified; the live backend proved nothing")
	}
}

// TestMLDSABackendVerifiesNobleVectorBytes isolates the cross-implementation
// claim: CIRCL (Go) accepts the exact ML-DSA-65 signature bytes
// @noble/post-quantum (JavaScript) produced, and rejects the one-byte-tampered
// sibling. This is the single fact the live half of the suite rests on, so it
// is asserted on its own rather than only as a side effect.
func TestMLDSABackendVerifiesNobleVectorBytes(t *testing.T) {
	var doc agilityDoc
	readVectors(t, pqAgilityVectors, &doc)
	message := []byte(doc.CanonicalPayload)

	var valid, tampered *emiliaverify.AgileSignature
	for _, v := range doc.Vectors {
		switch v.ID {
		case "ml-dsa-65-valid":
			valid = v.Signature
		case "ml-dsa-65-tampered-signature":
			tampered = v.Signature
		}
	}
	if valid == nil || tampered == nil {
		t.Fatal("ML-DSA-65 valid/tampered vectors not found")
	}

	got := emiliaverify.VerifyAgileSignature(message, valid, &doc.Keys.MLDSA65, live())
	if !got.Verified {
		t.Fatalf("CIRCL rejected a noble-generated ML-DSA-65 signature: reason=%q", got.Reason)
	}
	got = emiliaverify.VerifyAgileSignature(message, tampered, &doc.Keys.MLDSA65, live())
	if got.Verified || got.Reason != emiliaverify.AgilityReasonSignatureInvalid {
		t.Fatalf("tampered signature: verified=%v reason=%q, want false/%s",
			got.Verified, got.Reason, emiliaverify.AgilityReasonSignatureInvalid)
	}
}

// ---------------------------------------------------------------------------
// EP-RECEIPT-HYBRID-v1 -- conformance/hybrid-receipts/vectors.json
// ---------------------------------------------------------------------------

type hybridReceiptDoc struct {
	SignedBytesSHA256 string          `json:"signed_bytes_sha256"`
	Payload           json.RawMessage `json:"payload"`
	Keys              map[string]struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	} `json:"keys"`
	Vectors []struct {
		ID      string          `json:"id"`
		Receipt json.RawMessage `json:"receipt"`
		Expect  struct {
			Verified        bool    `json:"verified"`
			Reason          *string `json:"reason"`
			FailedAlgorithm *string `json:"failed_algorithm"`
		} `json:"expect"`
	} `json:"vectors"`
}

// TestHybridReceiptVectorsLive runs every EP-RECEIPT-HYBRID-v1 vector with a
// live ML-DSA-65 backend and requires the exact JavaScript verdict: the same
// named refusal, attributed to the same leg.
func TestHybridReceiptVectorsLive(t *testing.T) {
	var doc hybridReceiptDoc
	readVectors(t, hybridRcptVectors, &doc)
	if len(doc.Vectors) == 0 {
		t.Fatalf("%s carries no vectors", hybridRcptVectors)
	}
	ed := doc.Keys["Ed25519"]
	pq := doc.Keys["ML-DSA-65"]
	keys := &emiliaverify.HybridReceiptKeys{
		Ed25519PublicKey: ed.PublicKey,
		Ed25519KeyID:     ed.KeyID,
		MldsaPublicKey:   pq.PublicKey,
		MldsaKeyID:       pq.KeyID,
	}

	verifiedCount := 0
	for _, v := range doc.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			got := emiliaverify.VerifyHybridReceiptJSON(v.Receipt, keys, live())
			wantReason := ""
			if v.Expect.Reason != nil {
				wantReason = *v.Expect.Reason
			}
			wantAlg := ""
			if v.Expect.FailedAlgorithm != nil {
				wantAlg = *v.Expect.FailedAlgorithm
			}
			if got.Verified != v.Expect.Verified || got.Reason != wantReason || got.FailedAlgorithm != wantAlg {
				t.Fatalf("verified=%v reason=%q failed_algorithm=%q, want %v/%q/%q",
					got.Verified, got.Reason, got.FailedAlgorithm,
					v.Expect.Verified, wantReason, wantAlg)
			}
			if got.Verified {
				verifiedCount++
			}
		})
	}
	if verifiedCount == 0 {
		t.Fatal("no EP-RECEIPT-HYBRID-v1 vector verified; the live backend proved nothing")
	}
}

// TestHybridReceiptSignedBytesDigestLive re-derives the anti-stripping signed
// material and checks it against the digest recorded by the issuer. If this
// drifts, every live verdict above is meaningless.
func TestHybridReceiptSignedBytesDigestLive(t *testing.T) {
	var doc hybridReceiptDoc
	readVectors(t, hybridRcptVectors, &doc)
	raw, err := os.ReadFile(hybridRcptVectors)
	if err != nil {
		t.Fatalf("read %s: %v", hybridRcptVectors, err)
	}
	var envelope struct {
		Payload map[string]any `json:"payload"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&envelope); err != nil {
		t.Fatalf("decode payload with UseNumber: %v", err)
	}
	got := emiliaverify.HybridReceiptSignedBytes(envelope.Payload, emiliaverify.HybridReceiptRequiredAlgorithms)
	if got == nil {
		t.Fatal("signed material refused a well-formed payload")
	}
	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != doc.SignedBytesSHA256 {
		t.Fatalf("signed bytes digest = %s, want %s", hex.EncodeToString(sum[:]), doc.SignedBytesSHA256)
	}
}

// ---------------------------------------------------------------------------
// EP-HYBRID-v1 -- conformance/vectors/pq-hybrid-envelope.v1.json
// ---------------------------------------------------------------------------

type hybridEnvelopeDoc struct {
	Keys map[string]struct {
		SPKIB64URL      string `json:"spki_b64url"`
		PublicKeyB64URL string `json:"public_key_b64url"`
	} `json:"keys"`
	Vectors []struct {
		ID       string                       `json:"id"`
		Message  string                       `json:"message"`
		Envelope *emiliaverify.HybridEnvelope `json:"envelope"`
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

// TestHybridEnvelopeVectors runs every EP-HYBRID-v1 envelope vector. Vectors
// tagged backend "absent" are run with NO backend and must refuse with
// "pq_backend_unavailable"; every other vector is run with the live backend
// and must match the JavaScript verdict exactly.
func TestHybridEnvelopeVectors(t *testing.T) {
	var doc hybridEnvelopeDoc
	readVectors(t, hybridEnvVectors, &doc)
	if len(doc.Vectors) == 0 {
		t.Fatalf("%s carries no vectors", hybridEnvVectors)
	}

	verifiedCount := 0
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
			keys := &emiliaverify.HybridVerificationKeys{
				Ed25519PublicKey: edKey.SPKIB64URL,
				MldsaPublicKey:   pqKey.PublicKeyB64URL,
			}

			opts := live()
			if v.Backend == "absent" {
				opts = emiliaverify.AgilityOptions{}
			}
			got := emiliaverify.VerifyHybridEnvelope([]byte(v.Message), v.Envelope, keys, opts)

			wantReason := ""
			if v.Expect.Reason != nil {
				wantReason = *v.Expect.Reason
			}
			if got.Verified != v.Expect.Verified || got.Reason != wantReason {
				t.Fatalf("verified=%v reason=%q, want %v/%q",
					got.Verified, got.Reason, v.Expect.Verified, wantReason)
			}
			if got.Verified {
				verifiedCount++
			}
		})
	}
	if verifiedCount == 0 {
		t.Fatal("no EP-HYBRID-v1 envelope vector verified; the live backend proved nothing")
	}
}
