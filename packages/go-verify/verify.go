// SPDX-License-Identifier: Apache-2.0

// Package emiliaverify provides zero-dependency, offline verification of
// EMILIA Protocol trust receipts (EP-RECEIPT-v1): recursive canonical JSON +
// Ed25519 (SPKI-DER public key) + sorted-pair Merkle anchors.
//
// It is a faithful port of @emilia-protocol/verify (JavaScript) and
// emilia-verify (Python) and is byte-compatible with both — a receipt signed
// on the Node or Python side verifies here, and vice versa. No EP account, no
// API key, no network. Just math.
//
//	res := emiliaverify.VerifyReceiptJSON(rawReceiptBytes, pubKeyBase64URL)
//	if res.Valid {
//		// the named human's signoff is cryptographically intact
//	}
package emiliaverify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// SupportedVersions lists the receipt document versions this verifier accepts.
var SupportedVersions = []string{"EP-RECEIPT-v1"}

const maxSafeInteger = 9007199254740991

// Checks reports the outcome of each independent verification step. Anchor is
// nil when the receipt carries no Merkle anchor.
type Checks struct {
	Version   bool  `json:"version"`
	Signature bool  `json:"signature"`
	Anchor    *bool `json:"anchor"`
}

// Result is the outcome of verifying a receipt.
type Result struct {
	Valid  bool   `json:"valid"`
	Checks Checks `json:"checks"`
	Error  string `json:"error,omitempty"`
}

// VerifyReceiptJSON decodes raw EP-RECEIPT-v1 JSON and verifies it. This is the
// recommended entry point: it decodes with UseNumber so numeric tokens are
// canonicalized exactly as the signer produced them.
func VerifyReceiptJSON(data []byte, publicKeyBase64URL string, opts ...Option) Result {
	doc, err := decodeJSON(data)
	if err != nil {
		return Result{Error: "invalid JSON: " + err.Error()}
	}
	return VerifyReceipt(doc, publicKeyBase64URL, opts...)
}

// VerifyReceipt verifies an already-decoded EP-RECEIPT-v1 document against a
// signer's Ed25519 public key (base64url-encoded SPKI DER).
//
// For byte-exact canonicalization, decode the document with
// json.Decoder.UseNumber() (or use VerifyReceiptJSON) so numbers arrive as
// json.Number rather than float64.
//
// It never panics on malformed input; failures are reported as a Result with
// Valid=false and the relevant check left false.
// Option configures VerifyReceipt. Optional and source-compatible: existing
// callers pass nothing and get the secure default (EP-MERKLE-v2 required).
type Option func(*verifyConfig)

type verifyConfig struct{ allowLegacyMerkle bool }

// WithAllowLegacyMerkle verifies pre-v2 (legacy, sorted-pair) Merkle anchors.
// Use ONLY for old artifacts / compatibility tests — never in production gates.
// Preserves "receipts verify forever" without making v1 the default.
func WithAllowLegacyMerkle() Option { return func(c *verifyConfig) { c.allowLegacyMerkle = true } }

func VerifyReceipt(doc map[string]any, publicKeyBase64URL string, opts ...Option) Result {
	cfg := verifyConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	checks := Checks{}

	version, _ := doc["@version"].(string)
	if !contains(SupportedVersions, version) {
		return Result{Checks: checks, Error: "Unsupported version: " + version}
	}
	checks.Version = true

	payload, hasPayload := doc["payload"]
	sig, _ := doc["signature"].(map[string]any)
	sigValue, _ := sig["value"].(string)
	sigAlg, _ := sig["algorithm"].(string)
	if !hasPayload || payload == nil || sigValue == "" || sigAlg == "" {
		return Result{Checks: checks, Error: "Missing payload or signature"}
	}
	if !IsCanonicalizable(payload) {
		return Result{Checks: checks, Error: "Payload is outside the EP canonicalization profile; use strings or safe integers in signed material"}
	}

	pubDER, err := b64urlDecode(publicKeyBase64URL)
	if err != nil {
		return Result{Checks: checks, Error: "Signature verification failed: " + err.Error()}
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return Result{Checks: checks, Error: "Signature verification failed: " + err.Error()}
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		return Result{Checks: checks, Error: "Public key is not Ed25519"}
	}
	sigBytes, err := b64urlDecode(sigValue)
	if err != nil {
		return Result{Checks: checks, Error: "Signature verification failed: " + err.Error()}
	}
	checks.Signature = ed25519.Verify(pub, []byte(Canonicalize(payload)), sigBytes)

	if anchor, ok := doc["anchor"].(map[string]any); ok {
		proof, hasProof := anchor["merkle_proof"]
		leaf, _ := anchor["leaf_hash"].(string)
		root, _ := anchor["merkle_root"].(string)
		if hasProof && proof != nil && leaf != "" && root != "" {
			var v bool
			if alg, _ := anchor["alg"].(string); alg == MerkleV2Alg {
				// v2: bind the leaf to THIS receipt's payload, then verify the
				// domain-separated proof.
				expectedLeaf := leafHashV2(Canonicalize(payload))
				v = leaf == expectedLeaf && verifyMerkleAnchorMode(leaf, proof, root, true)
			} else if cfg.allowLegacyMerkle {
				// Dormant legacy path: pre-v2 anchors only on explicit opt-in.
				v = verifyMerkleAnchorMode(leaf, proof, root, false)
			} else {
				// Default (and every production gate): require EP-MERKLE-v2.
				v = false
			}
			checks.Anchor = &v
		}
	}

	valid := checks.Version && checks.Signature && (checks.Anchor == nil || *checks.Anchor)
	return Result{Valid: valid, Checks: checks}
}

// VerifyMerkleAnchor verifies a v1 (legacy, sorted-pair) Merkle inclusion proof.
func VerifyMerkleAnchor(leafHash string, proof any, expectedRoot string) bool {
	return verifyMerkleAnchorMode(leafHash, proof, expectedRoot, false)
}

// verifyMerkleAnchorMode folds a hex leaf through the proof to reconstruct the
// expected hex root. v1: sorted-pair SHA-256. v2: domain-separated positional
// SHA-256 (0x01 branch tag).
func verifyMerkleAnchorMode(leafHash string, proof any, expectedRoot string, v2 bool) bool {
	if leafHash == "" || expectedRoot == "" {
		return false
	}
	steps, ok := proof.([]any)
	if !ok || len(steps) > 20 {
		return false
	}
	pair := hashPair
	if v2 {
		pair = hashPairV2
	}
	current := leafHash
	for _, s := range steps {
		step, ok := s.(map[string]any)
		if !ok {
			return false
		}
		h, ok := step["hash"].(string)
		if !ok {
			return false
		}
		switch pos, _ := step["position"].(string); pos {
		case "left":
			current = pair(h, current)
		case "right":
			current = pair(current, h)
		default:
			return false
		}
	}
	return current == expectedRoot
}

// Canonicalize renders a JSON value as recursive canonical JSON: object keys
// sorted depth-first, arrays order-preserved, scalars rendered to match
// ECMAScript JSON.stringify byte-for-byte. Decode input with UseNumber so
// numbers arrive as json.Number and are emitted exactly as the signer wrote
// them.
func Canonicalize(v any) string {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sortJCSKeys(keys)
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(encodeString(k))
			b.WriteByte(':')
			b.WriteString(Canonicalize(val[k]))
		}
		b.WriteByte('}')
		return b.String()
	case []any:
		var b strings.Builder
		b.WriteByte('[')
		for i, e := range val {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(Canonicalize(e))
		}
		b.WriteByte(']')
		return b.String()
	case string:
		return encodeString(val)
	case json.Number:
		return canonicalNumber(val.String())
	case bool:
		if val {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	default:
		// Fallback for inputs decoded without UseNumber (float64) or other
		// scalar types. Mirrors JSON.stringify for integers and typical
		// decimals; prefer UseNumber for exotic numeric tokens.
		if f, ok := val.(float64); ok {
			return canonicalFloat(f)
		}
		out, _ := json.Marshal(val)
		return string(out)
	}
}

func sortJCSKeys(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		return utf16Less(keys[i], keys[j])
	})
}

func utf16Less(a, b string) bool {
	au := utf16.Encode([]rune(a))
	bu := utf16.Encode([]rune(b))
	for i := 0; i < len(au) && i < len(bu); i++ {
		if au[i] != bu[i] {
			return au[i] < bu[i]
		}
	}
	return len(au) < len(bu)
}

func canonicalNumber(raw string) string {
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return raw
	}
	return canonicalFloat(f)
}

func canonicalFloat(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "null"
	}
	if f == 0 {
		return "0"
	}
	if math.Trunc(f) == f && math.Abs(f) <= maxSafeInteger {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// IsCanonicalizable reports whether v is within EP's I-JSON canonicalization
// profile (mirrors JS isCanonicalizable / Python is_canonicalizable): every
// scalar must be a string, bool, nil, or an integer. Non-integer reals are out of
// profile because float serialization differs across implementations (Go's
// json.Number preserves the source token, ECMAScript re-serializes), which would
// break byte-identical cross-language canonicalization. Encode non-integer
// quantities as strings before signing.
func IsCanonicalizable(v any) bool {
	switch val := v.(type) {
	case nil, string, bool:
		return true
	case json.Number:
		f, err := strconv.ParseFloat(string(val), 64)
		return err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) && math.Trunc(f) == f && math.Abs(f) <= maxSafeInteger
	case float64:
		return !math.IsNaN(val) && !math.IsInf(val, 0) && math.Trunc(val) == val && math.Abs(val) <= maxSafeInteger
	case int:
		return int64(val) >= -maxSafeInteger && int64(val) <= maxSafeInteger
	case int8:
		return true
	case int16:
		return true
	case int32:
		return true
	case int64:
		return val >= -maxSafeInteger && val <= maxSafeInteger
	case uint:
		return uint64(val) <= maxSafeInteger
	case uint8:
		return true
	case uint16:
		return true
	case uint32:
		return true
	case uint64:
		return val <= maxSafeInteger
	case map[string]any:
		for _, e := range val {
			if !IsCanonicalizable(e) {
				return false
			}
		}
		return true
	case []any:
		for _, e := range val {
			if !IsCanonicalizable(e) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// encodeString serializes a string exactly as ECMAScript JSON.stringify does:
// escape the seven shorthand controls and every other code point below U+0020,
// and emit everything else (including non-ASCII and < > &) raw.
func encodeString(s string) string {
	const hexdigits = "0123456789abcdef"
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexdigits[(r>>4)&0xf])
				b.WriteByte(hexdigits[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func hashPair(a, b string) string {
	lo, hi := a, b
	if lo > hi {
		lo, hi = hi, lo
	}
	sum := sha256.Sum256([]byte(lo + hi))
	return hex.EncodeToString(sum[:])
}

// MerkleV2Alg marks an EP-MERKLE-v2 anchor: domain-separated + positional.
const MerkleV2Alg = "EP-MERKLE-v2"

// leafHashV2 = SHA-256(0x00 || canonicalJSON(payload)) -> hex.
func leafHashV2(canonicalPayload string) string {
	sum := sha256.Sum256(append([]byte{0x00}, []byte(canonicalPayload)...))
	return hex.EncodeToString(sum[:])
}

// hashPairV2 = SHA-256(0x01 || leftHex || rightHex) -> hex. Positional, not sorted.
func hashPairV2(left, right string) string {
	buf := make([]byte, 0, 1+len(left)+len(right))
	buf = append(buf, 0x01)
	buf = append(buf, left...)
	buf = append(buf, right...)
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

func b64urlDecode(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.URLEncoding.DecodeString(s)
}

func decodeJSON(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
