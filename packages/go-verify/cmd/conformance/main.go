// SPDX-License-Identifier: Apache-2.0
// Go conformance runner: emits [{id, valid}] for each vector. os.Args[1] = vectors path.
// Polymorphic: receipt (document) | signoff | quorum.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf16"

	emiliaverify "github.com/emiliaprotocol/emilia-protocol/packages/go-verify"
)

// canonVec is one EP-CANONICALIZATION-v1 vector body.
type canonVec struct {
	InputJSON      string `json:"input_json"`
	ExpectedDigest string `json:"expected_digest"`
}

type vec struct {
	ID                string         `json:"id"`
	PublicKey         string         `json:"public_key"`
	Document          map[string]any `json:"document"`
	Signoff           map[string]any `json:"signoff"`
	ApproverPublicKey string         `json:"approver_public_key"`
	RPID              string         `json:"rp_id"`
	Quorum            map[string]any `json:"quorum"`
	Revocation        map[string]any `json:"revocation"`
	Target            map[string]any `json:"target"`
	RevokerKeys       map[string]any `json:"revoker_keys"`
	MaxAgeSeconds     *float64       `json:"max_age_seconds"`
	Now               string         `json:"now"`
	TimeAttestation   map[string]any `json:"time_attestation"`
	TSAKeys           map[string]any `json:"tsa_keys"`
	ExpectedHash      string         `json:"expected_hash"`
	NotBefore         string         `json:"not_before"`
	NotAfter          string         `json:"not_after"`
	TrustReceipt      map[string]any `json:"trust_receipt"`
	Verification      map[string]any `json:"verification"`
	VerifyOpts        map[string]any `json:"verify_opts"`
	ProvenanceChain   map[string]any `json:"provenance_chain"`
	DelegationKeys    map[string]any `json:"delegation_keys"`
	NowMs             *float64       `json:"now_ms"`
	EvidenceRecord    map[string]any `json:"evidence_record"`
	ProtectedHash     string         `json:"protected_hash"`
	Canonicalization  *canonVec      `json:"canonicalization"`
}

// EP-CANONICALIZATION-v1 differential branch. Same gate as the JS runner
// (conformance/runners/strict-json.mjs) and the Python runner: standard parse
// (UseNumber so number tokens reach Canonicalize unmangled), then the
// strict-parse scan over the RAW text (duplicate member names compared after
// escape decoding, unpaired UTF-16 surrogate escapes, container depth > 64),
// then the EP I-JSON profile predicate, then SHA-256 over the UTF-8 canonical
// bytes compared to the pinned digest. The scan works on the raw text because
// encoding/json silently replaces unpaired surrogates with U+FFFD, which would
// otherwise hide the malformation. Fail-closed at every step.
const canonMaxDepth = 64

func runCanonicalization(c *canonVec) bool {
	dec := json.NewDecoder(strings.NewReader(c.InputJSON))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return false
	}
	if !strictScanOK(c.InputJSON) {
		return false
	}
	if !emiliaverify.IsCanonicalizable(value) {
		return false
	}
	sum := sha256.Sum256([]byte(emiliaverify.Canonicalize(value)))
	return hex.EncodeToString(sum[:]) == c.ExpectedDigest
}

type canonFrame struct {
	obj       bool
	keys      map[string]bool
	expectKey bool
}

// strictScanOK assumes syntactically valid JSON (the standard decode above runs
// first) and enforces the suite's strict-parse gate on the raw text.
func strictScanOK(raw string) bool {
	i, n := 0, len(raw)
	var stack []canonFrame
	readString := func() (string, bool) {
		i++ // opening quote
		var b strings.Builder
		for i < n {
			c := raw[i]
			if c == '"' {
				i++
				return b.String(), true
			}
			if c != '\\' {
				b.WriteByte(c)
				i++
				continue
			}
			if i+1 >= n {
				return "", false
			}
			e := raw[i+1]
			if e != 'u' {
				switch e {
				case '"':
					b.WriteByte('"')
				case '\\':
					b.WriteByte('\\')
				case '/':
					b.WriteByte('/')
				case 'b':
					b.WriteByte('\b')
				case 'f':
					b.WriteByte('\f')
				case 'n':
					b.WriteByte('\n')
				case 'r':
					b.WriteByte('\r')
				case 't':
					b.WriteByte('\t')
				default:
					return "", false
				}
				i += 2
				continue
			}
			if i+6 > n {
				return "", false
			}
			cu, err := strconv.ParseUint(raw[i+2:i+6], 16, 32)
			if err != nil {
				return "", false
			}
			i += 6
			if cu >= 0xD800 && cu <= 0xDBFF {
				if i+6 <= n && raw[i] == '\\' && raw[i+1] == 'u' {
					cu2, err2 := strconv.ParseUint(raw[i+2:i+6], 16, 32)
					if err2 == nil && cu2 >= 0xDC00 && cu2 <= 0xDFFF {
						i += 6
						b.WriteRune(utf16.DecodeRune(rune(cu), rune(cu2)))
						continue
					}
				}
				return "", false // unpaired high surrogate escape
			}
			if cu >= 0xDC00 && cu <= 0xDFFF {
				return "", false // unpaired low surrogate escape
			}
			b.WriteRune(rune(cu))
		}
		return "", false // unterminated string
	}
	for i < n {
		switch raw[i] {
		case '{':
			stack = append(stack, canonFrame{obj: true, keys: map[string]bool{}, expectKey: true})
			if len(stack) > canonMaxDepth {
				return false
			}
			i++
		case '[':
			stack = append(stack, canonFrame{})
			if len(stack) > canonMaxDepth {
				return false
			}
			i++
		case '}', ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			i++
		case ',':
			if len(stack) > 0 && stack[len(stack)-1].obj {
				stack[len(stack)-1].expectKey = true
			}
			i++
		case '"':
			isKey := len(stack) > 0 && stack[len(stack)-1].obj && stack[len(stack)-1].expectKey
			s, ok := readString()
			if !ok {
				return false
			}
			if isKey {
				top := &stack[len(stack)-1]
				if top.keys[s] {
					return false // duplicate object member name
				}
				top.keys[s] = true
				top.expectKey = false
			}
		default:
			i++ // whitespace, colons, primitive tokens
		}
	}
	return true
}

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var f struct {
		Vectors []vec `json:"vectors"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out := make([]map[string]any, 0, len(f.Vectors))
	for _, v := range f.Vectors {
		var valid bool
		switch {
		case v.Document != nil:
			valid = emiliaverify.VerifyReceipt(v.Document, v.PublicKey).Valid
		case v.Signoff != nil:
			valid = emiliaverify.VerifyWebAuthnSignoff(v.Signoff, v.ApproverPublicKey, v.RPID).Valid
		case v.Quorum != nil:
			valid = emiliaverify.VerifyQuorum(v.Quorum, "emiliaprotocol.ai").Valid
		case v.Revocation != nil:
			opts := map[string]any{"revokerKeys": v.RevokerKeys, "now": v.Now}
			if v.MaxAgeSeconds != nil {
				opts["maxAgeSeconds"] = *v.MaxAgeSeconds
			}
			valid = emiliaverify.VerifyRevocation(v.Target, v.Revocation, opts).Valid
		case v.TimeAttestation != nil:
			opts := map[string]any{"tsaKeys": v.TSAKeys, "notBefore": v.NotBefore, "notAfter": v.NotAfter}
			if v.ExpectedHash != "" {
				opts["expectedHash"] = v.ExpectedHash
			}
			valid = emiliaverify.VerifyTimeAttestation(v.TimeAttestation, opts).Valid
		case v.TrustReceipt != nil:
			opts := map[string]any{}
			if v.Verification != nil {
				opts["approverKeys"] = v.Verification["approver_keys"]
				opts["logPublicKey"] = v.Verification["log_public_key"]
			}
			for k, val := range v.VerifyOpts {
				opts[k] = val
			}
			valid = emiliaverify.VerifyTrustReceipt(v.TrustReceipt, opts).Valid
		case v.ProvenanceChain != nil:
			opts := map[string]any{"delegationKeys": v.DelegationKeys}
			if v.NowMs != nil {
				opts["now"] = *v.NowMs
			}
			valid = emiliaverify.VerifyProvenanceOffline(v.ProvenanceChain, opts).Valid
		case v.EvidenceRecord != nil:
			opts := map[string]any{"tsaKeys": v.TSAKeys}
			if v.ProtectedHash != "" {
				opts["protectedHash"] = v.ProtectedHash
			}
			valid = emiliaverify.VerifyEvidenceRecord(v.EvidenceRecord, opts).Valid
		case v.Canonicalization != nil:
			valid = runCanonicalization(v.Canonicalization)
		}
		out = append(out, map[string]any{"id": v.ID, "valid": valid})
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
