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
	"unicode/utf8"

	emiliaverify "github.com/emiliaprotocol/emilia-protocol/packages/go-verify/v2"
)

// canonVec is one EP-CANONICALIZATION-v1 vector body.
type canonVec struct {
	InputJSON      string `json:"input_json"`
	ExpectedDigest string `json:"expected_digest"`
}

// currencyVec is one EP-CURRENCY-v1 vector body: the raw args the JS/Python
// runners pass to evaluateCurrency, plus the expected two-valued status. valid
// iff EvaluateCurrency(args).currency_at_T.status == expect_status.
type currencyVec struct {
	Args         map[string]any `json:"args"`
	ExpectStatus string         `json:"expect_status"`
}

// witnessVec is one EP-WITNESS-v1 k-of-n quorum vector body. valid iff
// RequireWitnessQuorum(...).OK. `k` is kept raw so a non-integer/absent k drives
// the same fail-closed refusal the JS/Python runners get.
type witnessVec struct {
	Checkpoint   map[string]any   `json:"checkpoint"`
	Cosignatures []map[string]any `json:"cosignatures"`
	Pinned       []struct {
		WitnessID string `json:"witness_id"`
		PublicKey string `json:"public_key"`
	} `json:"pinned"`
	K json.RawMessage `json:"k"`
}

type vec struct {
	ID                      string                       `json:"id"`
	PublicKey               string                       `json:"public_key"`
	Document                map[string]any               `json:"document"`
	ResolutionReceipt       map[string]any               `json:"resolution_receipt"`
	ResolutionAuthorization map[string]any               `json:"resolution_authorization"`
	BindingMoment           map[string]any               `json:"binding_moment"`
	ExpectedActionHash      string                       `json:"expected_action_hash"`
	ExpectedSelectedOption  *int                         `json:"expected_selected_option"`
	ExpectedNonce           string                       `json:"expected_nonce"`
	ExpectedInitiator       string                       `json:"expected_initiator"`
	EvaluationTime          string                       `json:"evaluation_time"`
	PrincipalKeys           map[string]map[string]string `json:"principal_keys"`
	Signoff                 map[string]any               `json:"signoff"`
	ApproverPublicKey       string                       `json:"approver_public_key"`
	RPID                    string                       `json:"rp_id"`
	AllowedOrigins          []string                     `json:"allowed_origins"`
	Quorum                  map[string]any               `json:"quorum"`
	Revocation              map[string]any               `json:"revocation"`
	Target                  map[string]any               `json:"target"`
	RevokerKeys             map[string]any               `json:"revoker_keys"`
	MaxAgeSeconds           *float64                     `json:"max_age_seconds"`
	Now                     string                       `json:"now"`
	TimeAttestation         map[string]any               `json:"time_attestation"`
	TSAKeys                 map[string]any               `json:"tsa_keys"`
	ExpectedHash            string                       `json:"expected_hash"`
	NotBefore               string                       `json:"not_before"`
	NotAfter                string                       `json:"not_after"`
	TrustReceipt            map[string]any               `json:"trust_receipt"`
	Verification            map[string]any               `json:"verification"`
	VerifyOpts              map[string]any               `json:"verify_opts"`
	ProvenanceChain         map[string]any               `json:"provenance_chain"`
	DelegationKeys          map[string]any               `json:"delegation_keys"`
	NowMs                   *float64                     `json:"now_ms"`
	EvidenceRecord          map[string]any               `json:"evidence_record"`
	ProtectedHash           string                       `json:"protected_hash"`
	Canonicalization        *canonVec                    `json:"canonicalization"`
	Currency                *currencyVec                 `json:"currency"`
	InitiatorAttestation    map[string]any               `json:"initiator_attestation"`
	ConsumptionProof        map[string]any               `json:"consumption_proof"`
	WitnessQuorum           *witnessVec                  `json:"witness_quorum"`
	// EP-TIMESTAMP-PROOF-v1 (RFC 3161). TimestampProof is kept as a raw JSON
	// token to distinguish an ABSENT field (route elsewhere) from an empty-string
	// token (route to the verifier, which returns missing_token). PinnedTSAKeys
	// is polymorphic (string | []string | {id:key}), decoded in main.
	TimestampProof json.RawMessage `json:"timestamp_proof"`
	ExpectedDigest string          `json:"expected_digest"`
	PinnedTSAKeys  json.RawMessage `json:"pinned_tsa_keys"`
	// EP-AEC-ROLE-v1: a chain run through the built-in ep-receipt with role-scoped
	// pins (keys_by_type maps type -> {spki: spki}) and a permissive stub per type.
	AECChain             map[string]any               `json:"aec_chain"`
	KeysByType           map[string]map[string]string `json:"keys_by_type"`
	PoliciesByType       map[string]any               `json:"policies_by_type"`
	StubTypes            []string                     `json:"stub_types"`
	Requirement          string                       `json:"requirement"`
	ExpectedActionDigest string                       `json:"expected_action_digest"`
	VerificationTime     string                       `json:"verification_time"`
}

// pinnedTSAKeysFromRaw normalizes the polymorphic `pinned_tsa_keys` vector field
// (a single string, an array of strings, or a {id: key} object) into the
// []string VerifyTimestampProof takes. Mirrors the JS pinnedList assembly and the
// Go test helper.
func pinnedTSAKeysFromRaw(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		return arr
	}
	var obj map[string]string
	if json.Unmarshal(raw, &obj) == nil {
		out := make([]string, 0, len(obj))
		for _, v := range obj {
			out = append(out, v)
		}
		return out
	}
	return nil
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

// currencyArgsFromMap converts a raw EP-CURRENCY-v1 args object (as the JS and
// Python runners pass to evaluateCurrency) into the typed CurrencyArgs the Go
// port takes, preserving the JS optional/undefined semantics: a missing field
// stays nil/false so the verifier fails closed exactly as JS does. Mirrors the
// conversion in optin_profile_vectors_test.go. Numbers arrive as float64 because
// the runner decodes with the standard json.Unmarshal (no UseNumber).
func currencyArgsFromMap(args map[string]any) emiliaverify.CurrencyArgs {
	ca := emiliaverify.CurrencyArgs{}
	if r, ok := args["receipt"].(map[string]any); ok {
		ah, _ := r["action_hash"].(string)
		ca.Receipt = &emiliaverify.CurrencyReceipt{ActionHash: ah}
	}
	if b, ok := args["authentic_as_of_commit"].(bool); ok {
		ca.AuthenticAsOfCommit = b
	}
	if now, ok := args["now"].(string); ok {
		ca.Now = &now
	}
	if v, present := args["maxStalenessSeconds"]; present {
		if f, ok := v.(float64); ok {
			ca.MaxStalenessSeconds = &f
		} else {
			// Present but non-numeric: model an invalid bound so the verifier
			// fails closed exactly as JS does for a non-finite bound.
			neg := -1.0
			ca.MaxStalenessSeconds = &neg
		}
	}
	if b, ok := args["freshHeadRequired"].(bool); ok {
		ca.FreshHeadRequired = b
	}
	if fh, present := args["freshHead"]; present && fh != nil {
		if fhm, ok := fh.(map[string]any); ok {
			head := &emiliaverify.FreshHead{}
			head.ObservedAt, _ = fhm["observed_at"].(string)
			head.IssuedAt, _ = fhm["issued_at"].(string)
			if b, ok := fhm["revoked"].(bool); ok {
				head.Revoked = b
			}
			head.TargetHash, _ = fhm["target_hash"].(string)
			if rl, ok := fhm["revoked_target_hashes"].([]any); ok {
				for _, h := range rl {
					if hs, ok := h.(string); ok {
						head.RevokedTargetHashes = append(head.RevokedTargetHashes, hs)
					}
				}
			}
			ca.FreshHead = head
		}
	}
	return ca
}

// witnessKFromRaw parses the vector's `k` from raw JSON. An absent, null, or
// non-integer k yields (0, false) so RequireWitnessQuorum fails closed exactly
// as the JS/Python runners do when k is not a valid integer.
func witnessKFromRaw(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, false
	}
	if f != float64(int(f)) {
		return 0, false
	}
	return int(f), true
}

func main() {
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !utf8.Valid(data) {
		fmt.Fprintln(os.Stderr, "conformance corpus is not valid UTF-8")
		os.Exit(1)
	}
	var f struct {
		Vectors []json.RawMessage `json:"vectors"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !strictScanOK(string(data)) {
		fmt.Fprintln(os.Stderr, "strict corpus JSON refused")
		os.Exit(1)
	}
	out := make([]map[string]any, 0, len(f.Vectors))
	for _, rawVector := range f.Vectors {
		// Decode each vector independently. A hostile type in one vector must be
		// a false verdict for that vector, never a batch-wide availability failure.
		var header struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(rawVector, &header)
		var v vec
		if err := json.Unmarshal(rawVector, &v); err != nil {
			out = append(out, map[string]any{"id": header.ID, "valid": false})
			continue
		}
		var valid bool
		switch {
		case v.Document != nil:
			valid = emiliaverify.VerifyReceipt(v.Document, v.PublicKey).Valid
		case v.ResolutionReceipt != nil || v.ResolutionAuthorization != nil:
			receipt := v.ResolutionReceipt
			authorizationMode := false
			if receipt == nil {
				receipt = v.ResolutionAuthorization
				authorizationMode = true
			}
			result := emiliaverify.VerifyResolutionReceipt(receipt, emiliaverify.ResolutionOptions{
				BindingMoment: v.BindingMoment, ExpectedActionHash: v.ExpectedActionHash,
				ExpectedSelectedOption: v.ExpectedSelectedOption,
				ExpectedNonce:          v.ExpectedNonce, ExpectedInitiator: v.ExpectedInitiator,
				EvaluationTime: v.EvaluationTime, PrincipalKeys: v.PrincipalKeys, RPID: v.RPID,
				AllowedOrigins: v.AllowedOrigins,
			})
			valid = result.Valid
			if authorizationMode {
				valid = result.Valid && result.AuthorizesAction
			}
		case v.Signoff != nil:
			valid = emiliaverify.VerifyWebAuthnSignoff(v.Signoff, v.ApproverPublicKey, v.RPID).Valid
		case v.Quorum != nil:
			valid = emiliaverify.VerifyQuorum(v.Quorum, "emiliaprotocol.ai").Valid
		case v.Revocation != nil:
			opts := map[string]any{"revokerKeys": v.RevokerKeys}
			if v.Now != "" {
				opts["now"] = v.Now
			}
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
		case v.Currency != nil:
			// EP-CURRENCY-v1: valid iff the two-valued status equals expect_status.
			status := emiliaverify.EvaluateCurrency(currencyArgsFromMap(v.Currency.Args)).CurrencyAtT.Status
			valid = status == v.Currency.ExpectStatus
		case v.InitiatorAttestation != nil:
			// EP-INITIATOR-ATTESTATION-v1: valid iff the attestation validates.
			valid = emiliaverify.ValidateInitiatorAttestation(v.InitiatorAttestation).OK
		case v.ConsumptionProof != nil:
			// EP-SMT-CONSUME-v1: valid iff the absent->present transition verifies.
			valid = emiliaverify.VerifyConsumptionProof(v.ConsumptionProof).Valid
		case v.WitnessQuorum != nil:
			// EP-WITNESS-v1: valid iff k distinct pinned witnesses validly cosigned.
			w := v.WitnessQuorum
			pinned := make([]emiliaverify.PinnedWitnessKey, 0, len(w.Pinned))
			for _, p := range w.Pinned {
				pinned = append(pinned, emiliaverify.PinnedWitnessKey{WitnessID: p.WitnessID, PublicKey: p.PublicKey})
			}
			cosigs := w.Cosignatures
			if cosigs == nil {
				cosigs = []map[string]any{}
			}
			k, kValid := witnessKFromRaw(w.K)
			valid = emiliaverify.RequireWitnessQuorum(w.Checkpoint, cosigs, pinned, k, kValid).OK
		case len(v.TimestampProof) > 0:
			// EP-TIMESTAMP-PROOF-v1 (RFC 3161): valid iff the pinned TSA's
			// TimeStampToken verifies over the expected digest (fail-closed). The
			// field is PRESENT (len>0) even for the empty-string token, so a
			// missing_token vector routes to the verifier, not the default.
			var token string
			_ = json.Unmarshal(v.TimestampProof, &token)
			keys := pinnedTSAKeysFromRaw(v.PinnedTSAKeys)
			valid = emiliaverify.VerifyTimestampProof(token, v.ExpectedDigest, keys).Verified
		case v.AECChain != nil:
			// EP-AEC-ROLE-v1: valid iff VerifyAuthorizationChain ALLOWs, with the
			// built-in ep-receipt using role-scoped pins (keys_by_type) and a
			// permissive stub per stub_type. Real signatures, role scoping, binding.
			stub := func(ev any, ctx map[string]any) emiliaverify.ComponentResult {
				m, _ := ev.(map[string]any)
				ok := true
				if b, has := m["valid"].(bool); has {
					ok = b
				}
				ad, _ := m["action_digest"].(string)
				return emiliaverify.ComponentResult{Valid: ok, ActionDigest: ad}
			}
			verifiers := map[string]emiliaverify.ComponentVerifier{}
			for _, t := range v.StubTypes {
				verifiers[t] = stub
			}
			valid = emiliaverify.VerifyAuthorizationChainWithOptions(v.AECChain, verifiers, v.KeysByType, emiliaverify.AECOptions{
				Requirement: v.Requirement, ExpectedActionDigest: v.ExpectedActionDigest,
				VerificationTime: v.VerificationTime, PoliciesByType: v.PoliciesByType,
			}).Satisfied
		}
		out = append(out, map[string]any{"id": v.ID, "valid": valid})
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
