// SPDX-License-Identifier: Apache-2.0
// EP §6.2 Trust Receipt offline verifier (I-D §6.3) — Go parity with
// packages/verify verifyTrustReceipt and python-verify verify_trust_receipt.
// The PIP-007 attestation report is advisory and omitted (never affects validity).
package emiliaverify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// TrustReceiptResult mirrors the JS { valid, checks } shape.
type TrustReceiptResult struct {
	Valid  bool            `json:"valid"`
	Checks map[string]bool `json:"checks"`
}

func sha256HexOf(v any) string {
	sum := sha256.Sum256([]byte(Canonicalize(v)))
	return hex.EncodeToString(sum[:])
}

// jsonNumEquals reports whether a decoded JSON value is a NUMBER equal to want.
// Fail-closed: strings, bools, nil, and missing values are never equal. Handles
// both decode modes used in this package (float64 from plain json.Unmarshal,
// json.Number from UseNumber decoders), so an integer-valued token such as
// "1.0" equals 1 exactly as it does after ECMAScript JSON.parse.
func jsonNumEquals(v any, want float64) bool {
	switch n := v.(type) {
	case float64:
		return n == want
	case json.Number:
		f, err := n.Float64()
		return err == nil && f == want
	case int:
		return float64(n) == want
	case int64:
		return float64(n) == want
	default:
		return false
	}
}

func withinWindowGo(t, frm, to string) bool {
	ts, ok := parseMillis(t)
	if !ok {
		return false
	}
	if frm != "" {
		if f, ok2 := parseMillis(frm); ok2 && ts < f {
			return false
		}
	}
	if to != "" {
		if tt, ok2 := parseMillis(to); ok2 && ts > tt {
			return false
		}
	}
	return true
}

func verifyClassAOverDigestGo(wa map[string]any, digest []byte, pubB64u string, rpID string, allowedOrigins []string, requireOrigin bool) bool {
	cdBytes, err := b64urlDecode(getStr(wa, "client_data_json"))
	if err != nil {
		return false
	}
	client, err := decodeStrictJSONObject(cdBytes)
	if err != nil {
		return false
	}
	if getStr(client, "type") != "webauthn.get" {
		return false
	}
	if getStr(client, "challenge") != base64.RawURLEncoding.EncodeToString(digest) {
		return false
	}
	ad, err := b64urlDecode(getStr(wa, "authenticator_data"))
	if err != nil || len(ad) < 37 || ad[32]&flagUP != flagUP || ad[32]&flagUV != flagUV {
		return false
	}
	if rpID != "" {
		expected := sha256.Sum256([]byte(rpID))
		if !bytes.Equal(expected[:], ad[:32]) {
			return false
		}
	}
	if requireOrigin {
		originOK := false
		for _, allowed := range allowedOrigins {
			if getStr(client, "origin") == allowed {
				originOK = true
				break
			}
		}
		if crossOrigin, ok := client["crossOrigin"].(bool); ok && crossOrigin {
			originOK = false
		}
		if !originOK {
			return false
		}
	}
	signed := append(append([]byte{}, ad...), func() []byte { s := sha256.Sum256(cdBytes); return s[:] }()...)
	der, err := base64.RawURLEncoding.DecodeString(b64urlPad(pubB64u))
	if err != nil {
		return false
	}
	pubAny, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return false
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	sig, err := b64urlDecode(getStr(wa, "signature"))
	if err != nil {
		return false
	}
	h := sha256.Sum256(signed)
	return ecdsa.VerifyASN1(pub, h[:], sig)
}

func trustReceiptCanonicalProfileOK(receipt map[string]any) bool {
	leaf := map[string]any{}
	for k, v := range receipt {
		if k != "log_proof" && k != "approver_key_proofs" {
			leaf[k] = v
		}
	}
	if !IsCanonicalizable(leaf) {
		return false
	}
	if lp := getMap(receipt["log_proof"]); lp != nil {
		if cp := getMap(lp["checkpoint"]); cp != nil {
			signedCP := map[string]any{}
			for k, v := range cp {
				if k != "log_signature" {
					signedCP[k] = v
				}
			}
			if !IsCanonicalizable(signedCP) {
				return false
			}
		}
	}
	return true
}

// VerifyTrustReceipt verifies an EP §6.2 Trust Receipt offline. opts keys:
// approverKeys (map of approver_key_id -> {approver_id,public_key,key_class,valid_from,valid_to}),
// logPublicKey (string).
func VerifyTrustReceipt(receipt map[string]any, opts map[string]any) TrustReceiptResult {
	checks := map[string]bool{
		"action_hash": false, "context_commitments": false, "signoff_signatures": false,
		"sod": false, "inclusion": false, "checkpoint_signature": false, "windows": false,
	}
	if receipt == nil {
		return TrustReceiptResult{false, checks}
	}
	approverKeys := getMap(opts["approverKeys"])
	logPublicKey := getStr(opts, "logPublicKey")
	rpID := getStr(opts, "rpId")
	allowedOrigins, requireOrigin := stringSliceOption(opts, "allowedOrigins")
	contexts, _ := receipt["contexts"].([]any)
	signoffs, _ := receipt["signoffs"].([]any)
	if receipt["action"] == nil || getStr(receipt, "action_hash") == "" {
		return TrustReceiptResult{false, checks}
	}
	if len(contexts) == 0 || len(signoffs) == 0 {
		return TrustReceiptResult{false, checks}
	}
	if !trustReceiptCanonicalProfileOK(receipt) {
		return TrustReceiptResult{false, checks}
	}

	// I-JSON canonicalization gate (fail-closed) — identical guard to VerifyReceipt.
	// Every field folded into a signed digest below is re-canonicalized; a value
	// outside the profile canonicalizes differently across JS/Py/Go, so reject it
	// here. Signature/proof fields are excluded from the check.
	canonicalScope := map[string]any{}
	for k, v := range receipt {
		if k != "signoffs" && k != "log_proof" && k != "approver_key_proofs" {
			canonicalScope[k] = v
		}
	}
	if !IsCanonicalizable(canonicalScope) {
		return TrustReceiptResult{false, checks}
	}

	actionHashHex := sha256HexOf(receipt["action"])
	checks["action_hash"] = actionHashHex == hexStrip(receipt["action_hash"])

	contextByHash := map[string]map[string]any{}
	commitmentsOK := true
	policyHashes := map[string]bool{}
	for _, c := range contexts {
		ctx := getMap(c)
		contextByHash[sha256HexOf(ctx)] = ctx
		if hexStrip(ctx["action_hash"]) != actionHashHex {
			commitmentsOK = false
		}
		if getStr(ctx, "policy_hash") == "" {
			commitmentsOK = false
		} else {
			policyHashes[hexStrip(ctx["policy_hash"])] = true
		}
		if getStr(ctx, "approver") == "" {
			commitmentsOK = false
		}
	}
	if len(policyHashes) > 1 {
		commitmentsOK = false
	}
	checks["context_commitments"] = commitmentsOK

	type approval struct {
		approver, signedAt string
		ctx                map[string]any
	}
	validApprovals := []approval{}
	signaturesOK := len(signoffs) > 0
	for _, so := range signoffs {
		s := getMap(so)
		ctx, found := contextByHash[hexStrip(s["context_hash"])]
		if !found {
			signaturesOK = false
			continue
		}
		keyEntry := getMap(approverKeys[getStr(s, "approver_key_id")])
		pub := getStr(keyEntry, "public_key")
		if pub == "" {
			signaturesOK = false
			continue
		}
		// The pinned directory entry must bind this key to the approver named
		// by the signed context. A valid key signature without this identity
		// join cannot establish which principal approved.
		boundApprover := getStr(keyEntry, "approver_id")
		if boundApprover == "" || boundApprover != getStr(ctx, "approver") {
			signaturesOK = false
			continue
		}
		if !withinWindowGo(getStr(ctx, "issued_at"), getStr(keyEntry, "valid_from"), getStr(keyEntry, "valid_to")) {
			signaturesOK = false
			continue
		}
		digest, err := hex.DecodeString(hexStrip(s["context_hash"]))
		if err != nil {
			signaturesOK = false
			continue
		}
		// The PINNED key entry's class is authoritative and takes precedence over
		// the attacker-controlled signoff's declared key_class. Otherwise an
		// attacker pins a Class-A (WebAuthn, user-presence/user-verification)
		// approver but declares key_class:"B" and supplies a bare Ed25519 signature
		// over the digest, downgrading to raw-signature verification with NO
		// WebAuthn proof. A pinned Class-A key MUST be satisfied by a real WebAuthn
		// assertion and is rejected if it only carries a raw signature. Mirrors
		// index.js verifyTrustReceipt.
		keyClass := getStr(keyEntry, "key_class")
		// Key class is a relying-party directory fact. Missing defaults to B;
		// the presented signoff cannot promote its own key to Class A.
		if keyClass != "A" {
			keyClass = "B"
		}
		var sigOK bool
		if keyClass == "A" {
			sigOK = getMap(s["webauthn"]) != nil && verifyClassAOverDigestGo(getMap(s["webauthn"]), digest, pub, rpID, allowedOrigins, requireOrigin)
		} else {
			sigOK = ed25519VerifyBytes(digest, pub, getStr(s, "signature"))
		}
		if !sigOK {
			signaturesOK = false
			continue
		}
		validApprovals = append(validApprovals, approval{getStr(ctx, "approver"), getStr(s, "signed_at"), ctx})
	}
	checks["signoff_signatures"] = signaturesOK

	action := getMap(receipt["action"])
	initiator := getStr(action, "initiator")
	// A present-but-non-string initiator (e.g. ["alice"] or {"id":"alice"}) coerces
	// to "" via getStr, which would SKIP the separation-of-duties check below and let
	// the initiator double as the sole approver. Treat it as malformed -> fail-closed.
	initiatorRaw, initiatorPresent := action["initiator"]
	_, initiatorIsString := initiatorRaw.(string)
	initiatorMalformed := initiatorPresent && initiatorRaw != nil && !initiatorIsString
	approvers := make([]string, 0, len(validApprovals))
	for _, a := range validApprovals {
		approvers = append(approvers, a.approver)
	}
	// Canonical required_approvals coercion (fail-closed; mirrors packages/verify
	// coerceRequiredApprovals and the Python verifier). The threshold MUST be an
	// integer-valued JSON number. A string ("2"), a non-integer float, or any
	// other type is malformed and forces the receipt to fail — a string must NEVER
	// be silently ignored (that would let 1 signoff satisfy an under-approval).
	required := 1
	sodOK := true
	for _, c := range contexts {
		v, present := getMap(c)["required_approvals"]
		if !present || v == nil {
			continue
		}
		ra, ok := toFloat(v)
		if !ok || ra != float64(int(ra)) || int(ra) < 1 {
			sodOK = false // non-integer threshold is malformed -> fail-closed
			continue
		}
		if int(ra) > required {
			required = int(ra)
		}
	}
	if initiatorMalformed || (initiator != "" && contains(approvers, initiator)) {
		sodOK = false
	}
	seen := map[string]bool{}
	for _, a := range approvers {
		seen[a] = true
	}
	if len(seen) != len(approvers) {
		sodOK = false
	}
	if len(validApprovals) < required {
		sodOK = false
	}
	checks["sod"] = sodOK

	if lp := getMap(receipt["log_proof"]); lp != nil {
		cp := getMap(lp["checkpoint"])
		ipath, hasPath := lp["inclusion_path"].([]any)
		if cp != nil && hasPath {
			leaf := map[string]any{}
			for k, v := range receipt {
				if k != "log_proof" && k != "approver_key_proofs" {
					leaf[k] = v
				}
			}
			// EP-MERKLE-v2 (default): domain-separated, payload-bound leaf + positional
			// proof; when log_proof carries leaf_hash it must bind this receipt.
			merkleAlg := getStr(lp, "alg")
			if merkleAlg == "" {
				merkleAlg = getStr(cp, "merkle_alg")
			}
			// Degenerate empty-path rule (fail-closed): with an empty
			// inclusion_path the Merkle fold collapses to leafHash == root_hash,
			// which is only a true inclusion statement for a SINGLE-LEAF tree.
			// Without this gate, a forged checkpoint whose root_hash simply
			// repeats the leaf hash would "include" the receipt at ANY claimed
			// tree_size. An empty path is therefore accepted ONLY when
			// checkpoint.tree_size is exactly 1 (and, since this shape carries
			// an index, leaf_index, when present, is 0; a null leaf_index counts
			// as present and refuses). Missing or non-numeric tree_size refuses.
			// Applies to v2 AND opt-in legacy folds, evaluated before the
			// Merkle fold. Mirrors packages/verify (JS) verifyTrustReceipt:
			//   "empty inclusion_path requires checkpoint tree_size 1 (single-leaf tree)"
			//   "empty inclusion_path requires leaf_index 0 in a single-leaf tree"
			emptyPathRefused := false
			if len(ipath) == 0 {
				if !jsonNumEquals(cp["tree_size"], 1) {
					emptyPathRefused = true
				} else if li, present := lp["leaf_index"]; present && !jsonNumEquals(li, 0) {
					emptyPathRefused = true
				}
			}
			if emptyPathRefused {
				checks["inclusion"] = false
			} else if merkleAlg == MerkleV2Alg {
				leafHash := leafHashV2(Canonicalize(leaf))
				presented := hexStrip(lp["leaf_hash"])
				if presented == "" {
					presented = leafHash
				}
				checks["inclusion"] = presented == leafHash && verifyMerkleAnchorMode(leafHash, ipath, hexStrip(cp["root_hash"]), true)
			} else if opts != nil && (opts["allowLegacyMerkle"] == true || opts["allowLegacyTrustReceiptMerkle"] == true) {
				// Dormant legacy path: pre-v2 sorted-pair inclusion, opt-in only.
				checks["inclusion"] = VerifyMerkleAnchor(sha256HexOf(leaf), ipath, hexStrip(cp["root_hash"]))
			} else {
				// Default (and every production gate): require EP-MERKLE-v2.
				checks["inclusion"] = false
			}
			logSig := getStr(cp, "log_signature")
			if logPublicKey != "" && logSig != "" {
				signedCP := map[string]any{}
				for k, v := range cp {
					if k != "log_signature" {
						signedCP[k] = v
					}
				}
				sum := sha256.Sum256([]byte(Canonicalize(signedCP)))
				checks["checkpoint_signature"] = ed25519VerifyBytes(sum[:], logPublicKey, strings.Replace(logSig, "b64u:", "", 1))
			}
		}
	}

	windowsOK := len(validApprovals) > 0
	for _, a := range validApprovals {
		if !withinWindowGo(a.signedAt, getStr(a.ctx, "issued_at"), getStr(a.ctx, "expires_at")) {
			windowsOK = false
		}
	}
	committedAt := getStr(getMap(receipt["consumption"]), "committed_at")
	if committedAt == "" {
		windowsOK = false
	} else {
		for _, c := range contexts {
			ctx := getMap(c)
			if !withinWindowGo(committedAt, getStr(ctx, "issued_at"), getStr(ctx, "expires_at")) {
				windowsOK = false
				break
			}
		}
	}
	checks["windows"] = windowsOK

	return TrustReceiptResult{allTrue(checks), checks}
}
