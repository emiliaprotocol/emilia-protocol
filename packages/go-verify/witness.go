// SPDX-License-Identifier: Apache-2.0
//
// EP-WITNESS-v1 — WITNESS COSIGNATURE verification. Faithful port of
// packages/verify/witness.js, byte-compatible with it: a cosignature produced on
// the JS side verifies here and vice versa.
//
// A transparency-log operator signs its own checkpoint. A single operator
// signature does not make a split view (equivocation) detectable. An INDEPENDENT
// WITNESS re-signs the SAME committed checkpoint bytes under a DISTINCT domain
// tag; when several independent witnesses each cosign whatever head they
// observed, two verifiers who later gossip their cosignatures can detect that the
// log presented divergent heads at the same tree_size.
//
// DOMAIN SEPARATION (critical):
//
//	The log signs   Ed25519( SHA-256( canonicalize(signedCheckpoint) ) ).
//	A witness signs  Ed25519( SHA-256( WITNESS_DOMAIN_TAG || canonicalize(signedCheckpoint) ) ).
//
// signedCheckpoint is the checkpoint with its own log_signature removed — the
// identical committed bytes the log signed. Prepending the domain tag to the
// pre-image means a witness cosignature and a log signature are computed over
// DIFFERENT bytes and can never be confused or replayed for one another.
//
// KEY / HASH ENCODING (matches verify.go / index.js): public keys are base64url
// SPKI DER, verified with Ed25519 over the digest; signatures are base64url;
// hashes are "sha256:<hex>" or bare hex, compared prefix-stripped.
//
// FAIL-CLOSED: every check refuses on missing / malformed / unrecognized input.
// An unknown or unpinned witness key refuses. A signature over different bytes
// refuses. A cosignature presented for a different checkpoint refuses. The k-of-n
// helper refuses on fewer than k DISTINCT pinned witnesses.
package emiliaverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"sort"
	"strings"
)

// WitnessVersion is the cosignature alg identifier.
const WitnessVersion = "EP-WITNESS-v1"

// WitnessDomainTag is the domain-separation tag prepended to the SHA-256
// pre-image a witness signs. A UTF-8 label with a trailing 0x00 so it can never
// be a prefix of the canonical JSON that follows (canonical JSON begins with
// '{' 0x7b, never 0x00). The log's own signature has NO such prefix.
const WitnessDomainTag = "EP-WITNESS-COSIGN-v1\x00"

func witnessHexOf(h string) string {
	return strings.ToLower(strings.TrimPrefix(strings.ToLower(h), "sha256:"))
}

// committedCheckpoint returns the checkpoint the log signed — a copy WITHOUT its
// own log_signature. Returns nil if the checkpoint is not a plain object.
func committedCheckpoint(checkpoint map[string]any) map[string]any {
	if checkpoint == nil {
		return nil
	}
	signed := make(map[string]any, len(checkpoint))
	for k, v := range checkpoint {
		if k == "log_signature" {
			continue
		}
		signed[k] = v
	}
	return signed
}

// WitnessSigningDigest returns the exact 32-byte digest a witness signs / a
// verifier re-derives: SHA-256( WITNESS_DOMAIN_TAG || canonicalize(committed) ).
// Returns nil if the checkpoint could not be canonicalized. Byte-identical to
// witness.js witnessSigningDigest.
func WitnessSigningDigest(checkpoint map[string]any) []byte {
	signed := committedCheckpoint(checkpoint)
	if signed == nil {
		return nil
	}
	preimage := append([]byte(WitnessDomainTag), []byte(Canonicalize(signed))...)
	sum := sha256.Sum256(preimage)
	return sum[:]
}

// WitnessResult is the single-cosignature verification result.
type WitnessResult struct {
	Verified  bool
	WitnessID string
	Reason    string
}

func witnessRefuse(reason string) WitnessResult {
	return WitnessResult{Verified: false, WitnessID: "", Reason: reason}
}

// PinnedWitnessKey is the ONE witness the caller trusts for a cosignature: a
// stable witness_id plus its base64url SPKI-DER Ed25519 public key.
type PinnedWitnessKey struct {
	WitnessID string
	PublicKey string
}

// Cosignature is a witness cosignature over a checkpoint. The optional echoed
// head fields (TreeSize/RootHash/LogKeyID) are fail-closed: present-and-wrong
// refuses; use the *Set fields to model "present" vs "absent" (JS undefined).
type Cosignature struct {
	WitnessID   string
	Signature   string
	Alg         string
	AlgSet      bool
	TreeSize    any
	TreeSizeSet bool
	RootHash    string
	RootHashSet bool
	LogKeyID    string
	LogKeyIDSet bool
}

// cosignatureFromMap builds a Cosignature from a decoded JSON object, preserving
// the present/absent distinction the JS relies on.
func cosignatureFromMap(m map[string]any) Cosignature {
	c := Cosignature{}
	if v, ok := m["witness_id"].(string); ok {
		c.WitnessID = v
	}
	if v, ok := m["signature"].(string); ok {
		c.Signature = v
	}
	if v, ok := m["alg"]; ok {
		c.AlgSet = true
		if s, ok := v.(string); ok {
			c.Alg = s
		} else {
			c.Alg = "\x00non-string" // any non-matching sentinel => alg mismatch refusal
		}
	}
	if v, ok := m["tree_size"]; ok {
		c.TreeSizeSet = true
		c.TreeSize = v
	}
	if v, ok := m["root_hash"]; ok {
		c.RootHashSet = true
		if s, ok := v.(string); ok {
			c.RootHash = s
		}
	}
	if v, ok := m["log_key_id"]; ok {
		c.LogKeyIDSet = true
		if s, ok := v.(string); ok {
			c.LogKeyID = s
		}
	}
	return c
}

// numericEqual compares two JSON-decoded tree_size echoes for equality the way JS
// === would (json.Number vs float64 vs int). Non-numeric falls back to plain
// equality.
func numericEqual(a, b any) bool {
	af, aok := witnessToFloat(a)
	bf, bok := witnessToFloat(b)
	if aok && bok {
		return af == bf
	}
	return a == b
}

func witnessToFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	if jn, ok := v.(interface{ Float64() (float64, error) }); ok { // json.Number
		f, err := jn.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// VerifyWitnessCosignature verifies a single witness cosignature over a
// checkpoint against the ONE pinned witness the caller trusts. Faithful port of
// witness.js verifyWitnessCosignature.
func VerifyWitnessCosignature(checkpoint map[string]any, cosig Cosignature, pinned PinnedWitnessKey) WitnessResult {
	if checkpoint == nil {
		return witnessRefuse("checkpoint is missing or not an object")
	}
	if pinned.WitnessID == "" {
		return witnessRefuse("pinnedWitnessKey.witness_id is missing")
	}
	if pinned.PublicKey == "" {
		return witnessRefuse("pinnedWitnessKey.public_key is missing")
	}
	if cosig.WitnessID == "" {
		return witnessRefuse("cosignature.witness_id is missing")
	}
	if cosig.WitnessID != pinned.WitnessID {
		return witnessRefuse("cosignature witness_id is not the pinned witness (unpinned witness refused)")
	}
	if cosig.AlgSet && cosig.Alg != WitnessVersion {
		return witnessRefuse("cosignature alg must be " + WitnessVersion + " when present")
	}
	if cosig.Signature == "" {
		return witnessRefuse("cosignature.signature is missing")
	}

	// Echoed head fields must match the checkpoint being verified (fail-closed:
	// present-and-wrong refuses; absent is allowed).
	if cosig.TreeSizeSet && !numericEqual(cosig.TreeSize, checkpoint["tree_size"]) {
		return witnessRefuse("cosignature tree_size does not match the checkpoint (cosignature for a different head)")
	}
	if cosig.RootHashSet {
		cpRoot, _ := checkpoint["root_hash"].(string)
		if witnessHexOf(cosig.RootHash) != witnessHexOf(cpRoot) {
			return witnessRefuse("cosignature root_hash does not match the checkpoint (cosignature for a different head)")
		}
	}
	if cosig.LogKeyIDSet {
		cpLog, _ := checkpoint["log_key_id"].(string)
		if cosig.LogKeyID != cpLog {
			return witnessRefuse("cosignature log_key_id does not match the checkpoint (cosignature for a different log)")
		}
	}

	digest := WitnessSigningDigest(checkpoint)
	if digest == nil {
		return witnessRefuse("checkpoint could not be canonicalized")
	}

	pub, err := ed25519PubFromB64URL(pinned.PublicKey)
	if err != nil {
		return witnessRefuse("cosignature verification failed: " + err.Error())
	}
	sig, err := b64urlDecode(cosig.Signature)
	if err != nil {
		return witnessRefuse("cosignature verification failed: " + err.Error())
	}
	if !ed25519.Verify(pub, digest, sig) {
		return witnessRefuse("cosignature does not verify over the checkpoint committed bytes")
	}
	return WitnessResult{Verified: true, WitnessID: cosig.WitnessID}
}

func ed25519PubFromB64URL(s string) (ed25519.PublicKey, error) {
	der, err := b64urlDecode(s)
	if err != nil {
		return nil, err
	}
	anyKey, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := anyKey.(ed25519.PublicKey)
	if !ok {
		return nil, errNotEd25519
	}
	return pub, nil
}

type errString string

func (e errString) Error() string { return string(e) }

const errNotEd25519 = errString("public key is not Ed25519")

// WitnessQuorumResult is the requireWitnessQuorum result.
type WitnessQuorumResult struct {
	OK         bool
	Met        int
	Required   int
	WitnessIDs []string
	Reasons    []string
}

// RequireWitnessQuorum requires >= k DISTINCT pinned witnesses to have validly
// cosigned the SAME head. Duplicate witness_ids count ONCE. Cosignatures that
// fail verification, name an unpinned witness, or reference a different head are
// ignored and recorded in Reasons. Faithful port of witness.js
// requireWitnessQuorum. Fail-closed on bad k / bad inputs.
func RequireWitnessQuorum(checkpoint map[string]any, cosignatures []map[string]any, pinnedWitnessKeys []PinnedWitnessKey, k int, kValid bool) WitnessQuorumResult {
	reasons := []string{}

	if !kValid || k < 1 {
		reasons = append(reasons, "k must be an integer >= 1")
		req := 0
		if kValid {
			req = k
		}
		return WitnessQuorumResult{OK: false, Met: 0, Required: req, WitnessIDs: []string{}, Reasons: reasons}
	}
	if checkpoint == nil {
		reasons = append(reasons, "checkpoint is missing or not an object")
		return WitnessQuorumResult{OK: false, Met: 0, Required: k, WitnessIDs: []string{}, Reasons: reasons}
	}
	if cosignatures == nil {
		reasons = append(reasons, "cosignatures must be an array")
		return WitnessQuorumResult{OK: false, Met: 0, Required: k, WitnessIDs: []string{}, Reasons: reasons}
	}
	if pinnedWitnessKeys == nil {
		reasons = append(reasons, "pinnedWitnessKeys must be an array")
		return WitnessQuorumResult{OK: false, Met: 0, Required: k, WitnessIDs: []string{}, Reasons: reasons}
	}

	// Build the pinned-witness directory. A duplicated witness_id across pinned
	// entries is ambiguous, so it is dropped rather than trusted.
	pinnedByID := map[string]PinnedWitnessKey{}
	seenPinned := map[string]struct{}{}
	dupPinned := map[string]struct{}{}
	for _, w := range pinnedWitnessKeys {
		id := w.WitnessID
		if id == "" {
			reasons = append(reasons, "a pinned witness entry is missing witness_id (dropped)")
			continue
		}
		if _, seen := seenPinned[id]; seen {
			dupPinned[id] = struct{}{}
			continue
		}
		seenPinned[id] = struct{}{}
		pinnedByID[id] = w
	}
	// Deterministic order for the drop reasons.
	dups := make([]string, 0, len(dupPinned))
	for id := range dupPinned {
		dups = append(dups, id)
	}
	sort.Strings(dups)
	for _, id := range dups {
		delete(pinnedByID, id)
		reasons = append(reasons, "pinned witness_id \""+id+"\" appears more than once (dropped as ambiguous)")
	}

	// Count DISTINCT pinned witnesses whose cosignature over THIS head verifies.
	met := map[string]struct{}{}
	for _, cm := range cosignatures {
		cosig := cosignatureFromMap(cm)
		id := cosig.WitnessID
		if id == "" {
			reasons = append(reasons, "a cosignature is missing witness_id (ignored)")
			continue
		}
		if _, counted := met[id]; counted {
			reasons = append(reasons, "duplicate cosignature from witness \""+id+"\" (counted once)")
			continue
		}
		pinned, ok := pinnedByID[id]
		if !ok {
			reasons = append(reasons, "cosignature from unpinned witness \""+id+"\" (ignored)")
			continue
		}
		res := VerifyWitnessCosignature(checkpoint, cosig, pinned)
		if res.Verified {
			met[res.WitnessID] = struct{}{}
		} else {
			reasons = append(reasons, "cosignature from \""+id+"\" did not verify: "+res.Reason)
		}
	}

	witnessIDs := make([]string, 0, len(met))
	for id := range met {
		witnessIDs = append(witnessIDs, id)
	}
	sort.Strings(witnessIDs)

	return WitnessQuorumResult{
		OK:         len(met) >= k,
		Met:        len(met),
		Required:   k,
		WitnessIDs: witnessIDs,
		Reasons:    reasons,
	}
}
