// SPDX-License-Identifier: Apache-2.0
//
// EP-AUTHORITY-DOC-PROOF-JOIN-v1. Faithful same-team Go port of
// lib/authority/document-proof-join.js. The join accepts only the proof issuer;
// grant/action authorization, delegation, and registry membership are separate.
package emiliaverify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	AuthorityDocumentVersion = "EP-AUTHORITY-DOC-v1"
	AuthorityProofVersion    = "EP-AUTHORITY-PROOF-v1"
	AuthorityProofDomain     = "EP-AUTHORITY-PROOF-v1\x00"
)

var (
	authorityDigestRE      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	authorityProofDigestRE = regexp.MustCompile(`(?i)^sha256:[0-9a-f]{64}$`)
	authorityIssuerKIDRE   = regexp.MustCompile(`^ep:authority-issuer-key:sha256:[0-9a-f]{64}$`)
	authorityProofKeyIDRE  = regexp.MustCompile(`^ep:authority-registry-key:sha256:[0-9a-f]{64}$`)
	authorityRFC3339RE     = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$`)
)

var authorityCheckNames = []string{
	"document_chain",
	"continuity",
	"document_anchor",
	"organization_binding",
	"proof_document_binding",
	"registry_issuer_binding",
	"issuer_key_resolved",
	"issuer_key_usage",
	"proof_signature",
	"proof_time_anchor",
	"registry_head",
	"epoch_fresh",
}

// AuthorityJoinResult mirrors verifyAuthorityProofViaDocument's public result.
// Verified is proof mathematics plus chain continuity. Accepted and
// IssuerAccepted additionally require every relying-party trust input.
type AuthorityJoinResult struct {
	Verified            bool            `json:"verified"`
	IssuerAccepted      bool            `json:"issuer_accepted"`
	Accepted            bool            `json:"accepted"`
	AuthorityEvaluated  bool            `json:"authority_evaluated"`
	DelegationEvaluated bool            `json:"delegation_evaluated"`
	Checks              map[string]bool `json:"checks"`
	Reason              string          `json:"reason,omitempty"`
	DocumentHead        string          `json:"document_head,omitempty"`
	ProofDocumentHead   string          `json:"proof_document_head,omitempty"`
	BootstrapDigest     string          `json:"bootstrap_digest,omitempty"`
	RegistryIssuerID    string          `json:"registry_issuer_id,omitempty"`
	ProofDigest         string          `json:"proof_digest,omitempty"`
	KeyID               string          `json:"key_id,omitempty"`
	Limitations         []string        `json:"limitations,omitempty"`
}

type authorityChainResult struct {
	Verified bool
	Head     map[string]any
	Breaks   []int
}

type authorityResolvedKey struct {
	Key              string
	Usages           []string
	CustodyClass     any
	RegistryIssuerID any
	KID              string
	DocSeq           int
}

type authorityProofSignatureResult struct {
	Verified    bool
	Accepted    bool
	Checks      map[string]bool
	Reason      string
	ProofDigest string
	KeyID       string
}

func authorityCopyChecks(checks map[string]bool) map[string]bool {
	out := make(map[string]bool, len(checks))
	for key, value := range checks {
		out[key] = value
	}
	return out
}

func authoritySafeInteger(value any) (int, bool) {
	var number float64
	switch typed := value.(type) {
	case json.Number:
		parsed, err := strconv.ParseFloat(typed.String(), 64)
		if err != nil {
			return 0, false
		}
		number = parsed
	case float64:
		number = typed
	case float32:
		number = float64(typed)
	case int:
		if int64(typed) < -maxSafeInteger || int64(typed) > maxSafeInteger {
			return 0, false
		}
		return typed, true
	case int8:
		return int(typed), true
	case int16:
		return int(typed), true
	case int32:
		return int(typed), true
	case int64:
		if typed < -maxSafeInteger || typed > maxSafeInteger {
			return 0, false
		}
		return int(typed), true
	case uint:
		if uint64(typed) > maxSafeInteger {
			return 0, false
		}
		return int(typed), true
	case uint8:
		return int(typed), true
	case uint16:
		return int(typed), true
	case uint32:
		return int(typed), true
	case uint64:
		if typed > maxSafeInteger {
			return 0, false
		}
		return int(typed), true
	default:
		return 0, false
	}
	if math.IsNaN(number) || math.IsInf(number, 0) || math.Trunc(number) != number ||
		math.Abs(number) > maxSafeInteger {
		return 0, false
	}
	return int(number), true
}

func authorityInstant(value any) (time.Time, bool) {
	raw, ok := value.(string)
	if !ok {
		return time.Time{}, false
	}
	match := authorityRFC3339RE.FindStringSubmatch(raw)
	if match == nil {
		return time.Time{}, false
	}
	if match[9] != "" {
		hour, errHour := strconv.Atoi(match[9])
		minute, errMinute := strconv.Atoi(match[10])
		if errHour != nil || errMinute != nil || hour > 23 || minute > 59 {
			return time.Time{}, false
		}
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

func authorityStableIdentifier(value any) bool {
	raw, ok := value.(string)
	if !ok || raw == "" || utf8.RuneCountInString(raw) > 512 {
		return false
	}
	for _, char := range raw {
		if unicode.IsSpace(char) || char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func authorityEd25519Key(publicKeyB64u any) (ed25519.PublicKey, []byte, bool) {
	raw, ok := publicKeyB64u.(string)
	if !ok {
		return nil, nil, false
	}
	der, err := b64urlDecode(raw)
	if err != nil {
		return nil, nil, false
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, nil, false
	}
	key, ok := parsed.(ed25519.PublicKey)
	return key, der, ok
}

func authorityVerifyEd25519(data []byte, publicKeyB64u, signatureB64u any) bool {
	key, _, ok := authorityEd25519Key(publicKeyB64u)
	if !ok {
		return false
	}
	signatureRaw, ok := signatureB64u.(string)
	if !ok {
		return false
	}
	signature, err := b64urlDecode(signatureRaw)
	return err == nil && ed25519.Verify(key, data, signature)
}

// AuthorityIssuerKeyID derives the full Authority Document issuer key
// identifier from a base64url SPKI-DER Ed25519 key.
func AuthorityIssuerKeyID(publicKeyB64u string) string {
	_, der, ok := authorityEd25519Key(publicKeyB64u)
	if !ok {
		return ""
	}
	digest := sha256.Sum256(der)
	return "ep:authority-issuer-key:sha256:" + hex.EncodeToString(digest[:])
}

// AuthorityDocumentCoreDigest hashes the signed Authority Document core,
// excluding sig, continuity_sig, and endorsements.
func AuthorityDocumentCoreDigest(document map[string]any) string {
	if document == nil {
		return ""
	}
	core := make(map[string]any, len(document))
	for key, value := range document {
		if key != "sig" && key != "continuity_sig" && key != "endorsements" {
			core[key] = value
		}
	}
	digest := sha256.Sum256([]byte(Canonicalize(core)))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func authorityDocumentList(value any) ([]map[string]any, bool) {
	switch typed := value.(type) {
	case []map[string]any:
		if len(typed) == 0 {
			return nil, false
		}
		return typed, true
	case []any:
		if len(typed) == 0 {
			return nil, false
		}
		out := make([]map[string]any, len(typed))
		for index, item := range typed {
			document, ok := item.(map[string]any)
			if !ok {
				return nil, false
			}
			out[index] = document
		}
		return out, true
	default:
		return nil, false
	}
}

func authorityTerminalRevocation(documents []map[string]any, kid string) (time.Time, bool) {
	var terminal time.Time
	found := false
	for _, document := range documents {
		entries, ok := document["issuer_keys"].([]any)
		if !ok {
			if typed, typedOK := document["issuer_keys"].([]map[string]any); typedOK {
				entries = make([]any, len(typed))
				for index := range typed {
					entries[index] = typed[index]
				}
			}
		}
		for _, rawEntry := range entries {
			entry, ok := rawEntry.(map[string]any)
			if !ok || getStr(entry, "kid") != kid {
				continue
			}
			revokedAtRaw, present := entry["revoked_at"]
			if !present {
				continue
			}
			revokedAt, valid := authorityInstant(revokedAtRaw)
			if valid && (!found || revokedAt.Before(terminal)) {
				terminal = revokedAt
				found = true
			}
		}
	}
	return terminal, found
}

func authorityIssuerEntries(document map[string]any) ([]map[string]any, bool) {
	switch typed := document["issuer_keys"].(type) {
	case []any:
		out := make([]map[string]any, len(typed))
		for index, raw := range typed {
			entry, ok := raw.(map[string]any)
			if !ok {
				return nil, false
			}
			out[index] = entry
		}
		return out, true
	case []map[string]any:
		return typed, true
	default:
		return nil, false
	}
}

func authorityStringSlice(value any) ([]string, bool) {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...), true
	case []any:
		out := make([]string, len(typed))
		for index, raw := range typed {
			value, ok := raw.(string)
			if !ok {
				return nil, false
			}
			out[index] = value
		}
		return out, true
	default:
		return nil, false
	}
}

func authoritySameOptionalValue(left, right map[string]any, key string) bool {
	leftValue, leftPresent := left[key]
	rightValue, rightPresent := right[key]
	return leftPresent == rightPresent && (!leftPresent || leftValue == rightValue)
}

func authorityVerifyChain(value any) authorityChainResult {
	documents, ok := authorityDocumentList(value)
	if !ok {
		return authorityChainResult{}
	}
	breaks := []int{}
	registryIdentityByKID := map[string]any{}
	registryIdentityPresent := map[string]bool{}
	firstOrg := getMap(documents[0]["org"])

	for index, document := range documents {
		if getStr(document, "@version") != AuthorityDocumentVersion {
			return authorityChainResult{Breaks: breaks}
		}
		sequence, validSequence := authoritySafeInteger(document["seq"])
		if !validSequence || sequence != index {
			return authorityChainResult{Breaks: breaks}
		}
		org := getMap(document["org"])
		if org == nil || !authorityStableIdentifier(org["domain"]) {
			return authorityChainResult{Breaks: breaks}
		}
		if _, present := org["id"]; present && !authorityStableIdentifier(org["id"]) {
			return authorityChainResult{Breaks: breaks}
		}
		if index > 0 && (getStr(org, "domain") != getStr(firstOrg, "domain") ||
			!authoritySameOptionalValue(org, firstOrg, "id")) {
			return authorityChainResult{Breaks: breaks}
		}
		if _, valid := authorityInstant(document["issued_at"]); !valid {
			return authorityChainResult{Breaks: breaks}
		}
		if _, _, valid := authorityEd25519Key(document["root_key"]); !valid {
			return authorityChainResult{Breaks: breaks}
		}
		entries, validEntries := authorityIssuerEntries(document)
		if !validEntries {
			return authorityChainResult{Breaks: breaks}
		}
		kids := map[string]bool{}
		for _, entry := range entries {
			kid := getStr(entry, "kid")
			if kid == "" || kids[kid] {
				return authorityChainResult{Breaks: breaks}
			}
			kids[kid] = true
			validFrom, fromOK := authorityInstant(entry["valid_from"])
			validTo, toOK := authorityInstant(entry["valid_to"])
			if !fromOK || !toOK || validFrom.After(validTo) {
				return authorityChainResult{Breaks: breaks}
			}
			if revokedRaw, present := entry["revoked_at"]; present {
				if _, valid := authorityInstant(revokedRaw); !valid {
					return authorityChainResult{Breaks: breaks}
				}
			}
			key := getStr(entry, "key")
			if _, _, valid := authorityEd25519Key(key); !valid ||
				AuthorityIssuerKeyID(key) != kid {
				return authorityChainResult{Breaks: breaks}
			}
			registryIdentity, identityPresent := entry["registry_issuer_id"]
			if identityPresent && !authorityStableIdentifier(registryIdentity) {
				return authorityChainResult{Breaks: breaks}
			}
			if previousPresent, seen := registryIdentityPresent[kid]; seen &&
				(previousPresent != identityPresent ||
					(identityPresent && registryIdentityByKID[kid] != registryIdentity)) {
				return authorityChainResult{Breaks: breaks}
			}
			registryIdentityPresent[kid] = identityPresent
			registryIdentityByKID[kid] = registryIdentity
			if usagesRaw, present := entry["usages"]; present {
				usages, valid := authorityStringSlice(usagesRaw)
				if !valid {
					return authorityChainResult{Breaks: breaks}
				}
				seen := map[string]bool{}
				for _, usage := range usages {
					if !authorityStableIdentifier(usage) || seen[usage] {
						return authorityChainResult{Breaks: breaks}
					}
					seen[usage] = true
				}
			}
		}

		core := make(map[string]any, len(document))
		for key, field := range document {
			if key != "sig" && key != "continuity_sig" && key != "endorsements" {
				core[key] = field
			}
		}
		if !authorityVerifyEd25519(
			[]byte(Canonicalize(core)),
			document["root_key"],
			document["sig"],
		) {
			return authorityChainResult{Breaks: breaks}
		}
		if index == 0 {
			previousDigest, present := document["prev_doc_digest"]
			if !present || previousDigest != nil {
				return authorityChainResult{Breaks: breaks}
			}
			continue
		}

		previous := documents[index-1]
		if getStr(document, "prev_doc_digest") != AuthorityDocumentCoreDigest(previous) {
			return authorityChainResult{Breaks: breaks}
		}
		issuedAt, issuedOK := authorityInstant(document["issued_at"])
		previousIssuedAt, previousOK := authorityInstant(previous["issued_at"])
		if !issuedOK || !previousOK || !issuedAt.After(previousIssuedAt) {
			return authorityChainResult{Breaks: breaks}
		}

		continuityKeys := []any{previous["root_key"]}
		previousEntries, _ := authorityIssuerEntries(previous)
		for _, entry := range previousEntries {
			usages, usagesOK := authorityStringSlice(entry["usages"])
			validFrom, fromOK := authorityInstant(entry["valid_from"])
			validTo, toOK := authorityInstant(entry["valid_to"])
			revokedAt, revoked := authorityTerminalRevocation(documents, getStr(entry, "kid"))
			if usagesOK && contains(usages, "authority_doc_rotation") &&
				fromOK && toOK && !issuedAt.Before(validFrom) && !issuedAt.After(validTo) &&
				(!revoked || issuedAt.Before(revokedAt)) {
				continuityKeys = append(continuityKeys, entry["key"])
			}
		}
		continuitySignature, signaturePresent := document["continuity_sig"].(string)
		continuityOK := false
		if signaturePresent {
			digest := []byte(AuthorityDocumentCoreDigest(document))
			for _, key := range continuityKeys {
				if authorityVerifyEd25519(digest, key, continuitySignature) {
					continuityOK = true
					break
				}
			}
		}
		if !continuityOK {
			breaks = append(breaks, index)
		}
	}
	return authorityChainResult{
		Verified: true,
		Head:     documents[len(documents)-1],
		Breaks:   breaks,
	}
}

func authorityResolveIssuerKeyAt(value any, kid string, atISO any) *authorityResolvedKey {
	documents, ok := authorityDocumentList(value)
	at, validAt := authorityInstant(atISO)
	if !ok || !validAt {
		return nil
	}
	if revokedAt, revoked := authorityTerminalRevocation(documents, kid); revoked &&
		!at.Before(revokedAt) {
		return nil
	}

	var effective map[string]any
	for index := len(documents) - 1; index >= 0; index-- {
		issuedAt, valid := authorityInstant(documents[index]["issued_at"])
		if valid && !issuedAt.After(at) {
			effective = documents[index]
			break
		}
	}
	if effective == nil {
		return nil
	}
	entries, ok := authorityIssuerEntries(effective)
	if !ok {
		return nil
	}
	var found map[string]any
	for _, entry := range entries {
		if getStr(entry, "kid") == kid {
			found = entry
			break
		}
	}
	if found == nil {
		return nil
	}
	validFrom, fromOK := authorityInstant(found["valid_from"])
	validTo, toOK := authorityInstant(found["valid_to"])
	if !fromOK || !toOK || at.Before(validFrom) || at.After(validTo) {
		return nil
	}
	usages, _ := authorityStringSlice(found["usages"])
	docSeq, validSeq := authoritySafeInteger(effective["seq"])
	if !validSeq {
		return nil
	}
	return &authorityResolvedKey{
		Key:              getStr(found, "key"),
		Usages:           usages,
		CustodyClass:     found["custody_class"],
		RegistryIssuerID: found["registry_issuer_id"],
		KID:              getStr(found, "kid"),
		DocSeq:           docSeq,
	}
}

func authorityProofDigest(proof map[string]any) string {
	if proof == nil {
		return ""
	}
	unsigned := make(map[string]any, len(proof))
	for key, value := range proof {
		if key != "signature" {
			unsigned[key] = value
		}
	}
	signingBytes := []byte(AuthorityProofDomain + Canonicalize(unsigned))
	digest := sha256.Sum256(signingBytes)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func authorityRegistryKeyID(publicKeyB64u any) string {
	raw, ok := publicKeyB64u.(string)
	if !ok {
		return ""
	}
	der, err := b64urlDecode(raw)
	if err != nil || len(der) == 0 {
		return ""
	}
	digest := sha256.Sum256(der)
	return "ep:authority-registry-key:sha256:" + hex.EncodeToString(digest[:])
}

func authorityVerifyProofSignature(proof map[string]any) authorityProofSignatureResult {
	checks := map[string]bool{
		"version":      proof != nil && getStr(proof, "@type") == AuthorityProofVersion,
		"proof_digest": false,
		"key_id":       false,
		"signature":    false,
	}
	fail := func(reason, proofDigest string) authorityProofSignatureResult {
		return authorityProofSignatureResult{
			Checks: authorityCopyChecks(checks), Reason: reason, ProofDigest: proofDigest,
		}
	}
	if !checks["version"] {
		return fail("unsupported_version", "")
	}
	signature := getMap(proof["signature"])
	if signature == nil || getStr(signature, "algorithm") != "Ed25519" ||
		getStr(signature, "public_key") == "" ||
		getStr(signature, "signature_b64u") == "" ||
		!authorityProofDigestRE.MatchString(getStr(signature, "proof_digest")) ||
		!authorityProofKeyIDRE.MatchString(getStr(signature, "key_id")) {
		return fail("signature_missing_or_malformed", "")
	}
	proofDigest := authorityProofDigest(proof)
	if proofDigest == "" {
		return fail("proof_uncanonicalizable", "")
	}
	checks["proof_digest"] = proofDigest == getStr(signature, "proof_digest")
	if !checks["proof_digest"] {
		return fail("proof_digest_mismatch", proofDigest)
	}
	derivedKeyID := authorityRegistryKeyID(signature["public_key"])
	checks["key_id"] = derivedKeyID != "" && derivedKeyID == getStr(signature, "key_id")
	if !checks["key_id"] {
		return fail("key_id_mismatch", proofDigest)
	}
	unsigned := make(map[string]any, len(proof))
	for key, value := range proof {
		if key != "signature" {
			unsigned[key] = value
		}
	}
	checks["signature"] = authorityVerifyEd25519(
		[]byte(AuthorityProofDomain+Canonicalize(unsigned)),
		signature["public_key"],
		signature["signature_b64u"],
	)
	if !checks["signature"] {
		return fail("signature_invalid", proofDigest)
	}
	return authorityProofSignatureResult{
		Verified: true, Accepted: false, Checks: authorityCopyChecks(checks),
		ProofDigest: proofDigest, KeyID: derivedKeyID,
	}
}

func authorityExactKeys(value map[string]any, keys ...string) bool {
	if len(value) != len(keys) {
		return false
	}
	allowed := map[string]bool{}
	for _, key := range keys {
		allowed[key] = true
	}
	for key := range value {
		if !allowed[key] {
			return false
		}
	}
	return true
}

// VerifyAuthorityProofViaDocument verifies a proof issuer through a relying
// party-anchored Authority Document chain. opts uses the wire-compatible JS
// names present in the shared fixtures. The function is fail-closed and does
// not panic on malformed native inputs.
func VerifyAuthorityProofViaDocument(proof map[string]any, documentValue any, opts map[string]any) AuthorityJoinResult {
	if opts == nil {
		opts = map[string]any{}
	}
	checks := make(map[string]bool, len(authorityCheckNames))
	for _, name := range authorityCheckNames {
		checks[name] = false
	}
	signature := authorityVerifyProofSignature(proof)
	checks["proof_signature"] = signature.Verified

	documentHead := ""
	bootstrapDigest := ""
	fail := func(reason string) AuthorityJoinResult {
		return AuthorityJoinResult{
			Verified: checks["proof_signature"] && checks["document_chain"] && checks["continuity"],
			Checks:   authorityCopyChecks(checks), Reason: reason,
			DocumentHead: documentHead, BootstrapDigest: bootstrapDigest,
		}
	}

	documents, docsOK := authorityDocumentList(documentValue)
	chain := authorityVerifyChain(documentValue)
	if !docsOK || !chain.Verified || chain.Head == nil {
		return fail("authority_document_chain_invalid")
	}
	checks["document_chain"] = true
	documentHead = AuthorityDocumentCoreDigest(chain.Head)
	bootstrapDigest = AuthorityDocumentCoreDigest(documents[0])
	if documentHead == "" || bootstrapDigest == "" {
		return fail("authority_document_chain_invalid")
	}
	if len(chain.Breaks) > 0 {
		return fail("authority_document_continuity_break")
	}
	checks["continuity"] = true

	expectedHead, hasHeadAnchor := opts["expectedDocumentHead"].(string)
	expectedBootstrap, hasBootstrapAnchor := opts["expectedBootstrapDigest"].(string)
	if !hasHeadAnchor && !hasBootstrapAnchor {
		return fail("authority_document_anchor_required")
	}
	if (hasHeadAnchor && expectedHead != documentHead) ||
		(hasBootstrapAnchor && expectedBootstrap != bootstrapDigest) {
		return fail("authority_document_anchor_mismatch")
	}
	checks["document_anchor"] = true

	organizationID := opts["expectedOrganizationId"]
	organizationDomain := opts["expectedOrganizationDomain"]
	if !authorityStableIdentifier(organizationID) || !authorityStableIdentifier(organizationDomain) ||
		proof == nil || proof["organization_id"] != organizationID {
		return fail("authority_document_organization_mismatch")
	}
	for _, document := range documents {
		org := getMap(document["org"])
		if org == nil || org["id"] != organizationID || org["domain"] != organizationDomain {
			return fail("authority_document_organization_mismatch")
		}
	}
	checks["organization_binding"] = true

	expectedProofTime, hasProofTime := opts["expectedProofIssuedAt"].(string)
	if !hasProofTime {
		return fail("authority_proof_time_anchor_required")
	}
	if _, valid := authorityInstant(expectedProofTime); !valid {
		return fail("authority_proof_time_anchor_invalid")
	}
	proofIssuedAt, proofTimeValid := authorityInstant(proof["issued_at"])
	if !proofTimeValid {
		return fail("authority_proof_time_anchor_invalid")
	}
	if getStr(proof, "issued_at") != expectedProofTime || proofIssuedAt.IsZero() {
		return fail("authority_proof_time_anchor_mismatch")
	}
	checks["proof_time_anchor"] = true

	binding := getMap(proof["authority_document"])
	bindingSeq, sequenceOK := authoritySafeInteger(binding["head_seq"])
	if binding == nil || !authorityExactKeys(binding, "head_digest", "head_seq", "issuer_kid") ||
		!authorityDigestRE.MatchString(getStr(binding, "head_digest")) ||
		!sequenceOK || bindingSeq < 0 || bindingSeq >= len(documents) ||
		!authorityIssuerKIDRE.MatchString(getStr(binding, "issuer_kid")) {
		return fail("authority_proof_document_binding_missing_or_malformed")
	}
	boundDocument := documents[bindingSeq]
	if AuthorityDocumentCoreDigest(boundDocument) != getStr(binding, "head_digest") {
		return fail("authority_proof_document_head_mismatch")
	}
	checks["proof_document_binding"] = true

	registryIssuerID := opts["expectedRegistryIssuerId"]
	if !authorityStableIdentifier(registryIssuerID) ||
		!authorityStableIdentifier(proof["registry_issuer_id"]) ||
		proof["registry_issuer_id"] != registryIssuerID {
		return fail("authority_registry_issuer_mismatch")
	}
	boundEntries, _ := authorityIssuerEntries(boundDocument)
	var boundEntry map[string]any
	for _, entry := range boundEntries {
		if getStr(entry, "kid") == getStr(binding, "issuer_kid") {
			boundEntry = entry
			break
		}
	}
	if boundEntry == nil || boundEntry["registry_issuer_id"] != registryIssuerID {
		return fail("authority_registry_issuer_mismatch")
	}
	checks["registry_issuer_binding"] = true

	resolved := authorityResolveIssuerKeyAt(documentValue, getStr(binding, "issuer_kid"), expectedProofTime)
	proofSignature := getMap(proof["signature"])
	if resolved == nil || resolved.KID != getStr(binding, "issuer_kid") ||
		resolved.DocSeq != bindingSeq || resolved.Key != getStr(boundEntry, "key") ||
		resolved.Key != getStr(proofSignature, "public_key") ||
		resolved.RegistryIssuerID != registryIssuerID {
		return fail("authority_proof_key_unresolvable")
	}
	checks["issuer_key_resolved"] = true
	if !contains(resolved.Usages, "authority_proof_issuer") {
		return fail("authority_proof_key_wrong_usage")
	}
	checks["issuer_key_usage"] = true

	if !signature.Verified {
		result := fail(signature.Reason)
		result.ProofDigest = signature.ProofDigest
		return result
	}

	expectedRegistryHead, headPinOK := opts["expectRegistryHead"].(string)
	minEpoch, minEpochOK := authoritySafeInteger(opts["expectMinEpoch"])
	if !headPinOK || !authorityDigestRE.MatchString(expectedRegistryHead) ||
		!minEpochOK || minEpoch < 0 {
		result := fail("registry_snapshot_pins_required")
		result.ProofDigest = signature.ProofDigest
		return result
	}
	if getStr(proof, "registry_head") != expectedRegistryHead {
		result := fail("registry_head_mismatch")
		result.ProofDigest = signature.ProofDigest
		return result
	}
	checks["registry_head"] = true
	proofEpoch, proofEpochOK := authoritySafeInteger(proof["registry_epoch"])
	if !proofEpochOK || proofEpoch < minEpoch {
		result := fail("stale_registry")
		result.ProofDigest = signature.ProofDigest
		return result
	}
	checks["epoch_fresh"] = true

	return AuthorityJoinResult{
		Verified: true, IssuerAccepted: true, Accepted: true,
		Checks:       authorityCopyChecks(checks),
		DocumentHead: documentHead, ProofDocumentHead: getStr(binding, "head_digest"),
		BootstrapDigest: bootstrapDigest, RegistryIssuerID: registryIssuerID.(string),
		ProofDigest: signature.ProofDigest, KeyID: getStr(binding, "issuer_kid"),
		Limitations: []string{
			"Issuer acceptance is not a decision that the grant authorizes an action.",
			"Grant scope, limits, validity, revocation freshness, and delegation require separate evaluation.",
			"Authority-registry membership requires independently verified snapshot or inclusion evidence.",
		},
	}
}
