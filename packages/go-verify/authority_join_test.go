// SPDX-License-Identifier: Apache-2.0
package emiliaverify

import (
	"strings"
	"testing"
)

func authorityJoinVector(t *testing.T, id string) map[string]any {
	t.Helper()
	suite := loadSuite(t, "authority-document-proof-join.exec.v1.json")
	for _, vector := range suiteVectors(t, suite, "authority document proof join") {
		if vecID(vector) == id {
			return vector
		}
	}
	t.Fatalf("vector %s not found", id)
	return nil
}

func authorityJoinRun(vector map[string]any) AuthorityJoinResult {
	return VerifyAuthorityProofViaDocument(
		getMap(vector["proof"]),
		vector["docs"],
		getMap(vector["opts"]),
	)
}

func authorityJoinExpected(vector map[string]any) (bool, string) {
	expect := getMap(vector["expect"])
	accepted, _ := expect["accepted"].(bool)
	return accepted, getStr(expect, "reason")
}

func TestAuthorityJoinExactShared26CaseFixtureParity(t *testing.T) {
	suite := loadSuite(t, "authority-document-proof-join.exec.v1.json")
	vectors := suiteVectors(t, suite, "authority-document-proof-join.exec.v1.json")
	if len(vectors) != 26 {
		t.Fatalf("shared fixture count=%d want 26", len(vectors))
	}
	for _, vector := range vectors {
		id := vecID(vector)
		t.Run(id, func(t *testing.T) {
			result := authorityJoinRun(vector)
			wantAccepted, wantReason := authorityJoinExpected(vector)
			if result.Accepted != wantAccepted || result.IssuerAccepted != wantAccepted {
				t.Fatalf("accepted=%v issuer_accepted=%v want %v result=%+v",
					result.Accepted, result.IssuerAccepted, wantAccepted, result)
			}
			if wantReason != "" && result.Reason != wantReason {
				t.Fatalf("reason=%q want %q result=%+v", result.Reason, wantReason, result)
			}
		})
	}
}

func TestAuthorityJoinVerifiedDoesNotCollapseIntoAccepted(t *testing.T) {
	result := authorityJoinRun(authorityJoinVector(t, "reject_no_document_anchor"))
	if !result.Verified || result.Accepted || result.IssuerAccepted {
		t.Fatalf("verified/accepted split lost: %+v", result)
	}
	if !result.Checks["proof_signature"] || !result.Checks["document_chain"] ||
		!result.Checks["continuity"] {
		t.Fatalf("verification checks=%v", result.Checks)
	}
}

func TestAuthorityJoinAcceptanceRequiresEveryJoinCheck(t *testing.T) {
	vector := authorityJoinVector(t, "accept_anchored_document_key_at_issuance")
	result := authorityJoinRun(vector)
	if !result.Accepted {
		t.Fatalf("accept fixture refused: %+v", result)
	}
	for name, value := range result.Checks {
		if !value {
			t.Fatalf("accepted with %s=false: %v", name, result.Checks)
		}
	}
	if result.AuthorityEvaluated || result.DelegationEvaluated {
		t.Fatalf("join exceeded issuer-acceptance scope: %+v", result)
	}
	opts := getMap(vector["opts"])
	if result.DocumentHead != getStr(opts, "expectedDocumentHead") ||
		result.BootstrapDigest != getStr(opts, "expectedBootstrapDigest") {
		t.Fatalf("anchor outputs mismatch: %+v", result)
	}
}

func TestAuthorityJoinNewestEffectiveDocumentOmissionRemovesKey(t *testing.T) {
	vector := authorityJoinVector(t, "accept_anchored_document_key_at_issuance")
	proof := getMap(vector["proof"])
	binding := getMap(proof["authority_document"])
	docs, ok := authorityDocumentList(vector["docs"])
	if !ok {
		t.Fatal("fixture docs malformed")
	}
	docs[len(docs)-1]["issuer_keys"] = []any{}
	opts := getMap(vector["opts"])
	if resolved := authorityResolveIssuerKeyAt(
		docs,
		getStr(binding, "issuer_kid"),
		opts["expectedProofIssuedAt"],
	); resolved != nil {
		t.Fatalf("omitted key fell through to older state: %+v", resolved)
	}
}

func TestAuthorityJoinTerminalRevocationCannotBeResurrected(t *testing.T) {
	vector := authorityJoinVector(t, "accept_anchored_document_key_at_issuance")
	proof := getMap(vector["proof"])
	binding := getMap(proof["authority_document"])
	docs, ok := authorityDocumentList(vector["docs"])
	if !ok {
		t.Fatal("fixture docs malformed")
	}
	entries, _ := authorityIssuerEntries(docs[len(docs)-1])
	entry := entries[0]
	revoked := map[string]any{}
	resurrected := map[string]any{}
	for key, value := range entry {
		revoked[key] = value
		resurrected[key] = value
	}
	revoked["revoked_at"] = "2026-07-01T00:00:00.000Z"
	synthetic := []map[string]any{
		{"issued_at": "2026-06-01T00:00:00.000Z", "seq": 0, "issuer_keys": []any{revoked}},
		{"issued_at": "2026-07-05T00:00:00.000Z", "seq": 1, "issuer_keys": []any{resurrected}},
	}
	if resolved := authorityResolveIssuerKeyAt(
		synthetic,
		getStr(binding, "issuer_kid"),
		"2026-07-10T00:00:00.000Z",
	); resolved != nil {
		t.Fatalf("terminal revocation resurrected: %+v", resolved)
	}
}

func TestAuthorityJoinUnstableIdentifierFailsAfterVerification(t *testing.T) {
	vector := authorityJoinVector(t, "accept_anchored_document_key_at_issuance")
	opts := map[string]any{}
	for key, value := range getMap(vector["opts"]) {
		opts[key] = value
	}
	opts["expectedOrganizationId"] = "org 1"
	result := VerifyAuthorityProofViaDocument(getMap(vector["proof"]), vector["docs"], opts)
	if !result.Verified || result.Accepted ||
		result.Reason != "authority_document_organization_mismatch" {
		t.Fatalf("unstable identifier verdict=%+v", result)
	}
}

func TestAuthorityStableIdentifierBoundsUnicodeCodePoints(t *testing.T) {
	if !authorityStableIdentifier(strings.Repeat("😀", 512)) {
		t.Fatal("512 Unicode code points must be accepted")
	}
	if authorityStableIdentifier(strings.Repeat("😀", 513)) {
		t.Fatal("513 Unicode code points must be refused")
	}
}

func TestAuthorityJoinMalformedNativeInputsFailClosed(t *testing.T) {
	for _, docs := range []any{
		nil,
		map[string]any{},
		[]any{nil},
		[]any{float64(42)},
		[]any{map[string]any{"@version": AuthorityDocumentVersion}},
	} {
		result := VerifyAuthorityProofViaDocument(map[string]any{}, docs, map[string]any{})
		if result.Verified || result.IssuerAccepted ||
			result.Reason != "authority_document_chain_invalid" {
			t.Fatalf("docs=%#v result=%+v", docs, result)
		}
	}
}
