// SPDX-License-Identifier: Apache-2.0
package emiliaverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func signedRevocationForTimestamp(t *testing.T, revokedAt string) (map[string]any, map[string]any, map[string]any) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyB64u := base64.RawURLEncoding.EncodeToString(der)
	digest := sha256.Sum256(der)
	revokerID := "ep:revoker:fractional-seconds"
	target := map[string]any{
		"target_type": "receipt",
		"target_id":   "rcpt_fractional_seconds",
		"action_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	signed := map[string]any{
		"@version":    RevocationVersion,
		"action_hash": target["action_hash"],
		"reason":      "grammar boundary",
		"revoked_at":  revokedAt,
		"revoker_id":  revokerID,
		"target_id":   target["target_id"],
		"target_type": target["target_type"],
	}
	statement := map[string]any{
		"@version":    RevocationVersion,
		"target_type": target["target_type"],
		"target_id":   target["target_id"],
		"action_hash": target["action_hash"],
		"revoker_id":  revokerID,
		"revoked_at":  revokedAt,
		"reason":      signed["reason"],
		"proof": map[string]any{
			"algorithm":      "Ed25519",
			"revoker_key_id": "ep:revoker-key:sha256:" + hex.EncodeToString(digest[:]),
			"public_key":     publicKeyB64u,
			"signature_b64u": base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(Canonicalize(signed)))),
		},
	}
	opts := map[string]any{
		"revokerKeys": map[string]any{
			revokerID: map[string]any{"public_key": publicKeyB64u},
		},
		"now": "2026-06-20T12:00:01Z",
	}
	return target, statement, opts
}

func TestVerifyRevocationAcceptsFractionalSecondGrammarBoundaries(t *testing.T) {
	for _, revokedAt := range []string{
		"2026-06-20T12:00:00.1Z",
		"2026-06-20T12:00:00.123456789Z",
	} {
		t.Run(revokedAt, func(t *testing.T) {
			target, statement, opts := signedRevocationForTimestamp(t, revokedAt)
			result := VerifyRevocation(target, statement, opts)
			if !result.Valid {
				t.Fatalf("expected valid revocation, checks=%v", result.Checks)
			}
		})
	}
}
