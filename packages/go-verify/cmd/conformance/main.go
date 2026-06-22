// SPDX-License-Identifier: Apache-2.0
// Go conformance runner: emits [{id, valid}] for each vector. os.Args[1] = vectors path.
// Polymorphic: receipt (document) | signoff | quorum.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	emiliaverify "github.com/emiliaprotocol/emilia-protocol/packages/go-verify"
)

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
			valid = emiliaverify.VerifyTrustReceipt(v.TrustReceipt, opts).Valid
		}
		out = append(out, map[string]any{"id": v.ID, "valid": valid})
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
