// SPDX-License-Identifier: Apache-2.0
package emiliaverify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type quorumSuite struct {
	Vectors []struct {
		ID     string         `json:"id"`
		Quorum map[string]any `json:"quorum"`
		Expect struct {
			Valid bool `json:"valid"`
		} `json:"expect"`
	} `json:"vectors"`
}

func loadQuorumSuite(t *testing.T) quorumSuite {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "vectors", "quorum.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var suite quorumSuite
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatal(err)
	}
	if len(suite.Vectors) == 0 {
		t.Fatal("quorum suite is empty")
	}
	return suite
}

// Every shared EP-QUORUM-v1 vector must produce the same verdict here as in
// the JS and Python runtimes. Verdict parity is the parity claim; a vector
// that one runtime accepts and another refuses is a conformance failure.
func TestQuorumVectorsMatchExpect(t *testing.T) {
	for _, vector := range loadQuorumSuite(t).Vectors {
		result := VerifyQuorumWithOrigins(vector.Quorum, "emiliaprotocol.ai", []string{"https://www.emiliaprotocol.ai"})
		if result.Valid != vector.Expect.Valid {
			t.Errorf("%s: expected valid=%v, got %v (checks=%#v reason=%q)", vector.ID, vector.Expect.Valid, result.Valid, result.Checks, result.Reason)
		}
	}
}

func TestOrderedPrefixQuorumTwoOfThree(t *testing.T) {
	for _, vector := range loadQuorumSuite(t).Vectors {
		if vector.ID != "accept_ordered_2of3" {
			continue
		}
		result := VerifyQuorumWithOrigins(vector.Quorum, "emiliaprotocol.ai", []string{"https://www.emiliaprotocol.ai"})
		if !result.Valid {
			t.Fatalf("ordered 2-of-3 prefix quorum refused: %#v", result.Checks)
		}
		return
	}
	t.Fatal("shared vector accept_ordered_2of3 not found")
}

// A textual variant of one key is one signer. Seat 2 presents the same SPKI
// with base64 padding; the strict decoder must refuse it so the signature
// never counts and distinct_keys cannot be evaded by re-encoding.
func TestNonCanonicalSPKICannotFillASeat(t *testing.T) {
	for _, vector := range loadQuorumSuite(t).Vectors {
		if vector.ID != "reject_noncanonical_spki_second_seat" {
			continue
		}
		result := VerifyQuorumWithOrigins(vector.Quorum, "emiliaprotocol.ai", []string{"https://www.emiliaprotocol.ai"})
		if result.Valid || result.Checks["all_signatures_valid"] {
			t.Fatalf("non-canonical SPKI filled a seat: %#v", result.Checks)
		}
		return
	}
	t.Fatal("shared vector reject_noncanonical_spki_second_seat not found")
}

// required_algorithms must be refused by name when unparseable, never ignored.
func TestRequiredAlgorithmsRefusedByName(t *testing.T) {
	want := map[string]string{
		"reject_required_algorithms_malformed": "required_algorithms_malformed",
		"reject_required_algorithms_unknown":   "required_algorithms_unknown:RS256",
	}
	seen := 0
	for _, vector := range loadQuorumSuite(t).Vectors {
		reason, ok := want[vector.ID]
		if !ok {
			continue
		}
		seen++
		result := VerifyQuorumWithOrigins(vector.Quorum, "emiliaprotocol.ai", []string{"https://www.emiliaprotocol.ai"})
		if result.Valid || result.Reason != reason {
			t.Errorf("%s: expected refusal %q, got valid=%v reason=%q", vector.ID, reason, result.Valid, result.Reason)
		}
	}
	if seen != len(want) {
		t.Fatalf("expected %d required_algorithms vectors, found %d", len(want), seen)
	}
}
