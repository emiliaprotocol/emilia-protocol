// SPDX-License-Identifier: Apache-2.0
package emiliaverify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOrderedPrefixQuorumTwoOfThree(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "conformance", "vectors", "quorum.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var suite struct {
		Vectors []struct {
			ID     string         `json:"id"`
			Quorum map[string]any `json:"quorum"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &suite); err != nil {
		t.Fatal(err)
	}
	for _, vector := range suite.Vectors {
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
