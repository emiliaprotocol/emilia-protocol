// SPDX-License-Identifier: Apache-2.0
// Go conformance runner: emits [{id, valid}] for each vector. os.Args[1] = vectors path.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	emiliaverify "github.com/emiliaprotocol/emilia-protocol/packages/go-verify"
)

type vec struct {
	ID        string         `json:"id"`
	PublicKey string         `json:"public_key"`
	Document  map[string]any `json:"document"`
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
		r := emiliaverify.VerifyReceipt(v.Document, v.PublicKey)
		out = append(out, map[string]any{"id": v.ID, "valid": r.Valid})
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
