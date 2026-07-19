// SPDX-License-Identifier: Apache-2.0
//
// TLA+-invariant cross-language conformance runner — Go lane (SCAFFOLD).
//
// STATUS: SCAFFOLDED, NOT WIRED. This lane parses the shared invariant corpus
// (conformance/invariants.json) and walks every case by domain, mirroring the
// JavaScript lane (conformance/runners/run-invariants.mjs), so that once the
// state machines gain Go ports this file drives them with no corpus changes and
// any cross-port divergence surfaces immediately.
//
// WIRING BLOCKER (precise): the invariants are STATE-MACHINE properties. Driving
// them in Go requires a Go port of the two production state machines the JS lane
// drives:
//   - capability domain: createMemoryCapabilityStore (register/reserveSpend/
//     commitSpend) in packages/gate/capability-receipt.js
//   - handshake domain:  checkNoDuplicateResult / checkResultImmutability /
//     checkNotExpired / checkBindingValid in lib/handshake/invariants.js
//
// packages/go-verify today verifies RECEIPT vectors only (trust_receipt.go,
// signoff.go, ...); it has NO capability store and NO handshake invariant
// module. Until such a port exists, wiring this lane would mean re-implementing
// the state machines here — a NEW implementation the author writes, which cannot
// honestly detect a divergence from itself. So this lane is intentionally left
// unwired and reports SKIPPED(unwired) rather than fabricating a pass.
//
// When a Go port lands (proposed: packages/go-verify/capability_store.go and
// packages/go-verify/handshake_invariants.go), replace the dispatch bodies below
// and flip unwired to false.
//
// Standalone (stdlib only): go run conformance/runners/run_invariants.go [corpus.json]
// Exit codes: 0 = every case executed and held; 2 = lane is unwired (default
// today) so it can never be mistaken for a passing conformance lane.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const unwired = true // flip to false once the Go state-machine ports exist.

type invariant struct {
	Invariant string    `json:"invariant"`
	Spec      string    `json:"spec"`
	Domain    string    `json:"domain"`
	Cases     []invCase `json:"cases"`
}

type invCase struct {
	Name    string            `json:"name"`
	Actions []json.RawMessage `json:"actions"`
}

type corpus struct {
	Invariants []invariant `json:"invariants"`
}

func main() {
	args := []string{}
	for _, a := range os.Args[1:] {
		if !strings.HasPrefix(a, "--") {
			args = append(args, a)
		}
	}
	corpusPath := ""
	if len(args) > 0 {
		corpusPath = args[0]
	} else {
		exe, _ := os.Getwd()
		corpusPath = filepath.Join(exe, "conformance", "invariants.json")
	}

	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read corpus %s: %v\n", corpusPath, err)
		os.Exit(2)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		fmt.Fprintf(os.Stderr, "cannot parse corpus: %v\n", err)
		os.Exit(2)
	}

	total := 0
	for _, inv := range c.Invariants {
		total += len(inv.Cases)
	}

	if unwired {
		fmt.Println("EP invariant conformance — Go lane: SCAFFOLD (UNWIRED)")
		fmt.Printf("  parsed %d cases across %d invariants from %s\n", total, len(c.Invariants), corpusPath)
		fmt.Println("  no Go port of the capability store / handshake invariants exists yet;")
		fmt.Println("  see the wiring blocker at the top of this file. Reporting SKIPPED(unwired).")
		os.Exit(2)
	}

	// TODO(go-port): dispatch each case by inv.Domain against the Go state-machine
	// ports and compare observed outcomes to the declared expectations.
	failures := 0
	for _, inv := range c.Invariants {
		for _, kase := range inv.Cases {
			_ = kase
			fmt.Printf("  ok   %s/%s  %s\n", inv.Invariant, kase.Name, inv.Spec)
		}
	}
	fmt.Printf("\n%d/%d invariant cases hold.\n", total-failures, total)
	if failures > 0 {
		os.Exit(1)
	}
}
