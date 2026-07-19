// SPDX-License-Identifier: Apache-2.0
package emiliaverify

import (
	"encoding/json"
	"strings"
	"testing"
)

// decodeUseNumber decodes JSON via the package's real UseNumber() contract, so
// numbers arrive as json.Number (not float64) — the exact path the documented
// entry point (VerifyReceiptJSON / decodeJSON) uses. The conformance runner uses
// plain json.Unmarshal (float64), which is why these fail-open/fail-closed
// regressions never surfaced in the cross-language vector run.
func decodeUseNumber(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	if err := d.Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

// Regression (P0 fail-open, reported by Karthik Rampalli): a child delegation
// whose monetary ceiling EXCEEDS its parent's must NOT be scope-contained. Before
// toFloat learned json.Number, it fell through on the UseNumber path so
// provScopeContained skipped the ceiling guard entirely and returned true.
func TestProvScopeContained_ValueCapFailClosedUnderUseNumber(t *testing.T) {
	parent := decodeUseNumber(t, `{"max_value_usd":100}`)
	if provScopeContained(parent, decodeUseNumber(t, `{"max_value_usd":1000000}`)) {
		t.Fatal("fail-open: child cap 1000000 above parent cap 100 must not be contained")
	}
	if !provScopeContained(parent, decodeUseNumber(t, `{"max_value_usd":50}`)) {
		t.Fatal("child cap 50 within parent cap 100 must be contained")
	}
	if !provScopeContained(parent, decodeUseNumber(t, `{"max_value_usd":100}`)) {
		t.Fatal("equal caps must be contained")
	}
}

// Regression (P1 fail-closed): constraintsMonotonic must ACCEPT a child that
// tightens a numeric ceiling (10 -> 5) and REJECT one that relaxes it (10 -> 20),
// under the UseNumber decode path. Before the fix, json.Number fell through to the
// canonical-equality branch and a legitimate tightening was wrongly rejected.
func TestConstraintsMonotonic_NumericTighteningUnderUseNumber(t *testing.T) {
	parent := decodeUseNumber(t, `{"limit":10}`)
	if !constraintsMonotonic(parent, decodeUseNumber(t, `{"limit":5}`)) {
		t.Fatal("child tightening 10->5 must be monotonic")
	}
	if constraintsMonotonic(parent, decodeUseNumber(t, `{"limit":20}`)) {
		t.Fatal("child relaxing 10->20 must not be monotonic")
	}
}

// toFloat itself must accept json.Number alongside float64/int, and reject the
// non-numeric default.
func TestToFloat_AcceptsJSONNumber(t *testing.T) {
	m := decodeUseNumber(t, `{"n":42}`)
	if f, ok := toFloat(m["n"]); !ok || f != 42 {
		t.Fatalf("json.Number 42 -> (%v,%v), want (42,true)", f, ok)
	}
	if f, ok := toFloat(3.5); !ok || f != 3.5 {
		t.Fatalf("float64 3.5 -> (%v,%v)", f, ok)
	}
	if _, ok := toFloat("nope"); ok {
		t.Fatal("string must not convert to float")
	}
}
