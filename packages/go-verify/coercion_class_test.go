// SPDX-License-Identifier: Apache-2.0
package emiliaverify

import "testing"

// Regression suite for the type-coercion / assertion class (the one Karthik caught),
// closing the remaining instances found by the surface sweep. Each asserts fail-closed
// behavior and cross-port-consistent coercion.

// provScopeContained must REFUSE a present-but-non-numeric child cap (fail-open before:
// toFloat conflated absent with non-numeric, so a garbage cap inherited the parent).
func TestProvScopeContained_NonNumericChildCapFailsClosed(t *testing.T) {
	parent := map[string]any{"scope": []any{"pay"}, "max_value_usd": float64(100)}
	if provScopeContained(parent, map[string]any{"scope": []any{"pay"}, "max_value_usd": "abc"}) {
		t.Fatal("fail-open: non-numeric child cap must not be contained")
	}
	if provScopeContained(parent, map[string]any{"scope": []any{"pay"}, "max_value_usd": map[string]any{}}) {
		t.Fatal("fail-open: object child cap must not be contained")
	}
	if provScopeContained(parent, map[string]any{"scope": []any{"pay"}, "max_value_usd": float64(1_000_000)}) {
		t.Fatal("child cap 1e6 above parent 100 must not be contained")
	}
	if !provScopeContained(parent, map[string]any{"scope": []any{"pay"}, "max_value_usd": float64(50)}) {
		t.Fatal("child cap 50 within parent 100 must be contained")
	}
	if !provScopeContained(parent, map[string]any{"scope": []any{"pay"}}) {
		t.Fatal("absent child cap inherits parent and must be contained")
	}
	if !provScopeContained(parent, map[string]any{"scope": []any{"pay"}, "max_value_usd": nil}) {
		t.Fatal("null child cap inherits parent and must be contained")
	}
}

// jsonInt must accept an integral-valued decimal ("3.0") the same as 3 and float64(3),
// so the consumption-proof tree_size does not diverge across the ports.
func TestJsonInt_IntegralDecimalAccepted(t *testing.T) {
	if n, ok := jsonInt(float64(3)); !ok || n != 3 {
		t.Fatalf("float64(3) -> %d,%v", n, ok)
	}
	// json.Number path (UseNumber decode): "3.0" must be accepted as 3.
	m := decodeUseNumber(t, `{"n":3.0}`)
	if n, ok := jsonInt(m["n"]); !ok || n != 3 {
		t.Fatalf("json.Number 3.0 -> %d,%v (must be 3,true)", n, ok)
	}
	// A non-integral decimal must still be rejected.
	if _, ok := jsonInt(decodeUseNumber(t, `{"n":3.5}`)["n"]); ok {
		t.Fatal("json.Number 3.5 must be rejected by jsonInt")
	}
}
