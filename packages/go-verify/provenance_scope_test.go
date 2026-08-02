// SPDX-License-Identifier: Apache-2.0
package emiliaverify

import "testing"

func TestProvenanceScopeGrammarRejectsEmptyPrefixWildcard(t *testing.T) {
	if !provScopeContained(
		map[string]any{"scope": []any{"*"}},
		map[string]any{"scope": []any{"*"}},
	) {
		t.Fatal("universal child scope must be contained by universal parent scope")
	}
	if !provScopeContained(
		map[string]any{"scope": []any{"payment.*"}},
		map[string]any{"scope": []any{"payment.release"}},
	) {
		t.Fatal("concrete child scope must be contained by its non-empty prefix wildcard")
	}
	if provScopeContained(
		map[string]any{"scope": []any{"*"}},
		map[string]any{"scope": []any{".*"}},
	) {
		t.Fatal("empty-prefix wildcard must be rejected rather than widened to universal authority")
	}
}
