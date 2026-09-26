package caid

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// The shared vectors reach the integer field type through DecodeJSON
// (json.Number). These cases pin the other decoded forms a Go caller can
// supply, float64 from a decoder without UseNumber and int/int64 built in
// code, to the same value-based rule.
func TestIntegerFieldTypeIsValueBased(t *testing.T) {
	field := map[string]interface{}{"name": "n", "type": "integer"}
	for _, value := range []interface{}{
		json.Number("12"), json.Number("12.0"), json.Number("1.2e1"), json.Number("-0"),
		json.Number("9007199254740992"), json.Number("1e20"),
		float64(12), float64(1e20), int(12), int64(-12),
	} {
		if got := checkFieldType(value, field, nil); got != "" {
			t.Errorf("checkFieldType(%#v) = %q, want type-valid", value, got)
		}
	}
	for _, value := range []interface{}{
		json.Number("12.5"), json.Number("1" + strings.Repeat("0", 309)), json.Number("1e400"),
		float64(12.5), math.Inf(1), math.NaN(), "12", true, nil,
	} {
		if got := checkFieldType(value, field, nil); got != "mistyped_field" {
			t.Errorf("checkFieldType(%#v) = %q, want mistyped_field", value, got)
		}
	}
}
