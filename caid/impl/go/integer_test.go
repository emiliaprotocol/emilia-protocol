package caid

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// The integer field type is value-based: a number whose binary64 value is a
// finite integer is type-valid whatever its literal form. Magnitude is not
// part of the type check (an integer above 2^53-1 is refused once, as
// unsupported_number).
func TestIntegerFieldTypeIsValueBased(t *testing.T) {
	field := obj{"name": "n", "type": "integer"}
	for _, value := range []interface{}{
		json.Number("12"), json.Number("12.0"), json.Number("1.2e1"), json.Number("-0"), json.Number("1e-400"),
		json.Number("9007199254740992"), json.Number("1e20"), json.Number("0.99999999999999999999"),
		float64(12), float64(1e20), int(12), int64(-12),
	} {
		if got := checkField(value, field, nil); got != "" {
			t.Errorf("checkField(%#v) = %q, want type-valid", value, got)
		}
	}
	for _, value := range []interface{}{
		json.Number("12.5"), json.Number("1" + strings.Repeat("0", 309)), json.Number("1e400"), json.Number("NaN"),
		json.Number("1_2"), float64(12.5), math.Inf(1), math.NaN(), "12", true, nil, int32(12),
	} {
		if got := checkField(value, field, nil); got != "mistyped_field" {
			t.Errorf("checkField(%#v) = %q, want mistyped_field", value, got)
		}
	}
	// Midpoints: 2^53+1 rounds to 2^53 (even), which is beyond the limit.
	if lit, ok := integerLiteral(json.Number("9007199254740993")); ok {
		t.Errorf("2^53+1 accepted as %s", lit)
	}
	if lit, ok := integerLiteral(json.Number("9007199254740991.4")); !ok || lit != "9007199254740991" {
		t.Errorf("9007199254740991.4 = %q %v", lit, ok)
	}
	if lit, ok := integerLiteral(json.Number("1.000000000000000111022302462515654042363166809082031250001")); ok {
		t.Errorf("value above 1 accepted as %s", lit)
	}
}
