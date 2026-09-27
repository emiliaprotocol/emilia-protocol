// SPDX-License-Identifier: Apache-2.0

// json.go - strict JSON text input (draft -04 Section 2.4).
//
// Received JSON text reaches this package only through these decoders.
// encoding/json is not a conforming front end: it replaces an unpaired
// surrogate escape with U+FFFD, keeps the last of duplicate member names,
// accepts a byte order mark in some paths, and has no nesting bound suited to
// CAID, so it silently changes the content being identified. Nothing in this
// package or its runners decodes through it.
package caid

import (
	"caid/internal/jsontext"
)

// ReasonMalformedJSON is the single reason every JSON text refusal carries.
const ReasonMalformedJSON = "malformed_json"

// DecodeError is the error every decoder in this package returns. Whatever
// rule the text broke, its reason is malformed_json; Offset and Detail are
// informative only and are never part of a result that is compared.
type DecodeError struct {
	// Offset is the byte offset where decoding stopped, or -1 for a check
	// made before parsing (size, UTF-8 validity).
	Offset int
	// Detail says which rule the text broke.
	Detail string
}

func (e *DecodeError) Error() string {
	return "caid: " + ReasonMalformedJSON + ": " + (&jsontext.Error{Offset: e.Offset, Msg: e.Detail}).Error()
}

// Reason returns malformed_json.
func (e *DecodeError) Reason() string { return ReasonMalformedJSON }

// DecodeResult is the outcome of DecodeCaidJSON: {ok, value} or {ok, refusals}.
type DecodeResult struct {
	OK       bool        `json:"ok"`
	Value    interface{} `json:"value,omitempty"`
	Refusals []string    `json:"refusals,omitempty"`
}

func decode(data []byte, maxOctets int) (interface{}, error) {
	value, err := jsontext.Decode(data, jsontext.Options{MaxOctets: maxOctets, MaxDepth: specLimitNestingDepth})
	if err != nil {
		return nil, &DecodeError{Offset: err.Offset, Detail: err.Msg}
	}
	return value, nil
}

// DecodeJSON decodes an action object or a mapping source received as JSON
// text, under every rule of draft -04 Section 2.4. The text MUST be an I-JSON
// message [RFC7493] and in particular:
//
//   - at most 33554432 octets (checked before parsing);
//   - valid UTF-8 [RFC3629] that does not begin with a byte order mark;
//   - exactly one JSON text [RFC8259], with only the four JSON whitespace
//     octets around it and no unescaped control character in a string;
//   - no object with two members whose names are the same code points after
//     unescaping;
//   - no escape that denotes an unpaired surrogate, and no noncharacter,
//     escaped or literal, in a string or member name;
//   - nesting at most 64, the outermost object or array being depth 1.
//
// Any other text is refused with a *DecodeError (reason malformed_json). A
// number token is never refused here: it decodes to a json.Number holding
// the exact token, and the data model decides whether its value is accepted.
//
// Values decode to map[string]interface{}, []interface{}, json.Number,
// string, bool and nil, the value model ComputeCaid, VerifyCaid and MapAction
// take.
func DecodeJSON(data []byte) (interface{}, error) {
	return decode(data, specLimitJsonTextOctets)
}

// DecodeDocumentJSON decodes a registry, type definition, enum snapshot,
// mapping profile or conformance corpus. It applies every rule of DecodeJSON
// except the size limit, which draft -04 applies only to action objects and
// mapping sources: a value set that grows must never fall off a cliff.
func DecodeDocumentJSON(data []byte) (interface{}, error) {
	return decode(data, 0)
}

// DecodeCaidJSON is DecodeJSON in result form: {OK: true, Value} or
// {OK: false, Refusals: ["malformed_json"]}. It never panics.
func DecodeCaidJSON(data []byte) DecodeResult {
	value, err := DecodeJSON(data)
	if err != nil {
		return DecodeResult{OK: false, Refusals: []string{ReasonMalformedJSON}}
	}
	return DecodeResult{OK: true, Value: value}
}
