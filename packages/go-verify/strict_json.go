// SPDX-License-Identifier: Apache-2.0
package emiliaverify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

const maxStrictJSONDepth = 64

func decodeStrictJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeStrictJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err = decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing JSON value")
		}
		return nil, err
	}
	return value, nil
}

func decodeStrictJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxStrictJSONDepth {
		return nil, fmt.Errorf("JSON nesting exceeds %d", maxStrictJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return token, nil
	}
	switch delim {
	case '{':
		result := map[string]any{}
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return nil, keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("object member name is not a string")
			}
			if _, duplicate := result[key]; duplicate {
				return nil, fmt.Errorf("duplicate object member name %q", key)
			}
			value, valueErr := decodeStrictJSONValue(decoder, depth+1)
			if valueErr != nil {
				return nil, valueErr
			}
			result[key] = value
		}
		if closeToken, closeErr := decoder.Token(); closeErr != nil || closeToken != json.Delim('}') {
			return nil, fmt.Errorf("unterminated JSON object")
		}
		return result, nil
	case '[':
		result := []any{}
		for decoder.More() {
			value, valueErr := decodeStrictJSONValue(decoder, depth+1)
			if valueErr != nil {
				return nil, valueErr
			}
			result = append(result, value)
		}
		if closeToken, closeErr := decoder.Token(); closeErr != nil || closeToken != json.Delim(']') {
			return nil, fmt.Errorf("unterminated JSON array")
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}

func decodeStrictJSONObject(data []byte) (map[string]any, error) {
	value, err := decodeStrictJSON(data)
	if err != nil {
		return nil, err
	}
	result, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("JSON value is not an object")
	}
	return result, nil
}

func stringSliceOption(options map[string]any, key string) ([]string, bool) {
	raw, present := options[key]
	if !present {
		return nil, false
	}
	switch values := raw.(type) {
	case []string:
		for _, value := range values {
			if value == "" {
				return nil, true
			}
		}
		return values, true
	case []any:
		result := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok || text == "" {
				return nil, true
			}
			result = append(result, text)
		}
		return result, true
	default:
		return nil, true
	}
}
