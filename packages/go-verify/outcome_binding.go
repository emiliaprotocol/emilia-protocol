// SPDX-License-Identifier: Apache-2.0
// EP-OUTCOME-ATTESTATION-v1 + EP-OUTCOME-BINDING-v1.
//
// Faithful Go port of packages/verify/effect-predicates.js and
// packages/verify/outcome-binding.js. Decimal comparison is string-only,
// schemas and verdicts are closed, and relying-party policy is additive.
package emiliaverify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	OutcomeAttestationVersion = "EP-OUTCOME-ATTESTATION-v1"
	OutcomeAttestationDomain  = "EP-OUTCOME-ATTESTATION-v1\x00"
	OutcomeBindingVersion     = "EP-OUTCOME-BINDING-v1"
	MaxPredictedEffects       = 64
	MaxObservedEffects        = 256
	MaxEffectStringLength     = 512
)

var PredicateOps = []string{"eq", "lte", "gte", "range", "set_eq", "count_lte", "absent"}
var OutcomeBindingOutcomes = []string{"in_bounds", "divergent", "incomparable"}

var outcomeDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var outcomeNormalizedDigestPattern = regexp.MustCompile(`(?i)^sha256:[0-9a-f]{64}$`)
var outcomeKeyIDPattern = regexp.MustCompile(`^ep:executor-key:sha256:[0-9a-f]{64}$`)
var outcomeDecimalPattern = regexp.MustCompile(`^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?$`)
var outcomeCountPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
var outcomeInstantPattern = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$`)

var outcomeTopKeys = stringSet(
	"@version", "receipt_id", "receipt_digest", "action_hash", "consumption_nonce",
	"execution_id", "executor_id", "executed_at", "observed_effects",
	"observed_effects_digest", "proof",
)
var outcomeProofKeys = stringSet("algorithm", "key_id", "public_key", "signature_b64u")
var outcomeEntryKeys = stringSet("effect_type", "target", "predicate")
var outcomeObservedKeys = stringSet("effect_type", "target", "value", "values")
var outcomePredicateKeys = map[string]map[string]bool{
	"eq":        stringSet("op", "value"),
	"lte":       stringSet("op", "value"),
	"gte":       stringSet("op", "value"),
	"range":     stringSet("op", "min", "max"),
	"set_eq":    stringSet("op", "values"),
	"count_lte": stringSet("op", "value"),
	"absent":    stringSet("op"),
}

// OutcomePredicateValidation is the closed-schema validation result.
type OutcomePredicateValidation struct {
	OK      bool     `json:"ok"`
	Reasons []string `json:"reasons"`
}

// OutcomeEffectResult is one deterministic prediction evaluation.
type OutcomeEffectResult struct {
	EffectType string  `json:"effect_type"`
	Target     string  `json:"target"`
	Op         string  `json:"op"`
	Outcome    string  `json:"outcome"`
	Reason     *string `json:"reason"`
}

// OutcomeEvaluation is a semantic predicate evaluation, optionally identified
// by its signed-receipt or relying-party-policy source.
type OutcomeEvaluation struct {
	Source  string                `json:"source,omitempty"`
	Outcome string                `json:"outcome"`
	Results []OutcomeEffectResult `json:"results"`
	Reasons []string              `json:"reasons"`
}

// OutcomeBindingVerdict is the closed, typed composition verdict.
type OutcomeBindingVerdict struct {
	Version     string              `json:"@version"`
	Outcome     string              `json:"outcome"`
	Evaluations []OutcomeEvaluation `json:"evaluations"`
	Reasons     []string            `json:"reasons"`
}

// OutcomeAttestationResult mirrors the JS attestation verifier result.
type OutcomeAttestationResult struct {
	Valid  bool            `json:"valid"`
	Checks map[string]bool `json:"checks"`
	Errors []string        `json:"errors"`
}

// OutcomeBindingResult mirrors the JS full-composition result.
type OutcomeBindingResult struct {
	Valid             bool                      `json:"valid"`
	Checks            map[string]bool           `json:"checks"`
	Errors            []string                  `json:"errors"`
	ReceiptResult     *TrustReceiptResult       `json:"receipt_result,omitempty"`
	AttestationResult *OutcomeAttestationResult `json:"attestation_result,omitempty"`
	OutcomeBinding    OutcomeBindingVerdict     `json:"outcome_binding"`
	ResultDigest      string                    `json:"result_digest"`
}

type outcomeDecimal struct {
	negative bool
	integer  string
	fraction string
}

func stringSet(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func outcomeDigest(value any) string {
	sum := sha256.Sum256([]byte(Canonicalize(value)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func normalizeOutcomeDigest(value any) string {
	text, ok := value.(string)
	if !ok || !outcomeNormalizedDigestPattern.MatchString(text) {
		return ""
	}
	return strings.ToLower(text)
}

func outcomeTooLong(value any) bool {
	text, ok := value.(string)
	return ok && utf8.RuneCountInString(text) > MaxEffectStringLength
}

func outcomeIsNumber(value any) bool {
	switch value.(type) {
	case json.Number, float64, float32, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return true
	default:
		return false
	}
}

func splitOutcomeDecimal(value string) (outcomeDecimal, bool) {
	match := outcomeDecimalPattern.FindStringSubmatch(value)
	if match == nil {
		return outcomeDecimal{}, false
	}
	out := outcomeDecimal{
		negative: match[1] == "-",
		integer:  match[2],
		fraction: strings.TrimRight(match[3], "0"),
	}
	if out.integer == "0" && out.fraction == "" {
		out.negative = false
	}
	return out, true
}

// IsDecimalString reports whether value is an exact canonical decimal string.
func IsDecimalString(value string) bool {
	_, ok := splitOutcomeDecimal(value)
	return ok
}

// CompareDecimalStrings orders decimal strings without floats. The boolean is
// false when either input is not in the exact decimal profile.
func CompareDecimalStrings(left, right string) (int, bool) {
	a, aOK := splitOutcomeDecimal(left)
	b, bOK := splitOutcomeDecimal(right)
	if !aOK || !bOK {
		return 0, false
	}
	if a.negative != b.negative {
		if a.negative {
			return -1, true
		}
		return 1, true
	}
	magnitude := 0
	if len(a.integer) != len(b.integer) {
		if len(a.integer) < len(b.integer) {
			magnitude = -1
		} else {
			magnitude = 1
		}
	} else if a.integer != b.integer {
		if a.integer < b.integer {
			magnitude = -1
		} else {
			magnitude = 1
		}
	} else {
		width := len(a.fraction)
		if len(b.fraction) > width {
			width = len(b.fraction)
		}
		aFraction := a.fraction + strings.Repeat("0", width-len(a.fraction))
		bFraction := b.fraction + strings.Repeat("0", width-len(b.fraction))
		if aFraction < bFraction {
			magnitude = -1
		} else if aFraction > bFraction {
			magnitude = 1
		}
	}
	if a.negative {
		magnitude = -magnitude
	}
	return magnitude, true
}

// PredictedEffectsDigest digests the exact signed prediction array.
func PredictedEffectsDigest(predictedEffects any) string {
	return outcomeDigest(predictedEffects)
}

// ObservedEffectsDigest digests the exact executor observation array.
func ObservedEffectsDigest(observedEffects any) string {
	return outcomeDigest(observedEffects)
}

// TrustReceiptDigest digests the exact Trust Receipt referenced by an
// attestation.
func TrustReceiptDigest(receipt any) string {
	return outcomeDigest(receipt)
}

func outcomeAnySlice(value any) ([]any, bool) {
	items, ok := value.([]any)
	if ok {
		return items, true
	}
	maps, ok := value.([]map[string]any)
	if !ok {
		return nil, false
	}
	items = make([]any, len(maps))
	for i, item := range maps {
		items[i] = item
	}
	return items, true
}

func outcomeStringSlice(value any) ([]string, bool) {
	items, ok := outcomeAnySlice(value)
	if !ok {
		if stringsValue, stringsOK := value.([]string); stringsOK {
			return append([]string{}, stringsValue...), true
		}
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, isString := item.(string)
		if !isString {
			return nil, false
		}
		out = append(out, text)
	}
	return out, true
}

func sortedUnknownKeys(value map[string]any, allowed map[string]bool) []string {
	keys := []string{}
	for key := range value {
		if !allowed[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// ValidatePredictedEffects validates the exact, closed signed schema.
func ValidatePredictedEffects(predicted any) OutcomePredicateValidation {
	items, ok := outcomeAnySlice(predicted)
	if !ok || len(items) == 0 {
		return OutcomePredicateValidation{false, []string{"predicted_effects must be a non-empty array"}}
	}
	if len(items) > MaxPredictedEffects {
		return OutcomePredicateValidation{
			false,
			[]string{fmt.Sprintf("predicted_effects exceeds the %d-entry limit", MaxPredictedEffects)},
		}
	}
	reasons := []string{}
	for index, rawEntry := range items {
		at := fmt.Sprintf("predicted_effects[%d]", index)
		entry := getMap(rawEntry)
		if entry == nil {
			reasons = append(reasons, at+" is not an object")
			continue
		}
		if unknown := sortedUnknownKeys(entry, outcomeEntryKeys); len(unknown) > 0 {
			reasons = append(reasons, fmt.Sprintf(`%s has unknown member "%s"`, at, unknown[0]))
			continue
		}
		effectType, effectOK := entry["effect_type"].(string)
		if !effectOK || effectType == "" || outcomeTooLong(effectType) {
			reasons = append(reasons, fmt.Sprintf(
				"%s.effect_type must be a non-empty string of at most %d characters",
				at, MaxEffectStringLength,
			))
			continue
		}
		target, targetOK := entry["target"].(string)
		if !targetOK || target == "" || outcomeTooLong(target) {
			reasons = append(reasons, fmt.Sprintf(
				"%s.target must be a non-empty string of at most %d characters",
				at, MaxEffectStringLength,
			))
			continue
		}
		if strings.Contains(target, "*") {
			reasons = append(reasons, fmt.Sprintf(
				`%s.target contains "*"; EP-OUTCOME-BINDING-v1 targets are literal identifiers, not patterns`,
				at,
			))
			continue
		}
		predicate := getMap(entry["predicate"])
		if predicate == nil {
			reasons = append(reasons, at+".predicate is not an object")
			continue
		}
		op, opOK := predicate["op"].(string)
		if !opOK || !contains(PredicateOps, op) {
			rendered := "undefined"
			if _, present := predicate["op"]; present {
				rendered = fmt.Sprint(predicate["op"])
			}
			reasons = append(reasons, fmt.Sprintf(`%s.predicate.op "%s" is not a known op`, at, rendered))
			continue
		}
		if unknown := sortedUnknownKeys(predicate, outcomePredicateKeys[op]); len(unknown) > 0 {
			reasons = append(reasons, fmt.Sprintf(
				`%s.predicate (op %s) has unknown member "%s"`, at, op, unknown[0],
			))
			continue
		}
		switch op {
		case "eq":
			value := predicate["value"]
			if outcomeIsNumber(value) {
				reasons = append(reasons, at+".predicate.value is a number; comparison values MUST be strings (canonicalization malleability)")
			} else if text, ok := value.(string); !ok || outcomeTooLong(text) {
				reasons = append(reasons, at+".predicate.value must be a bounded string")
			}
		case "lte", "gte":
			value := predicate["value"]
			if outcomeIsNumber(value) {
				reasons = append(reasons, at+".predicate.value is a number; comparison values MUST be strings (canonicalization malleability)")
			} else if text, ok := value.(string); !ok || outcomeTooLong(text) || !IsDecimalString(text) {
				reasons = append(reasons, at+".predicate.value must be a bounded decimal string")
			}
		case "range":
			malformed := false
			for _, field := range []string{"min", "max"} {
				value := predicate[field]
				if outcomeIsNumber(value) {
					reasons = append(reasons, fmt.Sprintf(
						"%s.predicate.%s is a number; comparison values MUST be strings (canonicalization malleability)",
						at, field,
					))
					malformed = true
				} else if text, ok := value.(string); !ok || outcomeTooLong(text) || !IsDecimalString(text) {
					reasons = append(reasons, fmt.Sprintf(
						"%s.predicate.%s must be a bounded decimal string", at, field,
					))
					malformed = true
				}
			}
			if !malformed {
				cmp, _ := CompareDecimalStrings(getStr(predicate, "min"), getStr(predicate, "max"))
				if cmp == 1 {
					reasons = append(reasons, at+".predicate range has min > max")
				}
			}
		case "set_eq":
			values, stringsOK := outcomeStringSlice(predicate["values"])
			rawValues, arrayOK := outcomeAnySlice(predicate["values"])
			if stringValues, ok := predicate["values"].([]string); ok {
				arrayOK = true
				rawValues = make([]any, len(stringValues))
				for i, value := range stringValues {
					rawValues[i] = value
				}
			}
			if !arrayOK || len(rawValues) > MaxObservedEffects {
				reasons = append(reasons, at+".predicate.values must be a bounded array of strings")
				break
			}
			if !stringsOK {
				for _, value := range rawValues {
					if outcomeIsNumber(value) {
						reasons = append(reasons, at+".predicate.values contains a number; comparison values MUST be strings (canonicalization malleability)")
						break
					}
					if _, ok := value.(string); !ok {
						reasons = append(reasons, at+".predicate.values must contain only bounded strings")
						break
					}
				}
				break
			}
			for _, value := range values {
				if outcomeTooLong(value) {
					reasons = append(reasons, at+".predicate.values must contain only bounded strings")
					break
				}
			}
		case "count_lte":
			value := predicate["value"]
			if outcomeIsNumber(value) {
				reasons = append(reasons, at+".predicate.value is a number; comparison values MUST be strings (canonicalization malleability)")
			} else if text, ok := value.(string); !ok || outcomeTooLong(text) || !outcomeCountPattern.MatchString(text) {
				reasons = append(reasons, at+".predicate.value must be a bounded non-negative integer string")
			}
		}
	}
	return OutcomePredicateValidation{len(reasons) == 0, reasons}
}

func validateOutcomeObservedEffects(observed any) OutcomePredicateValidation {
	items, ok := outcomeAnySlice(observed)
	if !ok {
		return OutcomePredicateValidation{
			false,
			[]string{"observed_effects is missing or not an array (refusal, never a pass)"},
		}
	}
	if len(items) > MaxObservedEffects {
		return OutcomePredicateValidation{
			false,
			[]string{fmt.Sprintf("observed_effects exceeds the %d-entry limit", MaxObservedEffects)},
		}
	}
	reasons := []string{}
	for index, rawEntry := range items {
		at := fmt.Sprintf("observed_effects[%d]", index)
		entry := getMap(rawEntry)
		if entry == nil {
			reasons = append(reasons, at+" is not an object")
			continue
		}
		for _, member := range sortedUnknownKeys(entry, outcomeObservedKeys) {
			reasons = append(reasons, fmt.Sprintf(`%s has unknown member "%s"`, at, member))
		}
		effectType, effectOK := entry["effect_type"].(string)
		if !effectOK || effectType == "" || outcomeTooLong(effectType) {
			reasons = append(reasons, at+".effect_type must be a non-empty bounded string")
		}
		target, targetOK := entry["target"].(string)
		if !targetOK || target == "" || outcomeTooLong(target) || strings.Contains(target, "*") {
			reasons = append(reasons, at+".target must be a bounded literal identifier")
		}
		_, hasValue := entry["value"]
		_, hasValues := entry["values"]
		if hasValue == hasValues {
			reasons = append(reasons, at+" must carry exactly one of value or values")
		}
		if hasValue && outcomeIsNumber(entry["value"]) {
			reasons = append(reasons, at+".value is a number; observed values MUST be strings")
		} else if hasValue {
			if text, ok := entry["value"].(string); !ok || outcomeTooLong(text) {
				reasons = append(reasons, at+".value must be a bounded string")
			}
		}
		if hasValues {
			values, valuesOK := outcomeStringSlice(entry["values"])
			rawValues, arrayOK := outcomeAnySlice(entry["values"])
			if stringValues, ok := entry["values"].([]string); ok {
				arrayOK = true
				rawValues = make([]any, len(stringValues))
			}
			if !arrayOK || len(rawValues) > MaxObservedEffects {
				reasons = append(reasons, at+".values must be a bounded array")
			} else if !valuesOK {
				reasons = append(reasons, at+".values MUST be strings of bounded length")
			} else {
				for _, value := range values {
					if outcomeTooLong(value) {
						reasons = append(reasons, at+".values MUST be strings of bounded length")
						break
					}
				}
			}
		}
	}
	return OutcomePredicateValidation{len(reasons) == 0, reasons}
}

func outcomeReason(value string) *string {
	if value == "" {
		return nil
	}
	out := value
	return &out
}

func sortedUniqueOutcomeStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sortJCSKeys(out)
	return out
}

func evaluateOutcomeEntry(entry map[string]any, matches []map[string]any) (string, string) {
	predicate := getMap(entry["predicate"])
	op := getStr(predicate, "op")
	at := getStr(entry, "effect_type") + " on " + getStr(entry, "target")
	switch op {
	case "absent":
		if len(matches) == 0 {
			return "in_bounds", ""
		}
		return "divergent", fmt.Sprintf("predicted absent for %s, observed %d effect(s)", at, len(matches))
	case "count_lte":
		count := fmt.Sprintf("%d", len(matches))
		cmp, _ := CompareDecimalStrings(count, getStr(predicate, "value"))
		if cmp <= 0 {
			return "in_bounds", ""
		}
		return "divergent", fmt.Sprintf("predicted count <= %s for %s, observed %s", getStr(predicate, "value"), at, count)
	}
	if len(matches) == 0 {
		return "incomparable", "no observed effect for " + at
	}
	if len(matches) > 1 {
		return "incomparable", fmt.Sprintf("ambiguous: %d observed effects match %s", len(matches), at)
	}
	observed := matches[0]
	if op == "set_eq" {
		got, gotOK := outcomeStringSlice(observed["values"])
		if _, present := observed["values"]; !present || !gotOK {
			return "incomparable", "observed effect for " + at + " has no values array"
		}
		wanted, _ := outcomeStringSlice(predicate["values"])
		wanted = sortedUniqueOutcomeStrings(wanted)
		got = sortedUniqueOutcomeStrings(got)
		if Canonicalize(wanted) == Canonicalize(got) {
			return "in_bounds", ""
		}
		return "divergent", fmt.Sprintf(
			"predicted set_eq [%s] for %s, observed [%s]",
			strings.Join(wanted, ","), at, strings.Join(got, ","),
		)
	}
	value := observed["value"]
	if outcomeIsNumber(value) {
		return "incomparable", "observed value for " + at + " is a number; values MUST be strings (canonicalization malleability)"
	}
	text, textOK := value.(string)
	if !textOK {
		return "incomparable", "observed effect for " + at + " has no string value"
	}
	if op == "eq" {
		if text == getStr(predicate, "value") {
			return "in_bounds", ""
		}
		return "divergent", fmt.Sprintf(`predicted eq "%s" for %s, observed "%s"`, getStr(predicate, "value"), at, text)
	}
	if !IsDecimalString(text) {
		return "incomparable", fmt.Sprintf(`observed value "%s" for %s is not a decimal string`, text, at)
	}
	switch op {
	case "lte":
		cmp, _ := CompareDecimalStrings(text, getStr(predicate, "value"))
		if cmp <= 0 {
			return "in_bounds", ""
		}
		return "divergent", fmt.Sprintf("predicted <= %s for %s, observed %s", getStr(predicate, "value"), at, text)
	case "gte":
		cmp, _ := CompareDecimalStrings(text, getStr(predicate, "value"))
		if cmp >= 0 {
			return "in_bounds", ""
		}
		return "divergent", fmt.Sprintf("predicted >= %s for %s, observed %s", getStr(predicate, "value"), at, text)
	default:
		minCmp, _ := CompareDecimalStrings(text, getStr(predicate, "min"))
		if minCmp < 0 {
			return "divergent", fmt.Sprintf(
				"predicted range [%s, %s] for %s, observed %s (below min)",
				getStr(predicate, "min"), getStr(predicate, "max"), at, text,
			)
		}
		maxCmp, _ := CompareDecimalStrings(text, getStr(predicate, "max"))
		if maxCmp > 0 {
			return "divergent", fmt.Sprintf(
				"predicted range [%s, %s] for %s, observed %s (above max)",
				getStr(predicate, "min"), getStr(predicate, "max"), at, text,
			)
		}
		return "in_bounds", ""
	}
}

// EvaluatePredictedEffects deterministically evaluates signed predictions
// against executor-attested observations.
func EvaluatePredictedEffects(predicted, observed any) OutcomeEvaluation {
	structural := ValidatePredictedEffects(predicted)
	if !structural.OK {
		reasons := make([]string, len(structural.Reasons))
		for i, reason := range structural.Reasons {
			reasons[i] = "malformed predicted_effects: " + reason
		}
		return OutcomeEvaluation{Outcome: "incomparable", Results: []OutcomeEffectResult{}, Reasons: reasons}
	}
	observedStructural := validateOutcomeObservedEffects(observed)
	if !observedStructural.OK {
		reasons := make([]string, len(observedStructural.Reasons))
		for i, reason := range observedStructural.Reasons {
			reasons[i] = "malformed observed_effects: " + reason
		}
		return OutcomeEvaluation{Outcome: "incomparable", Results: []OutcomeEffectResult{}, Reasons: reasons}
	}
	predictedItems, _ := outcomeAnySlice(predicted)
	observedItems, _ := outcomeAnySlice(observed)
	results := make([]OutcomeEffectResult, 0, len(predictedItems))
	reasons := []string{}
	for _, rawEntry := range predictedItems {
		entry := getMap(rawEntry)
		matches := []map[string]any{}
		for _, rawObserved := range observedItems {
			item := getMap(rawObserved)
			if item != nil &&
				getStr(item, "effect_type") == getStr(entry, "effect_type") &&
				getStr(item, "target") == getStr(entry, "target") {
				matches = append(matches, item)
			}
		}
		outcome, reason := evaluateOutcomeEntry(entry, matches)
		results = append(results, OutcomeEffectResult{
			EffectType: getStr(entry, "effect_type"),
			Target:     getStr(entry, "target"),
			Op:         getStr(getMap(entry["predicate"]), "op"),
			Outcome:    outcome,
			Reason:     outcomeReason(reason),
		})
		if reason != "" {
			reasons = append(reasons, reason)
		}
	}
	outcome := "in_bounds"
	for _, result := range results {
		if result.Outcome == "divergent" {
			outcome = "divergent"
			break
		}
		if result.Outcome == "incomparable" {
			outcome = "incomparable"
		}
	}
	return OutcomeEvaluation{Outcome: outcome, Results: results, Reasons: reasons}
}

func exactOutcomeKeys(value map[string]any, allowed map[string]bool) bool {
	if value == nil {
		return false
	}
	for key := range value {
		if !allowed[key] {
			return false
		}
	}
	return true
}

func strictOutcomeInstant(value any) (time.Time, bool) {
	text, ok := value.(string)
	if !ok || !outcomeInstantPattern.MatchString(text) {
		return time.Time{}, false
	}
	match := outcomeInstantPattern.FindStringSubmatch(text)
	if match[9] != "" && (match[9] > "23" || match[10] > "59") {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	return parsed, err == nil
}

func executorOutcomeKeyID(publicKey string) string {
	der, err := base64.RawURLEncoding.Strict().DecodeString(publicKey)
	if err != nil || base64.RawURLEncoding.EncodeToString(der) != publicKey {
		return ""
	}
	sum := sha256.Sum256(der)
	return "ep:executor-key:sha256:" + hex.EncodeToString(sum[:])
}

func validateAttestedObservedEffects(observed any) (bool, []string) {
	items, ok := outcomeAnySlice(observed)
	if !ok {
		return false, []string{"observed_effects must be an array"}
	}
	if len(items) > MaxObservedEffects {
		return false, []string{fmt.Sprintf("observed_effects exceeds the %d-entry limit", MaxObservedEffects)}
	}
	errors := []string{}
	for index, rawEntry := range items {
		at := fmt.Sprintf("observed_effects[%d]", index)
		entry := getMap(rawEntry)
		if !exactOutcomeKeys(entry, outcomeObservedKeys) {
			errors = append(errors, at+" is not an exact observed-effect object")
			continue
		}
		effectType, effectOK := entry["effect_type"].(string)
		if !effectOK || effectType == "" || outcomeTooLong(effectType) {
			errors = append(errors, at+".effect_type is invalid")
		}
		target, targetOK := entry["target"].(string)
		if !targetOK || target == "" || outcomeTooLong(target) || strings.Contains(target, "*") {
			errors = append(errors, at+".target must be a bounded literal identifier")
		}
		_, hasValue := entry["value"]
		_, hasValues := entry["values"]
		if hasValue == hasValues {
			errors = append(errors, at+" must carry exactly one of value or values")
		}
		if hasValue {
			if text, ok := entry["value"].(string); !ok || outcomeTooLong(text) {
				errors = append(errors, at+".value must be a bounded string")
			}
		}
		if hasValues {
			values, stringsOK := outcomeStringSlice(entry["values"])
			rawValues, arrayOK := outcomeAnySlice(entry["values"])
			if stringValues, ok := entry["values"].([]string); ok {
				arrayOK = true
				rawValues = make([]any, len(stringValues))
			}
			bounded := arrayOK && len(rawValues) <= MaxObservedEffects && stringsOK
			if bounded {
				for _, value := range values {
					if outcomeTooLong(value) {
						bounded = false
						break
					}
				}
			}
			if !bounded {
				errors = append(errors, at+".values must be a bounded array of bounded strings")
			}
		}
	}
	return len(errors) == 0, errors
}

// VerifyOutcomeAttestation verifies an executor observation under a
// relying-party-pinned executor key. opts uses JS-compatible executorKeys and
// now keys.
func VerifyOutcomeAttestation(attestation map[string]any, opts map[string]any) OutcomeAttestationResult {
	checks := map[string]bool{
		"structure":           false,
		"observation_digest":  false,
		"executor_key_pinned": false,
		"signature":           false,
		"execution_time":      false,
	}
	errors := []string{}
	result := func() OutcomeAttestationResult {
		return OutcomeAttestationResult{Valid: allTrue(checks), Checks: checks, Errors: errors}
	}
	proof := getMap(attestation["proof"])
	if !exactOutcomeKeys(attestation, outcomeTopKeys) ||
		getStr(attestation, "@version") != OutcomeAttestationVersion ||
		getStr(attestation, "receipt_id") == "" ||
		normalizeOutcomeDigest(attestation["receipt_digest"]) == "" ||
		normalizeOutcomeDigest(attestation["action_hash"]) == "" ||
		getStr(attestation, "consumption_nonce") == "" ||
		getStr(attestation, "execution_id") == "" ||
		getStr(attestation, "executor_id") == "" ||
		!outcomeDigestPattern.MatchString(getStr(attestation, "observed_effects_digest")) ||
		!exactOutcomeKeys(proof, outcomeProofKeys) ||
		getStr(proof, "algorithm") != "Ed25519" ||
		!outcomeKeyIDPattern.MatchString(getStr(proof, "key_id")) ||
		func() bool { _, ok := proof["public_key"].(string); return !ok }() ||
		func() bool { _, ok := proof["signature_b64u"].(string); return !ok }() {
		errors = append(errors, "malformed_outcome_attestation")
		return result()
	}
	observedOK, observedErrors := validateAttestedObservedEffects(attestation["observed_effects"])
	if !observedOK {
		errors = append(errors, observedErrors...)
		return result()
	}
	checks["structure"] = true
	checks["observation_digest"] =
		ObservedEffectsDigest(attestation["observed_effects"]) == getStr(attestation, "observed_effects_digest")
	if !checks["observation_digest"] {
		errors = append(errors, "observed_effects_digest_mismatch")
	}

	executorKeys := getMap(opts["executorKeys"])
	pin := getMap(executorKeys[getStr(attestation, "executor_id")])
	derivedKeyID := executorOutcomeKeyID(getStr(proof, "public_key"))
	pinKeyID, pinHasKeyID := pin["key_id"]
	checks["executor_key_pinned"] =
		derivedKeyID == getStr(proof, "key_id") &&
			getStr(pin, "public_key") == getStr(proof, "public_key") &&
			(!pinHasKeyID || pinKeyID == derivedKeyID)
	if !checks["executor_key_pinned"] {
		errors = append(errors, "executor_key_not_pinned")
	}
	if checks["executor_key_pinned"] {
		unsigned := map[string]any{}
		for key, value := range attestation {
			if key != "proof" {
				unsigned[key] = value
			}
		}
		signingBytes := []byte(OutcomeAttestationDomain + Canonicalize(unsigned))
		checks["signature"] = ed25519VerifyBytes(
			signingBytes, getStr(pin, "public_key"), getStr(proof, "signature_b64u"),
		)
	}
	if !checks["signature"] {
		errors = append(errors, "executor_signature_invalid")
	}
	executedAt, executedOK := strictOutcomeInstant(attestation["executed_at"])
	now := time.Now()
	nowOK := true
	if rawNow, present := opts["now"]; present {
		now, nowOK = strictOutcomeInstant(rawNow)
	}
	checks["execution_time"] = executedOK && nowOK && !executedAt.After(now)
	if !checks["execution_time"] {
		errors = append(errors, "execution_time_invalid_or_future")
	}
	return result()
}

func combineOutcomeEvaluations(signed OutcomeEvaluation, policy *OutcomeEvaluation) OutcomeBindingVerdict {
	signed.Source = "signed_receipt"
	evaluations := []OutcomeEvaluation{signed}
	if policy != nil {
		policy.Source = "relying_party_policy"
		evaluations = append(evaluations, *policy)
	}
	outcome := "in_bounds"
	for _, evaluation := range evaluations {
		if evaluation.Outcome == "divergent" {
			outcome = "divergent"
			break
		}
		if evaluation.Outcome == "incomparable" {
			outcome = "incomparable"
		}
	}
	reasons := []string{}
	for _, evaluation := range evaluations {
		for _, reason := range evaluation.Reasons {
			reasons = append(reasons, evaluation.Source+": "+reason)
		}
	}
	return OutcomeBindingVerdict{
		Version: OutcomeBindingVersion, Outcome: outcome,
		Evaluations: evaluations, Reasons: reasons,
	}
}

func outcomeEffectMap(result OutcomeEffectResult) map[string]any {
	var reason any
	if result.Reason != nil {
		reason = *result.Reason
	}
	return map[string]any{
		"effect_type": result.EffectType,
		"target":      result.Target,
		"op":          result.Op,
		"outcome":     result.Outcome,
		"reason":      reason,
	}
}

func outcomeEvaluationMap(evaluation OutcomeEvaluation) map[string]any {
	results := make([]any, len(evaluation.Results))
	for i, result := range evaluation.Results {
		results[i] = outcomeEffectMap(result)
	}
	reasons := make([]any, len(evaluation.Reasons))
	for i, reason := range evaluation.Reasons {
		reasons[i] = reason
	}
	out := map[string]any{
		"outcome": evaluation.Outcome,
		"results": results,
		"reasons": reasons,
	}
	if evaluation.Source != "" {
		out["source"] = evaluation.Source
	}
	return out
}

func outcomeVerdictMap(verdict OutcomeBindingVerdict) map[string]any {
	evaluations := make([]any, len(verdict.Evaluations))
	for i, evaluation := range verdict.Evaluations {
		evaluations[i] = outcomeEvaluationMap(evaluation)
	}
	reasons := make([]any, len(verdict.Reasons))
	for i, reason := range verdict.Reasons {
		reasons[i] = reason
	}
	return map[string]any{
		"@version":    verdict.Version,
		"outcome":     verdict.Outcome,
		"evaluations": evaluations,
		"reasons":     reasons,
	}
}

func outcomeChecksMap(checks map[string]bool) map[string]any {
	out := make(map[string]any, len(checks))
	for key, value := range checks {
		out[key] = value
	}
	return out
}

func outcomeErrorsArray(errors []string) []any {
	out := make([]any, len(errors))
	for i, value := range errors {
		out[i] = value
	}
	return out
}

func outcomeInputCommitments(
	receipt map[string]any,
	attestation map[string]any,
	opts map[string]any,
) map[string]any {
	policy, policyPresent := opts["policyPredictedEffects"]
	var policyDigest any
	if policyPresent {
		policyDigest = outcomeDigest(policy)
	}
	return map[string]any{
		"receipt_digest":             outcomeDigest(receipt),
		"attestation_digest":         outcomeDigest(attestation),
		"policy_predictions_present": policyPresent,
		"policy_predictions_digest":  policyDigest,
	}
}

func outcomeExactCommitments(
	receipt map[string]any,
	attestation map[string]any,
) map[string]any {
	var receiptID, attestedReceiptID, consumptionNonce, attestedConsumptionNonce any
	var executionID, executorID, executorKeyID any
	if value, ok := receipt["receipt_id"].(string); ok {
		receiptID = value
	}
	if value, ok := attestation["receipt_id"].(string); ok {
		attestedReceiptID = value
	}
	if consumption := getMap(receipt["consumption"]); consumption != nil {
		if value, ok := consumption["nonce"].(string); ok {
			consumptionNonce = value
		}
	}
	if value, ok := attestation["consumption_nonce"].(string); ok {
		attestedConsumptionNonce = value
	}
	if value, ok := attestation["execution_id"].(string); ok {
		executionID = value
	}
	if value, ok := attestation["executor_id"].(string); ok {
		executorID = value
	}
	if proof := getMap(attestation["proof"]); proof != nil {
		if value, ok := proof["key_id"].(string); ok {
			executorKeyID = value
		}
	}
	return map[string]any{
		"receipt_id":                 receiptID,
		"attested_receipt_id":        attestedReceiptID,
		"receipt_digest":             outcomeDigest(receipt),
		"attested_receipt_digest":    normalizeOutcomeDigest(attestation["receipt_digest"]),
		"action_hash":                normalizeOutcomeDigest(receipt["action_hash"]),
		"attested_action_hash":       normalizeOutcomeDigest(attestation["action_hash"]),
		"consumption_nonce":          consumptionNonce,
		"attested_consumption_nonce": attestedConsumptionNonce,
		"execution_id":               executionID,
		"executor_id":                executorID,
		"executor_key_id":            executorKeyID,
		"observed_effects_digest":    normalizeOutcomeDigest(attestation["observed_effects_digest"]),
	}
}

func outcomeRefusal(
	receipt map[string]any,
	attestation map[string]any,
	opts map[string]any,
	checks map[string]bool,
	errors []string,
	reason string,
) OutcomeBindingResult {
	errors = append(errors, reason)
	verdict := OutcomeBindingVerdict{
		Version: OutcomeBindingVersion, Outcome: "incomparable",
		Evaluations: []OutcomeEvaluation{}, Reasons: append([]string{}, errors...),
	}
	digestInput := map[string]any{
		"input_commitments": outcomeInputCommitments(receipt, attestation, opts),
		"exact_commitments": outcomeExactCommitments(receipt, attestation),
		"valid":             false,
		"verdict":           verdict.Outcome,
		"checks":            outcomeChecksMap(checks),
		"errors":            outcomeErrorsArray(errors),
		"outcome_binding":   outcomeVerdictMap(verdict),
	}
	return OutcomeBindingResult{
		Valid: false, Checks: checks, Errors: errors,
		OutcomeBinding: verdict, ResultDigest: outcomeDigest(digestInput),
	}
}

// VerifyOutcomeBinding composes full Trust Receipt verification, the signed
// prediction commitment, executor-key verification, exact receipt/action/nonce
// bindings, and optional tightening policy. opts uses the JS-compatible keys
// receiptOptions, executorKeys, policyPredictedEffects, and now.
func VerifyOutcomeBinding(
	receipt map[string]any,
	attestation map[string]any,
	opts map[string]any,
) OutcomeBindingResult {
	if opts == nil {
		opts = map[string]any{}
	}
	checks := map[string]bool{
		"receipt_verified":     false,
		"signed_predictions":   false,
		"receipt_bound":        false,
		"receipt_digest_bound": false,
		"action_bound":         false,
		"consumption_bound":    false,
		"attestation_verified": false,
	}
	errors := []string{}
	receiptOptions := getMap(opts["receiptOptions"])
	receiptResult := VerifyTrustReceipt(receipt, receiptOptions)
	checks["receipt_verified"] = receiptResult.Valid
	if !checks["receipt_verified"] {
		return outcomeRefusal(
			receipt, attestation, opts, checks, errors, "receipt_verification_failed",
		)
	}
	action := getMap(receipt["action"])
	signedPredictions := action["predicted_effects"]
	boundPredictionDigest := action["predicted_effects_digest"]
	predictionValidation := ValidatePredictedEffects(signedPredictions)
	checks["signed_predictions"] = predictionValidation.OK &&
		normalizeOutcomeDigest(boundPredictionDigest) ==
			normalizeOutcomeDigest(PredictedEffectsDigest(signedPredictions))
	if !checks["signed_predictions"] {
		return outcomeRefusal(
			receipt, attestation, opts, checks, errors, "signed_predictions_missing_or_mismatched",
		)
	}
	policy, policyPresent := opts["policyPredictedEffects"]
	if policyPresent {
		if _, policyArray := outcomeAnySlice(policy); !policyArray {
			return outcomeRefusal(
				receipt, attestation, opts, checks, errors, "policy_predictions_present_but_not_array",
			)
		}
		validation := ValidatePredictedEffects(policy)
		if !validation.OK {
			for _, reason := range validation.Reasons {
				errors = append(errors, "relying_party_policy: "+reason)
			}
			return outcomeRefusal(
				receipt, attestation, opts, checks, errors, "policy_predictions_malformed",
			)
		}
	}
	attestationOpts := map[string]any{"executorKeys": opts["executorKeys"]}
	if now, present := opts["now"]; present {
		attestationOpts["now"] = now
	}
	attestationResult := VerifyOutcomeAttestation(attestation, attestationOpts)
	checks["attestation_verified"] = attestationResult.Valid
	if !checks["attestation_verified"] {
		errors = append(errors, attestationResult.Errors...)
		return outcomeRefusal(
			receipt, attestation, opts, checks, errors, "outcome_attestation_verification_failed",
		)
	}
	checks["receipt_bound"] = getStr(attestation, "receipt_id") == getStr(receipt, "receipt_id")
	checks["receipt_digest_bound"] =
		normalizeOutcomeDigest(attestation["receipt_digest"]) ==
			normalizeOutcomeDigest(TrustReceiptDigest(receipt))
	checks["action_bound"] =
		normalizeOutcomeDigest(attestation["action_hash"]) ==
			normalizeOutcomeDigest(receipt["action_hash"])
	consumption := getMap(receipt["consumption"])
	nonce, nonceOK := consumption["nonce"].(string)
	checks["consumption_bound"] = nonceOK && getStr(attestation, "consumption_nonce") == nonce
	if !checks["receipt_bound"] {
		errors = append(errors, "receipt_id_mismatch")
	}
	if !checks["receipt_digest_bound"] {
		errors = append(errors, "receipt_digest_mismatch")
	}
	if !checks["action_bound"] {
		errors = append(errors, "action_hash_mismatch")
	}
	if !checks["consumption_bound"] {
		errors = append(errors, "consumption_nonce_mismatch")
	}
	if !checks["receipt_bound"] || !checks["receipt_digest_bound"] ||
		!checks["action_bound"] || !checks["consumption_bound"] {
		return outcomeRefusal(
			receipt, attestation, opts, checks, errors, "attestation_not_bound_to_verified_receipt",
		)
	}
	signedEvaluation := EvaluatePredictedEffects(signedPredictions, attestation["observed_effects"])
	var policyEvaluation *OutcomeEvaluation
	if policyPresent {
		evaluated := EvaluatePredictedEffects(policy, attestation["observed_effects"])
		policyEvaluation = &evaluated
	}
	verdict := combineOutcomeEvaluations(signedEvaluation, policyEvaluation)
	resultErrors := append(append([]string{}, errors...), verdict.Reasons...)
	valid := allTrue(checks) && verdict.Outcome == "in_bounds"
	inputCommitments := outcomeInputCommitments(receipt, attestation, opts)
	inputCommitments["signed_predictions_digest"] = PredictedEffectsDigest(signedPredictions)
	digestInput := map[string]any{
		"input_commitments": inputCommitments,
		"exact_commitments": outcomeExactCommitments(receipt, attestation),
		"valid":             valid,
		"verdict":           verdict.Outcome,
		"checks":            outcomeChecksMap(checks),
		"errors":            outcomeErrorsArray(resultErrors),
		"outcome_binding":   outcomeVerdictMap(verdict),
	}
	return OutcomeBindingResult{
		Valid: valid, Checks: checks, Errors: resultErrors,
		ReceiptResult: &receiptResult, AttestationResult: &attestationResult,
		OutcomeBinding: verdict, ResultDigest: outcomeDigest(digestInput),
	}
}
