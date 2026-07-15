// SPDX-License-Identifier: Apache-2.0
// CAID Action-Mapping Profile v1.
//
// A mapping result is a content-correlation result, not authorization.
// The caller pins the exact profile hash and source descriptor. Missing
// material fields, unknown transforms, and unpinned profiles abstain.
package caid

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const MappingProfileVersion = "CAID-MAPPING-PROFILE-v1"

const (
	EquivalentUnderProfile = "EQUIVALENT_UNDER_PROFILE"
	NotEquivalent          = "NOT_EQUIVALENT"
	Indeterminate          = "INDETERMINATE"
)

var mappingFieldRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
var pointerIndexRe = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

var mappingTransforms = map[string]bool{
	"copy":        true,
	"sha256-utf8": true,
	"sha256-jcs":  true,
}

var mappingProfileKeys = map[string]bool{
	"@version": true, "profile_id": true, "source_format": true,
	"target_action_type": true, "loss_policy": true,
	"material_source_paths": true, "rules": true,
}
var mappingSourceFormatKeys = map[string]bool{
	"media_type": true, "schema": true, "version": true,
}
var mappingRuleKeys = map[string]bool{
	"source_path": true, "target_field": true, "transform": true,
}

const maxMappingRules = 128
const maxPointerBytes = 2048

type MapActionResult struct {
	OK           bool                   `json:"ok"`
	Reasons      []string               `json:"reasons,omitempty"`
	Action       map[string]interface{} `json:"action,omitempty"`
	Caid         string                 `json:"caid,omitempty"`
	Digest       string                 `json:"digest,omitempty"`
	Suite        string                 `json:"suite,omitempty"`
	ProfileHash  string                 `json:"profile_hash,omitempty"`
	SourceDigest string                 `json:"source_digest,omitempty"`
}

type MappingComparison struct {
	Verdict string          `json:"verdict"`
	Reasons []string        `json:"reasons"`
	Left    MapActionResult `json:"left"`
	Right   MapActionResult `json:"right"`
}

type MapActionOptions struct {
	Profile             map[string]interface{}
	SourceDescriptor    map[string]interface{}
	ExpectedProfileHash string
	NativeVerified      bool
	Definitions         []interface{}
	Suite               string
}

func hashJSON(value interface{}) string {
	canonical := Canonicalize(value)
	if !canonical.OK {
		return ""
	}
	sum := sha256.Sum256([]byte(canonical.Canonical))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func mappingString(value interface{}, max int) bool {
	text, ok := value.(string)
	return ok && len(text) > 0 && len(text) <= max
}

func mappingHasOnlyKeys(value map[string]interface{}, allowed map[string]bool) bool {
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

func validPointer(pointer string) bool {
	if len(pointer) == 0 || len([]byte(pointer)) > maxPointerBytes || pointer[0] != '/' {
		return false
	}
	for _, segment := range strings.Split(pointer[1:], "/") {
		for index := 0; index < len(segment); index++ {
			if segment[index] == '~' {
				if index+1 >= len(segment) || (segment[index+1] != '0' && segment[index+1] != '1') {
					return false
				}
				index++
			}
		}
	}
	return true
}

func pointerSegments(pointer string) ([]string, bool) {
	if !validPointer(pointer) {
		return nil, false
	}
	raw := strings.Split(pointer[1:], "/")
	out := make([]string, 0, len(raw))
	for _, segment := range raw {
		out = append(out, strings.ReplaceAll(strings.ReplaceAll(segment, "~1", "/"), "~0", "~"))
	}
	return out, true
}

func valueAtPointer(value interface{}, pointer string) (interface{}, bool, string) {
	segments, ok := pointerSegments(pointer)
	if !ok {
		return nil, false, "invalid_source_path"
	}
	current := value
	for _, segment := range segments {
		switch typed := current.(type) {
		case map[string]interface{}:
			next, present := typed[segment]
			if !present {
				return nil, false, "missing_source_field"
			}
			current = next
		case []interface{}:
			if !pointerIndexRe.MatchString(segment) {
				return nil, false, "invalid_source_path"
			}
			index, err := strconv.Atoi(segment)
			if err != nil || index >= len(typed) {
				return nil, false, "missing_source_field"
			}
			current = typed[index]
		default:
			return nil, false, "missing_source_field"
		}
	}
	return current, true, ""
}

func mappingDescriptorEqual(left, right interface{}) bool {
	a := Canonicalize(left)
	b := Canonicalize(right)
	return a.OK && b.OK && a.Canonical == b.Canonical
}

func mappingDefinition(actionType string, definitions []interface{}) map[string]interface{} {
	return resolveDefinition(actionType, definitions)
}

func mappingStringSlice(value interface{}) ([]string, bool) {
	raw, ok := value.([]interface{})
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		text, isString := item.(string)
		if !isString {
			return nil, false
		}
		out = append(out, text)
	}
	return out, true
}

func validateMappingProfile(profile map[string]interface{}, definitions []interface{}) []string {
	if profile == nil || profile["@version"] != MappingProfileVersion ||
		!mappingHasOnlyKeys(profile, mappingProfileKeys) {
		return []string{"invalid_mapping_profile"}
	}
	sourceFormat, sourceOK := profile["source_format"].(map[string]interface{})
	rules, rulesOK := profile["rules"].([]interface{})
	material, materialOK := mappingStringSlice(profile["material_source_paths"])
	actionType, typeOK := profile["target_action_type"].(string)
	if !mappingString(profile["profile_id"], 512) || !sourceOK ||
		!mappingHasOnlyKeys(sourceFormat, mappingSourceFormatKeys) ||
		!mappingString(sourceFormat["media_type"], 512) ||
		!mappingString(sourceFormat["schema"], 512) ||
		!mappingString(sourceFormat["version"], 512) ||
		!typeOK || actionType == "" ||
		profile["loss_policy"] != "no-material-field-loss" ||
		!rulesOK || len(rules) == 0 || len(rules) > maxMappingRules ||
		!materialOK || len(material) == 0 {
		return []string{"invalid_mapping_profile"}
	}

	reasons := []string{}
	targets := map[string]bool{}
	ruleSources := map[string]bool{}
	for _, raw := range rules {
		rule, ok := raw.(map[string]interface{})
		if !ok || !mappingHasOnlyKeys(rule, mappingRuleKeys) {
			reasons = append(reasons, "invalid_mapping_profile")
			break
		}
		sourcePath, sourceOK := rule["source_path"].(string)
		targetField, targetOK := rule["target_field"].(string)
		transform, transformOK := rule["transform"].(string)
		if !sourceOK || !validPointer(sourcePath) ||
			!targetOK || !mappingFieldRe.MatchString(targetField) ||
			targetField == "action_type" || targets[targetField] ||
			!transformOK || !mappingTransforms[transform] {
			reasons = append(reasons, "invalid_mapping_profile")
			break
		}
		targets[targetField] = true
		ruleSources[sourcePath] = true
	}

	materialSeen := map[string]bool{}
	for _, sourcePath := range material {
		if !validPointer(sourcePath) || materialSeen[sourcePath] {
			reasons = append(reasons, "invalid_mapping_profile")
			break
		}
		materialSeen[sourcePath] = true
	}
	if len(ruleSources) != len(materialSeen) {
		reasons = append(reasons, "invalid_mapping_profile")
	} else {
		for path := range ruleSources {
			if !materialSeen[path] {
				reasons = append(reasons, "invalid_mapping_profile")
				break
			}
		}
	}

	definition := mappingDefinition(actionType, definitions)
	if definition == nil {
		reasons = append(reasons, "unknown_action_type")
	} else {
		required := fieldList(definition, "required_fields")
		for _, field := range required {
			name, ok := field["name"].(string)
			if !ok || !mappingFieldRe.MatchString(name) || !targets[name] {
				if !ok {
					name = "?"
				}
				reasons = append(reasons, "unmapped_material_field:"+name)
			}
		}
	}
	return dedupe(reasons)
}

func applyMappingTransform(value interface{}, transform string) (interface{}, bool, string) {
	switch transform {
	case "copy":
		canonical := Canonicalize(value)
		if !canonical.OK {
			return nil, false, "source_value_not_canonicalizable"
		}
		decoder := json.NewDecoder(bytes.NewBufferString(canonical.Canonical))
		decoder.UseNumber()
		var cloned interface{}
		if err := decoder.Decode(&cloned); err != nil {
			return nil, false, "source_value_not_canonicalizable"
		}
		return cloned, true, ""
	case "sha256-utf8":
		text, ok := value.(string)
		if !ok {
			return nil, false, "source_value_type_mismatch"
		}
		sum := sha256.Sum256([]byte(text))
		return "sha256:" + hex.EncodeToString(sum[:]), true, ""
	case "sha256-jcs":
		canonical := Canonicalize(value)
		if !canonical.OK {
			return nil, false, "source_value_not_canonicalizable"
		}
		sum := sha256.Sum256([]byte(canonical.Canonical))
		return "sha256:" + hex.EncodeToString(sum[:]), true, ""
	default:
		return nil, false, "unknown_transform"
	}
}

func MappingProfileHash(profile map[string]interface{}) string {
	return hashJSON(profile)
}

func MapAction(source interface{}, opts MapActionOptions) (result MapActionResult) {
	defer func() {
		if recover() != nil {
			result = MapActionResult{OK: false, Reasons: []string{"unexpected_mapping_error"}}
		}
	}()

	reasons := validateMappingProfile(opts.Profile, opts.Definitions)
	if !opts.NativeVerified {
		reasons = append(reasons, "native_verification_required")
	}
	profileHash := MappingProfileHash(opts.Profile)
	if profileHash == "" {
		reasons = append(reasons, "invalid_mapping_profile")
	}
	if opts.ExpectedProfileHash == "" || opts.ExpectedProfileHash != profileHash {
		reasons = append(reasons, "mapping_profile_unpinned")
	}
	sourceFormat, _ := opts.Profile["source_format"].(map[string]interface{})
	if opts.SourceDescriptor == nil || !mappingDescriptorEqual(opts.SourceDescriptor, sourceFormat) {
		reasons = append(reasons, "source_format_mismatch")
	}
	sourceObject, sourceOK := source.(map[string]interface{})
	if !sourceOK {
		reasons = append(reasons, "source_not_object")
	}
	sourceDigest := ""
	if sourceOK {
		sourceDigest = hashJSON(sourceObject)
	}
	if sourceDigest == "" {
		reasons = append(reasons, "source_not_canonicalizable")
	}
	reasons = dedupe(reasons)
	if len(reasons) > 0 {
		return MapActionResult{OK: false, Reasons: reasons, ProfileHash: profileHash, SourceDigest: sourceDigest}
	}

	actionType, _ := opts.Profile["target_action_type"].(string)
	action := map[string]interface{}{"action_type": actionType}
	rules, _ := opts.Profile["rules"].([]interface{})
	for _, raw := range rules {
		rule := raw.(map[string]interface{})
		sourcePath := rule["source_path"].(string)
		value, found, reason := valueAtPointer(sourceObject, sourcePath)
		if !found {
			reasons = append(reasons, reason+":"+sourcePath)
			continue
		}
		transformed, ok, reason := applyMappingTransform(value, rule["transform"].(string))
		if !ok {
			reasons = append(reasons, reason+":"+sourcePath)
			continue
		}
		action[rule["target_field"].(string)] = transformed
	}
	if len(reasons) > 0 {
		return MapActionResult{OK: false, Reasons: reasons, ProfileHash: profileHash, SourceDigest: sourceDigest}
	}

	suite := opts.Suite
	if suite == "" {
		suite = "jcs-sha256"
	}
	computed := ComputeCaid(action, ComputeOptions{Suite: suite, Definitions: opts.Definitions})
	if computed.Caid == "" {
		mappedReasons := make([]string, 0, len(computed.Refusals))
		for _, reason := range computed.Refusals {
			mappedReasons = append(mappedReasons, "mapped_action:"+reason)
		}
		if len(mappedReasons) == 0 {
			mappedReasons = []string{"mapped_action:invalid_mapped_action"}
		}
		return MapActionResult{OK: false, Reasons: mappedReasons, ProfileHash: profileHash, SourceDigest: sourceDigest}
	}
	return MapActionResult{
		OK:           true,
		Action:       action,
		Caid:         computed.Caid,
		Digest:       computed.Digest,
		Suite:        suite,
		ProfileHash:  profileHash,
		SourceDigest: sourceDigest,
	}
}

func mapComparisonSide(side map[string]interface{}, definitions []interface{}, suite string) MapActionResult {
	if side == nil {
		side = map[string]interface{}{}
	}
	profile, _ := side["profile"].(map[string]interface{})
	descriptor, _ := side["source_descriptor"].(map[string]interface{})
	expected, _ := side["expected_profile_hash"].(string)
	nativeVerified, _ := side["native_verified"].(bool)
	return MapAction(side["source"], MapActionOptions{
		Profile:             profile,
		SourceDescriptor:    descriptor,
		ExpectedProfileHash: expected,
		NativeVerified:      nativeVerified,
		Definitions:         definitions,
		Suite:               suite,
	})
}

func CompareMappedActions(left, right map[string]interface{}, definitions []interface{}, suite string) MappingComparison {
	mappedLeft := mapComparisonSide(left, definitions, suite)
	mappedRight := mapComparisonSide(right, definitions, suite)
	if !mappedLeft.OK || !mappedRight.OK {
		reasons := []string{}
		if !mappedLeft.OK {
			for _, reason := range mappedLeft.Reasons {
				reasons = append(reasons, "left:"+reason)
			}
		}
		if !mappedRight.OK {
			for _, reason := range mappedRight.Reasons {
				reasons = append(reasons, "right:"+reason)
			}
		}
		return MappingComparison{Verdict: Indeterminate, Reasons: reasons, Left: mappedLeft, Right: mappedRight}
	}
	if mappedLeft.Action["action_type"] != mappedRight.Action["action_type"] {
		return MappingComparison{
			Verdict: Indeterminate,
			Reasons: []string{"target_action_type_mismatch"},
			Left:    mappedLeft,
			Right:   mappedRight,
		}
	}
	if mappedLeft.Caid == mappedRight.Caid {
		return MappingComparison{Verdict: EquivalentUnderProfile, Reasons: []string{}, Left: mappedLeft, Right: mappedRight}
	}
	return MappingComparison{
		Verdict: NotEquivalent,
		Reasons: []string{"material_projection_mismatch"},
		Left:    mappedLeft,
		Right:   mappedRight,
	}
}

// SortedMappingReasons is a helper for consumers that need a stable set view.
// Protocol results preserve evaluation order; this helper does not alter them.
func SortedMappingReasons(reasons []string) []string {
	out := append([]string(nil), reasons...)
	sort.Strings(out)
	return out
}
