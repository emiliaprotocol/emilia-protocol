// SPDX-License-Identifier: Apache-2.0

// mapping.go - the CAID Action-Mapping Profile v1 (draft -04 Section 8).
//
// A mapping result is a content-correlation result, not authorization. The
// caller pins the exact profile hash and source descriptor. Missing material
// fields, unregistered transforms and unpinned profiles abstain; no mapping
// failure ever becomes equivalence.
//
// Reason order is normative (draft -04 Sections 8.3 and 8.4,
// caid/spec/core.json mapping.stages):
//
//	A  profile checks. A profile that is not an object in the data model (so
//	   it has no profile digest), has the wrong @version, carries a member
//	   outside the closed member sets, or breaks a member rule (JSON kind,
//	   octet limits, closed sets, item counts, the source-path and field-name
//	   rules, reserved names) yields exactly invalid_mapping_profile. Otherwise every check runs: distinct rule
//	   paths and targets, distinct material and omitted paths, rule paths
//	   equal to material paths as sets (exactly one rule per material path),
//	   omitted paths disjoint from rule paths, the loss policy's omission
//	   requirement, definition resolution for target_action_type, and one
//	   unmapped_material_field per required field no rule targets.
//	B  native_verification_required, mapping_profile_unpinned,
//	   source_format_mismatch, source_not_object, source_not_canonicalizable,
//	   declared_source_semantic_loss. A and B sort together by reason rank,
//	   repeats removed; mapping stops if any is present.
//	C  one reason per rule, in rule order, suffixed ":<source_path>"; mapping
//	   stops if any is present.
//	D  computation over the projected action; each refusal r becomes
//	   mapped_action:r, in computation order.
//
// A comparison reports left: reasons, then right: reasons (INDETERMINATE);
// then target_action_type_mismatch (INDETERMINATE); then
// material_projection_mismatch (NOT_EQUIVALENT).
package caid

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"caid/internal/jsontext"
)

// MappingProfileVersion is the @version of a v1 mapping profile.
const MappingProfileVersion = specMappingProfileVersion

// Comparison verdicts.
const (
	EquivalentUnderProfile = "EQUIVALENT_UNDER_PROFILE"
	NotEquivalent          = "NOT_EQUIVALENT"
	Indeterminate          = "INDETERMINATE"
)

// DefaultMappingSuite is the suite MapAction uses when its Suite option is
// absent (nil). An explicit empty suite is not defaulted: it refuses.
const DefaultMappingSuite = "jcs-sha256"

// MapActionResult is the outcome of MapAction.
type MapActionResult struct {
	OK               bool                   `json:"ok"`
	Reasons          []string               `json:"reasons,omitempty"`
	Action           map[string]interface{} `json:"action,omitempty"`
	Caid             string                 `json:"caid,omitempty"`
	Digest           string                 `json:"digest,omitempty"`
	DefinitionSha256 string                 `json:"definition_sha256,omitempty"`
	Suite            string                 `json:"suite,omitempty"`
	ProfileHash      string                 `json:"profile_hash,omitempty"`
	SourceDigest     string                 `json:"source_digest,omitempty"`
}

// MappingComparison is the outcome of a comparison of two mapped actions.
type MappingComparison struct {
	Verdict string          `json:"verdict"`
	Reasons []string        `json:"reasons"`
	Left    MapActionResult `json:"left"`
	Right   MapActionResult `json:"right"`
}

// MapActionOptions carries one side of a mapping. Profile, SourceDescriptor
// and the source are host values (normally the output of DecodeJSON or
// DecodeDocumentJSON). ExpectedProfileHash must equal the profile's hash
// ("" pins nothing and refuses as mapping_profile_unpinned). Suite nil means
// DefaultMappingSuite; any non-nil value, including "", is used as given.
type MapActionOptions struct {
	Profile             interface{}
	SourceDescriptor    interface{}
	ExpectedProfileHash string
	NativeVerified      bool
	Definitions         []interface{}
	EnumSnapshots       []interface{}
	Suite               *string
}

// CompareOptions carries what both sides of a comparison share. Suite nil
// means DefaultMappingSuite; any non-nil value is used as given.
type CompareOptions struct {
	Definitions   []interface{}
	EnumSnapshots []interface{}
	Suite         *string
}

var mappingMemberSets = map[string][]string{
	"profile":              specMappingProfileMembers,
	"source_format":        specMappingSourceFormatMembers,
	"rule":                 specMappingRuleMembers,
	"omitted_source_field": specMappingOmittedSourceFieldMembers,
}

var mappingClosedSets = map[string][]string{
	"transforms":    specMappingTransforms,
	"loss_policies": specMappingLossPolicies,
}

// MappingProfileHash is "sha256:" and the hex SHA-256 of the RFC 8785
// encoding of the profile, or "" when the profile is outside the data model.
func MappingProfileHash(profile interface{}) string {
	return hashJSON(profile)
}

// validSourcePath is the source-path rule of Appendix A: a JSON pointer
// [RFC6901] other than "", of scalar values, in which every "~" is followed
// by "0" or "1".
func validSourcePath(pointer string) bool {
	if len(pointer) == 0 || pointer[0] != '/' || !utf8.ValidString(pointer) {
		return false
	}
	for i := 0; i < len(pointer); i++ {
		if pointer[i] == '~' {
			if i+1 >= len(pointer) || (pointer[i+1] != '0' && pointer[i+1] != '1') {
				return false
			}
			i++
		}
	}
	return true
}

// mappingValuesAt returns the values at a member path ("*" is every element
// of an array). ok is false when a member on the path is absent or has the
// wrong kind, except that an absent optional profile member has no values.
func mappingValuesAt(profile map[string]interface{}, path []string) ([]interface{}, bool) {
	current := []interface{}{profile}
	for depth, segment := range path {
		next := []interface{}{}
		for _, node := range current {
			if segment == "*" {
				items, ok := asArray(node)
				if !ok {
					return nil, false
				}
				next = append(next, items...)
				continue
			}
			obj, ok := asObject(node)
			if !ok {
				return nil, false
			}
			value, present := obj[segment]
			if !present {
				if depth == 0 && stringIn(specMappingOptionalProfileMembers, segment) {
					continue
				}
				return nil, false
			}
			next = append(next, value)
		}
		current = next
	}
	return current, true
}

func mappingMemberRuleHolds(rule specMappingMemberRule, value interface{}) bool {
	if kindOf(value) != rule.JSON {
		return false // includes a member written as null
	}
	switch rule.JSON {
	case "string":
		s := value.(string)
		if (rule.MinOctets > 0 && len(s) < rule.MinOctets) || (rule.MaxOctets > 0 && len(s) > rule.MaxOctets) {
			return false
		}
		if rule.Closed != "" && !stringIn(mappingClosedSets[rule.Closed], s) {
			return false
		}
		switch rule.Rule {
		case "":
		case "source-path":
			if !validSourcePath(s) {
				return false
			}
		case "field-name":
			if !utf8.ValidString(s) || len(s) < specFieldNameMinLength {
				return false
			}
			for _, r := range specFieldNameForbiddenCodePoints {
				if strings.ContainsRune(s, r) {
					return false
				}
			}
		default:
			return false // a rule this implementation does not know: fail closed
		}
		if stringIn(rule.Reserved, s) {
			return false
		}
	case "array":
		items := value.([]interface{})
		if (rule.MinItems > 0 && len(items) < rule.MinItems) || (rule.MaxItems > 0 && len(items) > rule.MaxItems) {
			return false
		}
	}
	return true
}

// mappingShapeHolds is the stage A shape gate: an object in the data model
// (canonicalizable, so it has a profile digest), version, closed members,
// member rules.
func mappingShapeHolds(profile interface{}, canonicalizable bool) bool {
	p, ok := asObject(profile)
	if !ok || !canonicalizable {
		return false
	}
	if v, ok := p["@version"].(string); !ok || v != specMappingProfileVersion {
		return false
	}
	closed := func(value interface{}, set string) bool {
		obj, ok := asObject(value)
		if !ok {
			return true // the member rules refuse a non-object
		}
		for k := range obj {
			if !stringIn(mappingMemberSets[set], k) {
				return false
			}
		}
		return true
	}
	if !closed(p, "profile") || !closed(p["source_format"], "source_format") {
		return false
	}
	if rules, ok := asArray(p["rules"]); ok {
		for _, r := range rules {
			if !closed(r, "rule") {
				return false
			}
		}
	}
	if omissions, ok := asArray(p["omitted_source_fields"]); ok {
		for _, o := range omissions {
			if !closed(o, "omitted_source_field") {
				return false
			}
		}
	}
	for _, rule := range specMappingMemberRules {
		values, ok := mappingValuesAt(p, rule.Path)
		if !ok {
			return false
		}
		for _, v := range values {
			if !mappingMemberRuleHolds(rule, v) {
				return false
			}
		}
	}
	return true
}

func mappingStrings(p map[string]interface{}, path []string) []string {
	values, _ := mappingValuesAt(p, path)
	out := make([]string, 0, len(values))
	for _, v := range values {
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

func stringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, v := range values {
		out[v] = true
	}
	return out
}

// mappingStageA returns the ranked stage A reasons.
func mappingStageA(profile interface{}, canonicalizable bool, definitions []interface{}) []rankedReason {
	gate := []rankedReason{{specMappingReasonRank["invalid_mapping_profile"], 0, "invalid_mapping_profile"}}
	if !mappingShapeHolds(profile, canonicalizable) {
		return gate
	}
	p, _ := asObject(profile)
	var found []rankedReason
	invalid := func() { found = append(found, gate[0]) }
	for _, path := range specMappingUnique {
		values := mappingStrings(p, path)
		if len(stringSet(values)) != len(values) {
			invalid()
		}
	}
	for _, pair := range specMappingEqualSets {
		a, b := stringSet(mappingStrings(p, pair[0])), stringSet(mappingStrings(p, pair[1]))
		equal := len(a) == len(b)
		for v := range a {
			if !b[v] {
				equal = false
			}
		}
		if !equal {
			invalid()
		}
	}
	for _, pair := range specMappingDisjoint {
		a, b := stringSet(mappingStrings(p, pair[0])), stringSet(mappingStrings(p, pair[1]))
		for v := range a {
			if b[v] {
				invalid()
				break
			}
		}
	}
	lossPolicy, _ := p["loss_policy"].(string)
	omissions, _ := asArray(p["omitted_source_fields"])
	switch specMappingLossPolicyOmissions[lossPolicy] {
	case "absent_or_empty":
		if len(omissions) != 0 {
			invalid()
		}
	case "non_empty":
		if len(omissions) == 0 {
			invalid()
		}
	default:
		invalid()
	}
	targetType, _ := p["target_action_type"].(string)
	res := resolveDefinition(targetType, definitions)
	if res.reason != "" {
		found = append(found, rankedReason{specMappingReasonRank[res.reason], 0, res.reason})
	} else {
		targets := stringSet(mappingStrings(p, []string{"rules", "*", "target_field"}))
		for i, e := range fieldEntries(res.definition, "required_fields") {
			f, _ := asObject(e)
			name, _ := f["name"].(string)
			if !targets[name] {
				found = append(found, rankedReason{specMappingReasonRank["unmapped_material_field"], i, "unmapped_material_field:" + name})
			}
		}
	}
	return found
}

func valueAtPointer(value interface{}, pointer string) (interface{}, string) {
	if !validSourcePath(pointer) {
		return nil, "invalid_source_path"
	}
	current := value
	for _, raw := range strings.Split(pointer[1:], "/") {
		segment := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		if items, ok := asArray(current); ok {
			if !specPatternArrayIndex.MatchString(segment) {
				return nil, "invalid_source_path"
			}
			index, err := strconv.Atoi(segment)
			if err != nil || index >= len(items) {
				return nil, "missing_source_field"
			}
			current = items[index]
			continue
		}
		if obj, ok := asObject(current); ok {
			next, present := obj[segment]
			if !present {
				return nil, "missing_source_field"
			}
			current = next
			continue
		}
		return nil, "missing_source_field"
	}
	return current, ""
}

func applyMappingTransform(value interface{}, transform string) (interface{}, string) {
	switch transform {
	case "copy":
		c := Canonicalize(value)
		if !c.OK {
			return nil, "source_value_not_canonicalizable"
		}
		// A fresh copy in canonical form, decoded by the package's own
		// strict decoder (never encoding/json).
		cloned, err := jsontext.Decode([]byte(c.Canonical), jsontext.Options{MaxDepth: specLimitNestingDepth})
		if err != nil {
			return nil, "source_value_not_canonicalizable"
		}
		return cloned, ""
	case "sha256-utf8":
		text, ok := value.(string)
		if !ok {
			return nil, "source_value_type_mismatch"
		}
		sum := sha256.Sum256([]byte(text))
		return "sha256:" + hex.EncodeToString(sum[:]), ""
	case "sha256-jcs":
		c := Canonicalize(value)
		if !c.OK {
			return nil, "source_value_not_canonicalizable"
		}
		return "sha256:" + sha256Hex(c.Canonical), ""
	case "sha256-hex-to-digest":
		text, ok := value.(string)
		if !ok || !specMappingTransformPattern[transform].MatchString(text) {
			return nil, "source_value_type_mismatch"
		}
		return "sha256:" + text, ""
	}
	return nil, "unknown_transform"
}

func mappingFailure(reasons []string, profileHash, sourceDigest string) MapActionResult {
	return MapActionResult{OK: false, Reasons: reasons, ProfileHash: profileHash, SourceDigest: sourceDigest}
}

// MapAction projects a native source object onto its target action type
// under a pinned mapping profile and computes the projected action's CAID.
// It never panics; a fault inside it would yield unexpected_mapping_error,
// which a conforming mapper never emits.
func MapAction(source interface{}, opts MapActionOptions) (result MapActionResult) {
	defer func() {
		if recover() != nil {
			result = MapActionResult{OK: false, Reasons: []string{specMappingFaultReasons[0]}}
		}
	}()

	profileHash := MappingProfileHash(opts.Profile)
	found := mappingStageA(opts.Profile, profileHash != "", opts.Definitions)
	rank := func(r string) rankedReason { return rankedReason{specMappingReasonRank[r], 0, r} }
	if !opts.NativeVerified {
		found = append(found, rank("native_verification_required"))
	}
	if opts.ExpectedProfileHash == "" || opts.ExpectedProfileHash != profileHash {
		found = append(found, rank("mapping_profile_unpinned"))
	}
	profile, profileIsObject := asObject(opts.Profile)
	var profileSourceFormat interface{}
	if profileIsObject {
		profileSourceFormat = profile["source_format"]
	}
	descriptor, descriptorIsObject := asObject(opts.SourceDescriptor)
	if !descriptorIsObject || !canonicalEqual(descriptor, profileSourceFormat) {
		found = append(found, rank("source_format_mismatch"))
	}
	sourceObject, sourceIsObject := asObject(source)
	if !sourceIsObject {
		found = append(found, rank("source_not_object"))
	}
	sourceDigest := ""
	if sourceIsObject {
		sourceDigest = hashJSON(sourceObject)
	}
	if sourceDigest == "" {
		found = append(found, rank("source_not_canonicalizable"))
	}
	if profileIsObject {
		if policy, _ := profile["loss_policy"].(string); policy == "declared-source-semantic-loss" {
			found = append(found, rank("declared_source_semantic_loss"))
		}
	}
	if reasons := orderMappingReasons(found); len(reasons) > 0 {
		return mappingFailure(reasons, profileHash, sourceDigest)
	}

	// Stage C: the profile passed stage A, so its shape is known.
	actionType, _ := profile["target_action_type"].(string)
	action := map[string]interface{}{"action_type": actionType}
	var reasons []string
	rules, _ := asArray(profile["rules"])
	for _, raw := range rules {
		rule, _ := asObject(raw)
		sourcePath, _ := rule["source_path"].(string)
		transform, _ := rule["transform"].(string)
		target, _ := rule["target_field"].(string)
		value, reason := valueAtPointer(sourceObject, sourcePath)
		if reason == "" {
			value, reason = applyMappingTransform(value, transform)
		}
		if reason != "" {
			reasons = append(reasons, reason+":"+sourcePath)
			continue
		}
		action[target] = value
	}
	if len(reasons) > 0 {
		return mappingFailure(reasons, profileHash, sourceDigest)
	}

	// Stage D.
	suite := DefaultMappingSuite
	if opts.Suite != nil {
		suite = *opts.Suite
	}
	computed := ComputeCaid(action, ComputeOptions{Suite: suite, Definitions: opts.Definitions, EnumSnapshots: opts.EnumSnapshots})
	if computed.Caid == "" {
		refusals := computed.Refusals
		if len(refusals) == 0 {
			refusals = []string{specMappingFaultReasons[1]}
		}
		mapped := make([]string, 0, len(refusals))
		for _, r := range refusals {
			mapped = append(mapped, "mapped_action:"+r)
		}
		return mappingFailure(mapped, profileHash, sourceDigest)
	}
	return MapActionResult{
		OK:               true,
		Action:           action,
		Caid:             computed.Caid,
		Digest:           computed.Digest,
		DefinitionSha256: computed.DefinitionSha256,
		Suite:            suite,
		ProfileHash:      profileHash,
		SourceDigest:     sourceDigest,
	}
}

func canonicalEqual(left, right interface{}) bool {
	a := Canonicalize(left)
	b := Canonicalize(right)
	return a.OK && b.OK && a.Canonical == b.Canonical
}

// orderMappingReasons sorts stage A and B reasons by rank, then by field
// position, stable, and removes repeats.
func orderMappingReasons(found []rankedReason) []string {
	return orderReasons(found)
}

func mapComparisonSide(side interface{}, opts CompareOptions) MapActionResult {
	obj, _ := asObject(side)
	var source, profile, descriptor interface{}
	expected := ""
	nativeVerified := false
	if obj != nil {
		source = obj["source"]
		profile = obj["profile"]
		descriptor = obj["source_descriptor"]
		expected, _ = obj["expected_profile_hash"].(string)
		nativeVerified, _ = obj["native_verified"].(bool)
	}
	return MapAction(source, MapActionOptions{
		Profile:             profile,
		SourceDescriptor:    descriptor,
		ExpectedProfileHash: expected,
		NativeVerified:      nativeVerified,
		Definitions:         opts.Definitions,
		EnumSnapshots:       opts.EnumSnapshots,
		Suite:               opts.Suite,
	})
}

// CompareMappedActionsWithOptions maps both sides and compares the projected
// actions. Each side is an object with members source, profile,
// source_descriptor, expected_profile_hash and native_verified (true only
// when it is the JSON value true).
func CompareMappedActionsWithOptions(left, right interface{}, opts CompareOptions) MappingComparison {
	mappedLeft := mapComparisonSide(left, opts)
	mappedRight := mapComparisonSide(right, opts)
	if !mappedLeft.OK || !mappedRight.OK {
		reasons := []string{}
		for i, side := range []MapActionResult{mappedLeft, mappedRight} {
			if side.OK {
				continue
			}
			for _, reason := range side.Reasons {
				reasons = append(reasons, specMappingComparisonPrefixes[i]+":"+reason)
			}
		}
		return MappingComparison{Verdict: specMappingPrefixedVerdict, Reasons: reasons, Left: mappedLeft, Right: mappedRight}
	}
	if mappedLeft.Action["action_type"] != mappedRight.Action["action_type"] {
		return MappingComparison{
			Verdict: specMappingReasonVerdicts["target_action_type_mismatch"],
			Reasons: []string{"target_action_type_mismatch"},
			Left:    mappedLeft,
			Right:   mappedRight,
		}
	}
	if mappedLeft.Caid == mappedRight.Caid {
		return MappingComparison{Verdict: EquivalentUnderProfile, Reasons: []string{}, Left: mappedLeft, Right: mappedRight}
	}
	return MappingComparison{
		Verdict: specMappingReasonVerdicts["material_projection_mismatch"],
		Reasons: []string{"material_projection_mismatch"},
		Left:    mappedLeft,
		Right:   mappedRight,
	}
}

// CompareMappedActions compares two sides under suite, used exactly as given
// (an empty suite refuses on both sides; it is never defaulted).
func CompareMappedActions(left, right map[string]interface{}, definitions []interface{}, suite string) MappingComparison {
	return CompareMappedActionsWithOptions(left, right, CompareOptions{Definitions: definitions, Suite: &suite})
}

// CompareMappedActionsWithEnumSnapshots is CompareMappedActions with
// integrity-pinned external enum snapshots.
func CompareMappedActionsWithEnumSnapshots(left, right map[string]interface{}, definitions []interface{}, enumSnapshots []interface{}, suite string) MappingComparison {
	return CompareMappedActionsWithOptions(left, right, CompareOptions{Definitions: definitions, EnumSnapshots: enumSnapshots, Suite: &suite})
}

// SortedMappingReasons is a helper for consumers that need a stable set view.
// Protocol results keep their normative order; this helper does not alter
// them.
func SortedMappingReasons(reasons []string) []string {
	out := append([]string(nil), reasons...)
	sort.Strings(out)
	return out
}
