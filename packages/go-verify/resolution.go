// SPDX-License-Identifier: Apache-2.0
// EP-RESOLUTION-v1 -- four-outcome binding-moment resolution.
package emiliaverify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"time"
)

const ResolutionVersion = "EP-RESOLUTION-v1"
const ResolutionContextType = "ep.resolution.v1"

var resolutionHashPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var resolutionTimestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)

// ResolutionOptions are relying-party inputs. The wire object never supplies
// its own authority: PrincipalKeys, BindingMoment, ExpectedActionHash, and RPID
// must come from the verifier's trust configuration or transaction context.
type ResolutionOptions struct {
	BindingMoment          map[string]any
	ExpectedActionHash     string
	ExpectedSelectedOption *int
	ExpectedNonce          string
	ExpectedInitiator      string
	EvaluationTime         string
	PrincipalKeys          map[string]map[string]string
	RPID                   string
	AllowedOrigins         []string
}

type ResolutionResult struct {
	Valid             bool            `json:"valid"`
	AuthorizesAction  bool            `json:"authorizes_action"`
	Outcome           string          `json:"outcome,omitempty"`
	RequiresSuccessor bool            `json:"requires_successor"`
	Checks            map[string]bool `json:"checks"`
	Reason            string          `json:"reason,omitempty"`
}

func resolutionIsHash(value string) bool {
	return resolutionHashPattern.MatchString(value)
}

func ComputeBindingMomentHash(bindingMoment map[string]any) string {
	if bindingMoment == nil || !IsCanonicalizable(bindingMoment) {
		return ""
	}
	sum := sha256.Sum256([]byte(Canonicalize(bindingMoment)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ComputeResolutionResponseHash(response any) string {
	if !IsCanonicalizable(response) {
		return ""
	}
	sum := sha256.Sum256([]byte(Canonicalize(response)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func resolutionBindingMomentShapeValid(bindingMoment map[string]any) bool {
	outerAllowed := []string{"synopsis", "findings", "recommendations", "offer", "question", "meta"}
	outerRequired := []string{"synopsis", "findings", "recommendations", "offer", "question"}
	if !resolutionExactKeys(bindingMoment, outerAllowed, outerRequired) {
		return false
	}
	if _, ok := bindingMoment["synopsis"].(string); !ok {
		return false
	}
	if _, ok := bindingMoment["offer"].(string); !ok {
		return false
	}
	for _, field := range []string{"findings", "recommendations"} {
		items, ok := bindingMoment[field].([]any)
		if !ok {
			return false
		}
		for _, item := range items {
			if _, ok := item.(string); !ok {
				return false
			}
		}
	}
	question := getMap(bindingMoment["question"])
	questionKeys := []string{"stem", "options", "recommended_idx", "hatches"}
	if !resolutionExactKeys(question, questionKeys, questionKeys) {
		return false
	}
	if _, ok := question["stem"].(string); !ok {
		return false
	}
	options, ok := question["options"].([]any)
	if !ok || len(options) < 2 || len(options) > 4 {
		return false
	}
	optionKeys := []string{"label", "reasoning"}
	for _, rawOption := range options {
		option := getMap(rawOption)
		if !resolutionExactKeys(option, optionKeys, optionKeys) {
			return false
		}
		if _, ok := option["label"].(string); !ok {
			return false
		}
		if _, ok := option["reasoning"].(string); !ok {
			return false
		}
	}
	recommended, ok := resolutionIndex(question["recommended_idx"])
	if !ok || recommended >= len(options) {
		return false
	}
	hatches := getMap(question["hatches"])
	hatchKeys := []string{"free_text", "dialogue"}
	if !resolutionExactKeys(hatches, hatchKeys, hatchKeys) {
		return false
	}
	if _, ok := hatches["free_text"].(bool); !ok {
		return false
	}
	if _, ok := hatches["dialogue"].(bool); !ok {
		return false
	}
	if rawMeta, present := bindingMoment["meta"]; present {
		meta := getMap(rawMeta)
		if !resolutionExactKeys(meta, []string{"decision_class", "calibration_note"}, []string{}) {
			return false
		}
		for _, value := range meta {
			if _, ok := value.(string); !ok {
				return false
			}
		}
	}
	return true
}

func resolutionSignedOrigin(signoff map[string]any) string {
	encoded := getStr(getMap(signoff["webauthn"]), "client_data_json")
	raw, err := b64urlDecode(encoded)
	if err != nil {
		return ""
	}
	client, err := decodeStrictJSONObject(raw)
	if err != nil {
		return ""
	}
	return getStr(client, "origin")
}

func resolutionOriginAllowed(origin string, allowed []string) bool {
	if origin == "" || len(allowed) == 0 {
		return false
	}
	found := false
	for _, item := range allowed {
		if item == "" {
			return false
		}
		if item == origin {
			found = true
		}
	}
	return found
}

func resolutionExactKeys(value map[string]any, allowed []string, required []string) bool {
	if value == nil {
		return false
	}
	a := map[string]bool{}
	for _, key := range allowed {
		a[key] = true
	}
	for key := range value {
		if !a[key] {
			return false
		}
	}
	for _, key := range required {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}

func resolutionIndex(value any) (int, bool) {
	switch n := value.(type) {
	case json.Number:
		i, err := strconv.Atoi(n.String())
		return i, err == nil && i >= 0
	case float64:
		return int(n), n >= 0 && math.Trunc(n) == n
	case int:
		return n, n >= 0
	default:
		return 0, false
	}
}

func resolutionShapeValid(resolution map[string]any, bindingMoment map[string]any, currentEnvelopeHash string) bool {
	outcome := getStr(resolution, "outcome")
	allowed := map[string][]string{
		"approved": {"outcome", "selected_option"},
		"declined": {"outcome"},
		"amended":  {"outcome", "response_hash", "successor_envelope_hash"},
		"rejected": {"outcome", "objection_hash", "successor_envelope_hash"},
	}[outcome]
	if allowed == nil || !resolutionExactKeys(resolution, allowed, []string{"outcome"}) {
		return false
	}
	if outcome == "approved" {
		selected, ok := resolutionIndex(resolution["selected_option"])
		question := getMap(bindingMoment["question"])
		options, optionsOK := question["options"].([]any)
		return ok && optionsOK && selected < len(options)
	}
	if outcome == "declined" {
		return len(resolution) == 1
	}
	if outcome == "amended" && !resolutionIsHash(getStr(resolution, "response_hash")) {
		return false
	}
	if outcome == "rejected" {
		if _, present := resolution["objection_hash"]; present && !resolutionIsHash(getStr(resolution, "objection_hash")) {
			return false
		}
	}
	if _, present := resolution["successor_envelope_hash"]; present {
		successor := getStr(resolution, "successor_envelope_hash")
		if !resolutionIsHash(successor) || successor == currentEnvelopeHash {
			return false
		}
	}
	return true
}

func resolutionStructureValid(receipt map[string]any) bool {
	if !resolutionExactKeys(receipt, []string{"profile", "signoff"}, []string{"profile", "signoff"}) || getStr(receipt, "profile") != ResolutionVersion {
		return false
	}
	signoff := getMap(receipt["signoff"])
	if !resolutionExactKeys(signoff, []string{"@type", "context", "webauthn"}, []string{"@type", "context", "webauthn"}) || getStr(signoff, "@type") != "ep.signoff" {
		return false
	}
	context := getMap(signoff["context"])
	contextKeys := []string{"ep_version", "context_type", "envelope_hash", "action_hash", "principal", "principal_key_id", "initiator", "nonce", "issued_at", "expires_at", "resolution"}
	if !resolutionExactKeys(context, contextKeys, contextKeys) {
		return false
	}
	webauthn := getMap(signoff["webauthn"])
	webauthnKeys := []string{"authenticator_data", "client_data_json", "signature"}
	if !resolutionExactKeys(webauthn, webauthnKeys, webauthnKeys) {
		return false
	}
	return getStr(context, "ep_version") == "1.0" && getStr(context, "context_type") == ResolutionContextType &&
		resolutionIsHash(getStr(context, "envelope_hash")) && resolutionIsHash(getStr(context, "action_hash")) &&
		getStr(context, "principal") != "" && getStr(context, "principal_key_id") != "" &&
		getStr(context, "initiator") != "" && getStr(context, "nonce") != ""
}

func resolutionRefuse(reason string, checks map[string]bool, outcome string) ResolutionResult {
	return ResolutionResult{Valid: false, AuthorizesAction: false, Outcome: outcome, RequiresSuccessor: false, Checks: checks, Reason: reason}
}

func resolutionInstant(value string) (time.Time, bool) {
	if !resolutionTimestampPattern.MatchString(value) {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	return t, err == nil
}

// VerifyResolutionReceipt verifies an EP-RESOLUTION-v1 object. It never panics;
// malformed or hostile input returns a typed refusal.
func VerifyResolutionReceipt(receipt map[string]any, opts ResolutionOptions) (result ResolutionResult) {
	checks := map[string]bool{
		"structure": false, "canonical_profile": false, "binding_moment_shape": false,
		"outcome_shape": false, "envelope_binding": false, "action_binding": false,
		"principal_pin": false, "selected_option_binding": false, "authorization_context": false,
		"initiator_binding": false, "nonce_binding": false, "time_window": false,
		"evaluation_time": false, "rp_id": false, "origin": false, "webauthn": false,
	}
	defer func() {
		if recover() != nil {
			result = resolutionRefuse("malformed_resolution_receipt", checks, "")
		}
	}()
	if !resolutionStructureValid(receipt) {
		return resolutionRefuse("malformed_resolution_receipt", checks, "")
	}

	signoff := getMap(receipt["signoff"])
	context := getMap(signoff["context"])
	resolution := getMap(context["resolution"])
	outcome := getStr(resolution, "outcome")
	checks["structure"] = true
	checks["canonical_profile"] = IsCanonicalizable(context) && IsCanonicalizable(opts.BindingMoment)
	if !checks["canonical_profile"] {
		return resolutionRefuse("resolution_outside_canonicalization_profile", checks, outcome)
	}
	checks["binding_moment_shape"] = resolutionBindingMomentShapeValid(opts.BindingMoment)
	if !checks["binding_moment_shape"] {
		return resolutionRefuse("malformed_binding_moment", checks, outcome)
	}

	checks["outcome_shape"] = resolutionShapeValid(resolution, opts.BindingMoment, getStr(context, "envelope_hash"))
	if !checks["outcome_shape"] {
		return resolutionRefuse("invalid_outcome_shape", checks, outcome)
	}
	checks["envelope_binding"] = opts.BindingMoment != nil && getStr(context, "envelope_hash") == ComputeBindingMomentHash(opts.BindingMoment)
	if !checks["envelope_binding"] {
		return resolutionRefuse("envelope_binding_mismatch", checks, outcome)
	}
	checks["action_binding"] = resolutionIsHash(opts.ExpectedActionHash) && getStr(context, "action_hash") == opts.ExpectedActionHash
	if !checks["action_binding"] {
		return resolutionRefuse("action_binding_mismatch", checks, outcome)
	}
	checks["selected_option_binding"] = outcome != "approved"
	if outcome == "approved" && opts.ExpectedSelectedOption != nil {
		selected, ok := resolutionIndex(resolution["selected_option"])
		checks["selected_option_binding"] = ok && selected == *opts.ExpectedSelectedOption
	}
	keyID := getStr(context, "principal_key_id")
	pin := opts.PrincipalKeys[keyID]
	checks["principal_pin"] = pin != nil && pin["public_key"] != "" && pin["principal"] == getStr(context, "principal")
	if !checks["principal_pin"] {
		return resolutionRefuse("principal_key_not_pinned_for_role", checks, outcome)
	}
	initiatorPinned := opts.ExpectedInitiator != ""
	checks["initiator_binding"] = !initiatorPinned || getStr(context, "initiator") == opts.ExpectedInitiator
	if !checks["initiator_binding"] {
		return resolutionRefuse("initiator_binding_mismatch", checks, outcome)
	}
	noncePinned := opts.ExpectedNonce != ""
	checks["nonce_binding"] = !noncePinned || getStr(context, "nonce") == opts.ExpectedNonce
	if !checks["nonce_binding"] {
		return resolutionRefuse("nonce_binding_mismatch", checks, outcome)
	}
	issued, issuedOK := resolutionInstant(getStr(context, "issued_at"))
	expires, expiresOK := resolutionInstant(getStr(context, "expires_at"))
	checks["time_window"] = issuedOK && expiresOK && issued.Before(expires)
	if checks["time_window"] && opts.EvaluationTime != "" {
		evaluation, evaluationOK := resolutionInstant(opts.EvaluationTime)
		checks["evaluation_time"] = evaluationOK && !evaluation.Before(issued) && !evaluation.After(expires)
		if !checks["evaluation_time"] {
			return resolutionRefuse("resolution_outside_validity_window", checks, outcome)
		}
	}
	if !checks["time_window"] {
		return resolutionRefuse("resolution_outside_validity_window", checks, outcome)
	}
	checks["rp_id"] = opts.RPID != ""
	if !checks["rp_id"] {
		return resolutionRefuse("rp_id_required", checks, outcome)
	}
	checks["origin"] = resolutionOriginAllowed(resolutionSignedOrigin(signoff), opts.AllowedOrigins)
	if !checks["origin"] {
		return resolutionRefuse("webauthn_origin_not_allowed", checks, outcome)
	}
	checks["webauthn"] = VerifyWebAuthnSignoff(signoff, pin["public_key"], opts.RPID, opts.AllowedOrigins).Valid
	if !checks["webauthn"] {
		return resolutionRefuse("webauthn_verification_failed", checks, outcome)
	}
	checks["authorization_context"] = checks["selected_option_binding"] && initiatorPinned && noncePinned && checks["evaluation_time"]
	return ResolutionResult{
		Valid: true, AuthorizesAction: outcome == "approved" && checks["authorization_context"], Outcome: outcome,
		RequiresSuccessor: outcome == "amended" || outcome == "rejected", Checks: checks,
	}
}
