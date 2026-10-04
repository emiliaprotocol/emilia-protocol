// SPDX-License-Identifier: Apache-2.0
//
// EP-AEC-v1 — Authorization Evidence Chain (composition verifier).
// Mirrors packages/verify/evidence-chain.js and the Python verify_authorization_chain.
// Composes heterogeneous agent-authorization receipts that all bind ONE canonical
// action into a single offline, fail-closed SATISFIED/UNSATISFIED result. It does
// not make the relying party's separate authorization decision.
package emiliaverify

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const AECVersion = "EP-AEC-v1"

const (
	aecMaxComponents        = 64
	aecMaxRequirementLength = 4096
	aecMaxRequirementTokens = 256
	aecMaxRequirementDepth  = 32
	aecMaxQuorumMembers     = 32
	aecMaxJSONDepth         = 64
	aecMaxJSONNodes         = 50000
	aecMaxJSONStringBytes   = 1024 * 1024
)

var aecIdent = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

// ComponentResult is what a component verifier reports: validity + the action
// digest the component itself attests it authorized.
type ComponentResult struct {
	Valid        bool
	ActionDigest string
}

// ComponentVerifier verifies one component's evidence within a context.
type ComponentVerifier func(evidence any, ctx map[string]any) ComponentResult

// AECComponentRow is a per-component audit row.
type AECComponentRow struct {
	Type   string
	Label  string
	Valid  bool
	Bound  bool
	Reason string
}

// AECResult is the chain verification result.
type AECResult struct {
	Satisfied bool
	// Allow is a compatibility alias for Satisfied.
	Allow               bool
	ActionDigest        string
	ExpectedActionBound bool
	Components          []AECComponentRow
	Reasons             []string
	// RequirementSource records whose sufficiency bar was evaluated:
	// "relying_party" when pinned via the variadic requirement argument,
	// "presenter" when the chain document's own requirement was used.
	RequirementSource string
}

// AECOptions carries relying-party-owned acceptance inputs. It is separate from
// the legacy VerifyAuthorizationChain signature so existing Go callers keep
// compiling while profile-aware callers can pin built-in verifier policy.
type AECOptions struct {
	Requirement          string
	ExpectedActionDigest string
	VerificationTime     string
	PoliciesByType       map[string]any
}

// ActionDigest returns the canonical action digest (hex) = sha256(JCS(action)).
func ActionDigest(action any) string {
	sum := sha256.Sum256([]byte(Canonicalize(action)))
	return hex.EncodeToString(sum[:])
}

func aecNormDigest(d any) string {
	s, ok := d.(string)
	if !ok {
		return ""
	}
	bare := strings.TrimPrefix(strings.ToLower(s), "sha256:")
	if len(bare) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(bare); err != nil {
		return ""
	}
	return bare
}

func aecMaxAgeValid(maxAge any) bool {
	max, ok := toFloat(maxAge)
	return ok && max >= 0 && max == float64(int64(max))
}

func aecFreshAt(context map[string]any, verificationTime string, maxAge any) bool {
	if !aecMaxAgeValid(maxAge) {
		return false
	}
	max, _ := toFloat(maxAge)
	at, atOK := parseMillis(verificationTime)
	issued, issuedOK := parseMillis(getStr(context, "issued_at"))
	expires, expiresOK := parseMillis(getStr(context, "expires_at"))
	return atOK && issuedOK && expiresOK && issued <= at && at <= expires && float64(at-issued) <= max*1000
}

func aecFreshRegistrySnapshot(profile map[string]any, verificationTime string) bool {
	maxAge := profile["max_registry_age_sec"]
	if !aecMaxAgeValid(maxAge) {
		return false
	}
	max, _ := toFloat(maxAge)
	at, atOK := parseMillis(verificationTime)
	checked, checkedOK := parseMillis(getStr(profile, "registry_checked_at"))
	return atOK && checkedOK && checked <= at && float64(at-checked) <= max*1000
}

func aecActiveDirectoryEntry(entry map[string]any, verificationTime string) bool {
	if entry == nil || getStr(entry, "status") != "active" {
		return false
	}
	at, atOK := parseMillis(verificationTime)
	start, startOK := parseMillis(getStr(entry, "valid_from"))
	end, endOK := parseMillis(getStr(entry, "valid_to"))
	if !atOK || !startOK || !endOK || at < start || at > end {
		return false
	}
	revokedRaw, present := entry["revoked_at"]
	if !present || revokedRaw == nil {
		return true
	}
	revoked, revokedOK := parseMillis(getStr(entry, "revoked_at"))
	return revokedOK && at < revoked
}

func aecAllowedOrigins(profile map[string]any) map[string]bool {
	raw, ok := profile["allowed_origins"].([]any)
	if !ok || len(raw) == 0 || len(raw) > 16 {
		return nil
	}
	origins := map[string]bool{}
	for _, value := range raw {
		origin, ok := value.(string)
		if !ok || origin == "" || len(origin) > 2048 {
			return nil
		}
		origins[origin] = true
	}
	return origins
}

func aecWebAuthnOrigin(webauthn map[string]any) string {
	encoded := getStr(webauthn, "client_data_json")
	if encoded == "" || strings.ContainsAny(encoded, "+/=") {
		return ""
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return ""
	}
	clientData, err := decodeStrictJSONObject(decoded)
	if err != nil {
		return ""
	}
	return getStr(clientData, "origin")
}

func aecBoundedJSON(value any) bool {
	type item struct {
		value any
		depth int
	}
	stack := []item{{value: value}}
	nodes, stringBytes := 0, 0
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		nodes++
		if nodes > aecMaxJSONNodes || current.depth > aecMaxJSONDepth {
			return false
		}
		switch v := current.value.(type) {
		case string:
			if !utf8.ValidString(v) {
				return false
			}
			stringBytes += len(v)
		case map[string]any:
			for key, child := range v {
				if !utf8.ValidString(key) {
					return false
				}
				stringBytes += len(key)
				stack = append(stack, item{value: child, depth: current.depth + 1})
			}
		case []any:
			for _, child := range v {
				stack = append(stack, item{value: child, depth: current.depth + 1})
			}
		default:
			if !IsCanonicalizable(v) {
				return false
			}
		}
		if stringBytes > aecMaxJSONStringBytes {
			return false
		}
	}
	return true
}

func builtinAECVerifiers() map[string]ComponentVerifier {
	return map[string]ComponentVerifier{
		"ep-quorum": func(ev any, ctx map[string]any) ComponentResult {
			m, _ := ev.(map[string]any)
			// Internal consistency is not acceptance. Pin the exact quorum policy,
			// RP ID, context policy, and key -> approver -> role directory out of band.
			profiles, _ := ctx["policiesByType"].(map[string]any)
			profile := getMap(profiles["ep-quorum"])
			allowedOrigins := aecAllowedOrigins(profile)
			policy := getMap(profile["policy"])
			approvers := getMap(profile["approvers"])
			rpID := getStr(profile, "rp_id")
			contextPolicy := getStr(profile, "context_policy")
			maxAge := profile["max_age_sec"]
			membersRaw, _ := m["members"].([]any)
			if policy == nil || approvers == nil || allowedOrigins == nil || rpID == "" || contextPolicy == "" || !aecMaxAgeValid(maxAge) || !aecFreshRegistrySnapshot(profile, getStr(ctx, "verificationTime")) || len(membersRaw) == 0 || len(membersRaw) > aecMaxQuorumMembers {
				return ComponentResult{Valid: false, ActionDigest: ""}
			}
			mode := getStr(policy, "mode")
			if mode != "threshold" && mode != "ordered" {
				return ComponentResult{Valid: false, ActionDigest: ""}
			}
			required := 0
			if n, ok := toFloat(policy["required"]); ok && n == float64(int(n)) {
				required = int(n)
			}
			eligible, _ := policy["approvers"].([]any)
			distinct, _ := policy["distinct_humans"].(bool)
			orderedChain, _ := policy["ordered_chain"].(bool)
			if required < 2 || required > len(eligible) || !distinct || (mode == "ordered" && !orderedChain) {
				return ComponentResult{Valid: false, ActionDigest: ""}
			}
			presentedPolicy := getMap(m["policy"])
			if presentedPolicy == nil || Canonicalize(presentedPolicy) != Canonicalize(policy) {
				return ComponentResult{Valid: false, ActionDigest: ""}
			}
			for _, mr := range membersRaw {
				mm, _ := mr.(map[string]any)
				if mm == nil {
					return ComponentResult{Valid: false, ActionDigest: ""}
				}
				k, _ := mm["approver_public_key"].(string)
				entry := getMap(approvers[k])
				signoff := getMap(mm["signoff"])
				signedCtx := getMap(signoff["context"])
				roles, _ := entry["roles"].([]any)
				roleAllowed := false
				for _, r := range roles {
					if rs, _ := r.(string); rs != "" && rs == getStr(mm, "role") {
						roleAllowed = true
					}
				}
				if k == "" || !aecActiveDirectoryEntry(entry, getStr(ctx, "verificationTime")) || signedCtx == nil || getStr(entry, "public_key") != k ||
					getStr(entry, "approver_id") == "" || getStr(entry, "approver_id") != getStr(signedCtx, "approver") ||
					!roleAllowed || getStr(signedCtx, "policy") != contextPolicy ||
					!allowedOrigins[aecWebAuthnOrigin(getMap(signoff["webauthn"]))] ||
					!aecFreshAt(signedCtx, getStr(ctx, "verificationTime"), maxAge) {
					return ComponentResult{Valid: false, ActionDigest: ""}
				}
			}
			originList := make([]string, 0, len(allowedOrigins))
			for origin := range allowedOrigins {
				originList = append(originList, origin)
			}
			r := VerifyQuorumWithOrigins(m, rpID, originList)
			if !r.Valid {
				return ComponentResult{Valid: false, ActionDigest: ""}
			}
			ad, _ := m["action_hash"].(string)
			return ComponentResult{Valid: true, ActionDigest: ad}
		},
		"ep-receipt": func(ev any, ctx map[string]any) ComponentResult {
			m, _ := ev.(map[string]any)
			profiles, _ := ctx["policiesByType"].(map[string]any)
			profile := getMap(profiles["ep-receipt"])
			allowedOrigins := aecAllowedOrigins(profile)
			approverKeys := getMap(profile["approver_keys"])
			logPublicKey := getStr(profile, "log_public_key")
			rpID := getStr(profile, "rp_id")
			expectedPolicy := aecNormDigest(profile["expected_policy_hash"])
			maxAge := profile["max_age_sec"]
			contexts, _ := m["contexts"].([]any)
			signoffs, _ := m["signoffs"].([]any)
			if m == nil || profile == nil || approverKeys == nil || allowedOrigins == nil || logPublicKey == "" || rpID == "" || expectedPolicy == "" || !aecMaxAgeValid(maxAge) || !aecFreshRegistrySnapshot(profile, getStr(ctx, "verificationTime")) || len(contexts) == 0 || len(signoffs) == 0 {
				return ComponentResult{Valid: false}
			}

			contextByHash := map[string]map[string]any{}
			for _, raw := range contexts {
				receiptContext := getMap(raw)
				if receiptContext == nil || aecNormDigest(receiptContext["policy_hash"]) != expectedPolicy {
					return ComponentResult{Valid: false}
				}
				sum := sha256.Sum256([]byte(Canonicalize(receiptContext)))
				contextByHash[hex.EncodeToString(sum[:])] = receiptContext
			}
			expectedRPHash := sha256.Sum256([]byte(rpID))
			for _, raw := range signoffs {
				signoff := getMap(raw)
				keyEntry := getMap(approverKeys[getStr(signoff, "approver_key_id")])
				signedContext := contextByHash[aecNormDigest(signoff["context_hash"])]
				webauthn := getMap(signoff["webauthn"])
				authData, err := b64urlDecode(getStr(webauthn, "authenticator_data"))
				if signoff == nil || !aecActiveDirectoryEntry(keyEntry, getStr(ctx, "verificationTime")) || getStr(keyEntry, "key_class") != "A" || signedContext == nil ||
					getStr(keyEntry, "approver_id") != getStr(signedContext, "approver") || err != nil || len(authData) < 37 ||
					!bytes.Equal(authData[:32], expectedRPHash[:]) || !allowedOrigins[aecWebAuthnOrigin(webauthn)] ||
					!aecFreshAt(signedContext, getStr(ctx, "verificationTime"), maxAge) {
					return ComponentResult{Valid: false}
				}
			}

			originList := make([]string, 0, len(allowedOrigins))
			for origin := range allowedOrigins {
				originList = append(originList, origin)
			}
			r := VerifyTrustReceipt(m, map[string]any{
				"approverKeys":   approverKeys,
				"logPublicKey":   logPublicKey,
				"rpId":           rpID,
				"allowedOrigins": originList,
			})
			if !r.Valid {
				return ComponentResult{Valid: false}
			}
			return ComponentResult{Valid: true, ActionDigest: getStr(m, "action_hash")}
		},
	}
}

func aecIdentChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '_' || c == '.' || c == ':' || c == '-'
}

// AEC -08 requirement expressions (evaluator EP-AEC-EVALUATOR-08-v1).
//
// Mirrors compileAecRequirementExpression in packages/verify/src/evidence-chain.ts:
// the lexer takes the LONGEST identifier run and only then classifies it (a
// complete run of exactly AND or OR is an operator; every other run, such as
// "and", "Or" or "aORb", is an identifier); only SP, HTAB, CR and LF are
// whitespace; operators group left to right with equal precedence; the caps
// are 4096 UTF-8 octets, 256 tokens (identifiers, operators and parentheses
// all count) and 32 levels of nesting. Refusal order: length, then the lexer
// left to right, then the parser left to right. One parse produces one tree;
// the canonical parse, parse identity and Boolean value all come from it. The
// parse identity is an interpretation diagnostic: a matching identity does not
// guarantee a matching verdict.

// AECExpressionParseDomain separates the parse identity hash.
const AECExpressionParseDomain = "EP-AEC-EXPRESSION-PARSE-v1"

type aecExprToken struct {
	kind string // "id", "op", "(", ")"
	text string
}

type aecExprNode struct {
	ident       string
	op          string // "" for an identifier, otherwise AND or OR
	left, right *aecExprNode
}

type aecExprRefusal struct{ class, detail string }

func aecIsExprWS(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// aecHasExpressionContent reports whether s holds a byte other than SP, HTAB, CR, LF.
func aecHasExpressionContent(s string) bool {
	for i := 0; i < len(s); i++ {
		if !aecIsExprWS(s[i]) {
			return true
		}
	}
	return false
}

func aecLexExpression(s string) ([]aecExprToken, *aecExprRefusal) {
	if len(s) > aecMaxRequirementLength {
		return nil, &aecExprRefusal{"limit", "length_limit"}
	}
	var toks []aecExprToken
	i := 0
	for i < len(s) {
		c := s[i]
		if aecIsExprWS(c) {
			i++
			continue
		}
		if c == '(' || c == ')' {
			toks = append(toks, aecExprToken{string(c), string(c)})
			i++
		} else if (c == '&' || c == '|') && i+1 < len(s) && s[i+1] == c {
			op := "AND"
			if c == '|' {
				op = "OR"
			}
			toks = append(toks, aecExprToken{"op", op})
			i += 2
		} else if aecIdentChar(c) {
			j := i + 1
			for j < len(s) && aecIdentChar(s[j]) {
				j++
			}
			run := s[i:j]
			if run == "AND" || run == "OR" {
				toks = append(toks, aecExprToken{"op", run})
			} else {
				toks = append(toks, aecExprToken{"id", run})
			}
			i = j
		} else {
			return nil, &aecExprRefusal{"syntax", "invalid_character"}
		}
		if len(toks) > aecMaxRequirementTokens {
			return nil, &aecExprRefusal{"limit", "token_limit"}
		}
	}
	if len(toks) == 0 {
		return nil, &aecExprRefusal{"syntax", "empty"}
	}
	return toks, nil
}

func aecParseExpression(s string) (*aecExprNode, int, *aecExprRefusal) {
	toks, refusal := aecLexExpression(s)
	if refusal != nil {
		return nil, 0, refusal
	}
	i := 0
	var parseExpr func(int) (*aecExprNode, *aecExprRefusal)
	var parseTerm func(int) (*aecExprNode, *aecExprRefusal)
	parseTerm = func(depth int) (*aecExprNode, *aecExprRefusal) {
		if i >= len(toks) {
			return nil, &aecExprRefusal{"syntax", "unexpected_end"}
		}
		t := toks[i]
		if t.kind == "(" {
			i++
			inner, r := parseExpr(depth + 1)
			if r != nil {
				return nil, r
			}
			if i >= len(toks) {
				return nil, &aecExprRefusal{"syntax", "unclosed_group"}
			}
			if toks[i].kind != ")" {
				return nil, &aecExprRefusal{"syntax", "unexpected_token"}
			}
			i++
			return inner, nil
		}
		if t.kind != "id" {
			return nil, &aecExprRefusal{"syntax", "unexpected_token"}
		}
		i++
		return &aecExprNode{ident: t.text}, nil
	}
	parseExpr = func(depth int) (*aecExprNode, *aecExprRefusal) {
		if depth > aecMaxRequirementDepth {
			return nil, &aecExprRefusal{"limit", "depth_limit"}
		}
		node, r := parseTerm(depth)
		if r != nil {
			return nil, r
		}
		for i < len(toks) && toks[i].kind == "op" {
			op := toks[i].text
			i++
			right, rr := parseTerm(depth)
			if rr != nil {
				return nil, rr
			}
			node = &aecExprNode{op: op, left: node, right: right}
		}
		return node, nil
	}
	tree, r := parseExpr(0)
	if r != nil {
		return nil, 0, r
	}
	if i != len(toks) {
		return nil, 0, &aecExprRefusal{"syntax", "trailing_input"}
	}
	return tree, len(toks), nil
}

func aecRenderExpression(n *aecExprNode) string {
	if n.op == "" {
		return n.ident
	}
	return "(" + aecRenderExpression(n.left) + " " + n.op + " " + aecRenderExpression(n.right) + ")"
}

func aecParseIdentity(canonical string) string {
	h := sha256.New()
	h.Write([]byte(AECExpressionParseDomain))
	h.Write([]byte{0})
	h.Write([]byte(canonical))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func aecEvalExpressionTree(n *aecExprNode, eligible map[string]bool) bool {
	if n.op == "" {
		return eligible[n.ident]
	}
	left := aecEvalExpressionTree(n.left, eligible)
	right := aecEvalExpressionTree(n.right, eligible)
	if n.op == "AND" {
		return left && right
	}
	return left || right
}

// AECExpressionEvaluation keeps syntax validity apart from truth. Value,
// CanonicalParse and ParseIdentity are nil for an invalid expression.
type AECExpressionEvaluation struct {
	Syntax         string  `json:"syntax"`
	InvalidClass   *string `json:"invalid_class"`
	Value          *bool   `json:"value"`
	Result         string  `json:"result"`
	CanonicalParse *string `json:"canonical_parse"`
	ParseIdentity  *string `json:"parse_identity"`
}

// AECCompiledExpression is one parse of a requirement expression; Evaluate
// reads only that tree.
type AECCompiledExpression struct {
	Valid          bool
	InvalidClass   string
	Detail         string
	TokenCount     int
	CanonicalParse string
	ParseIdentity  string
	tree           *aecExprNode
}

// CompileAECRequirementExpression parses once and exposes the tree's
// diagnostics. Expression agreement with the JS reference is not conformance
// to the structured -07/-08 requirement and replay contract, which this
// package does not implement.
func CompileAECRequirementExpression(expr string) AECCompiledExpression {
	tree, count, refusal := aecParseExpression(expr)
	if refusal != nil {
		return AECCompiledExpression{InvalidClass: refusal.class, Detail: refusal.detail}
	}
	canonical := aecRenderExpression(tree)
	return AECCompiledExpression{Valid: true, TokenCount: count, CanonicalParse: canonical,
		ParseIdentity: aecParseIdentity(canonical), tree: tree}
}

// Evaluate computes the Boolean value of the compiled tree over the eligible types.
func (c AECCompiledExpression) Evaluate(eligible map[string]bool) AECExpressionEvaluation {
	if !c.Valid || c.tree == nil {
		class := c.InvalidClass
		if class == "" {
			class = "syntax"
		}
		return AECExpressionEvaluation{Syntax: "INVALID", InvalidClass: &class, Result: "UNSATISFIED"}
	}
	value := aecEvalExpressionTree(c.tree, eligible)
	result := "UNSATISFIED"
	if value {
		result = "SATISFIED"
	}
	canonical, identity := c.CanonicalParse, c.ParseIdentity
	return AECExpressionEvaluation{Syntax: "VALID", Value: &value, Result: result,
		CanonicalParse: &canonical, ParseIdentity: &identity}
}

// EvaluateAECRequirementExpression compiles once, then evaluates that tree.
func EvaluateAECRequirementExpression(expr string, eligibleTypes []string) AECExpressionEvaluation {
	eligible := make(map[string]bool, len(eligibleTypes))
	for _, t := range eligibleTypes {
		eligible[t] = true
	}
	return CompileAECRequirementExpression(expr).Evaluate(eligible)
}

func callAECVerifier(v ComponentVerifier, evidence any, ctx map[string]any) (result ComponentResult) {
	defer func() {
		if recover() != nil {
			result = ComponentResult{Valid: false}
		}
	}()
	return v(evidence, ctx)
}

// VerifyAuthorizationChain verifies an EP-AEC chain offline, fail-closed.
//
// TRUST BOUNDARY: the chain document's "requirement" is PRESENTER-supplied — a
// claim of what the bundle satisfies, never the relying party's bar. A pinned
// relying-party requirement is mandatory before Satisfied can be true.
// keysByType is retained for source compatibility and custom verifiers. Built-in
// human acceptance uses AECOptions.PoliciesByType: ep-receipt requires a Class-A
// Trust Receipt profile; ep-quorum requires an exact quorum profile.
func VerifyAuthorizationChain(aec map[string]any, verifiers map[string]ComponentVerifier, keysByType map[string]map[string]string, relyingPartyRequirement ...string) AECResult {
	opts := AECOptions{}
	if len(relyingPartyRequirement) > 0 {
		opts.Requirement = relyingPartyRequirement[0]
	}
	if len(relyingPartyRequirement) > 1 {
		opts.ExpectedActionDigest = relyingPartyRequirement[1]
	}
	return VerifyAuthorizationChainWithOptions(aec, verifiers, keysByType, opts)
}

// VerifyAuthorizationChainWithOptions is the profile-aware AEC verifier.
func VerifyAuthorizationChainWithOptions(aec map[string]any, verifiers map[string]ComponentVerifier, keysByType map[string]map[string]string, opts AECOptions) AECResult {
	// Only SP, HTAB, CR and LF are expression whitespace (AEC -08). A pinned
	// requirement is evaluated exactly as supplied, never trimmed: trimming
	// Unicode spaces here once let "\u00a0a" evaluate as "a".
	pinned := ""
	if aecHasExpressionContent(opts.Requirement) {
		pinned = opts.Requirement
	}
	policiesByType := opts.PoliciesByType
	res := AECResult{RequirementSource: "presenter"}
	if pinned != "" {
		res.RequirementSource = "relying_party"
	}
	fail := func(why string) AECResult {
		res.Satisfied = false
		res.Allow = false
		res.Reasons = append(res.Reasons, why)
		return res
	}
	if aec == nil {
		return fail("chain is not an object")
	}
	if !aecBoundedJSON(aec) {
		return fail("chain exceeds the canonical JSON safety profile or resource limits")
	}
	if v, _ := aec["@version"].(string); v != AECVersion {
		return fail("unexpected @version")
	}
	action, ok := aec["action"].(map[string]any)
	if !ok {
		return fail("missing action object")
	}
	compsIn, ok := aec["components"].([]any)
	if !ok || len(compsIn) == 0 {
		return fail("no components")
	}
	if len(compsIn) > aecMaxComponents {
		return fail(fmt.Sprintf("too many components (maximum %d)", aecMaxComponents))
	}
	req, reqOk := aec["requirement"].(string)
	if pinned != "" {
		req = pinned
	} else if !reqOk || !aecHasExpressionContent(req) {
		return fail("missing requirement expression")
	}
	if len(req) > aecMaxRequirementLength {
		return fail("requirement expression exceeds size limit")
	}
	// Parse once, before component work; the verdict is computed on this tree.
	compiledRequirement := CompileAECRequirementExpression(req)
	chainDigest := ActionDigest(action)
	res.ActionDigest = chainDigest
	expectedDigest := ""
	if opts.ExpectedActionDigest != "" {
		expectedDigest = aecNormDigest(opts.ExpectedActionDigest)
		if expectedDigest == "" {
			return fail("expected action digest is malformed")
		}
		if expectedDigest != chainDigest {
			return fail("chain action does not match the relying-party expected action")
		}
		res.ExpectedActionBound = true
	}
	if ad, present := aec["action_digest"]; present && ad != nil {
		if aecNormDigest(ad) != chainDigest {
			return fail("declared action_digest does not match canonical digest of the action")
		}
	}
	vmap := builtinAECVerifiers()
	for k, v := range verifiers {
		if k != "ep-quorum" && k != "ep-receipt" && v != nil {
			vmap[k] = v
		}
	}
	satisfied := map[string]bool{}
	for idx, ci := range compsIn {
		c, ok := ci.(map[string]any)
		if !ok || c == nil {
			res.Components = append(res.Components, AECComponentRow{Label: fmt.Sprintf("#%d", idx), Reason: "component is not an object"})
			continue
		}
		typ, _ := c["type"].(string)
		label, _ := c["label"].(string)
		if label == "" {
			if typ != "" {
				label = typ
			} else {
				label = fmt.Sprintf("#%d", idx)
			}
		}
		row := AECComponentRow{Type: typ, Label: label}
		if typ == "" || len(typ) > 128 || !aecIdent.MatchString(typ) || getMap(c["evidence"]) == nil {
			row.Reason = "component type or evidence is malformed"
			res.Components = append(res.Components, row)
			continue
		}
		v, has := vmap[typ]
		if !has {
			row.Reason = fmt.Sprintf("no verifier registered for type %q", typ)
			res.Components = append(res.Components, row)
			continue
		}
		cr := callAECVerifier(v, c["evidence"], map[string]any{"action": action, "keysByType": keysByType, "policiesByType": policiesByType, "verificationTime": opts.VerificationTime})
		row.Valid = cr.Valid
		row.Bound = aecNormDigest(cr.ActionDigest) == chainDigest
		if !row.Valid {
			row.Reason = "component evidence did not verify"
		} else if !row.Bound {
			row.Reason = "component binds a DIFFERENT action than the chain"
		}
		if row.Valid && row.Bound {
			satisfied[typ] = true
			// Presenter-controlled labels are display metadata only.
		}
		res.Components = append(res.Components, row)
	}
	evaluated := compiledRequirement.Evaluate(satisfied)
	expressionValid := evaluated.Syntax == "VALID"
	value := expressionValid && *evaluated.Value
	res.Satisfied = pinned != "" && expectedDigest != "" && expressionValid && value
	res.Allow = res.Satisfied
	if !expressionValid {
		res.Reasons = append(res.Reasons, "requirement expression is malformed or exceeds parser limits")
	} else if !value {
		res.Reasons = append(res.Reasons, fmt.Sprintf("requirement not satisfied: %q", req))
	}
	if pinned == "" {
		res.Reasons = append(res.Reasons, "presenter requirement is descriptive only; relying-party requirement is required for satisfaction")
	}
	if expectedDigest == "" {
		res.Reasons = append(res.Reasons, "relying-party expected action is required for satisfaction")
	}
	if pinned != "" && reqOk {
		if presenter := aec["requirement"].(string); aecHasExpressionContent(presenter) && presenter != pinned {
			res.Reasons = append(res.Reasons, fmt.Sprintf("presenter requirement ignored in favor of relying-party requirement (presenter claimed: %q)", presenter))
		}
	}
	return res
}
