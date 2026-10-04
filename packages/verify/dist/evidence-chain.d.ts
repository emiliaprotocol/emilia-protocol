import { verifyAuthorizationBundle } from './authorization-bundle.js';
type Obj = Record<string, any>;
export declare const AEC_VERSION = "EP-AEC-v1";
declare function isRecord(v: any): boolean;
declare function own(obj: any, key: string): boolean;
declare function sha256hex(s: string): string;
/** Canonical action digest (hex). NOTE: uses EP's canonicalize(); see the JCS
 *  conformance note in the spec — the shared substrate MUST be true RFC 8785. */
export declare function actionDigest(action: any): string;
/** Normalize a digest claim to bare lowercase hex (strip any "sha256:" prefix). */
declare function normDigest(d: any): string | null;
declare function strictInstantMs(value: any): number;
declare function freshAt(context: any, verificationTime: any, maxAgeSec: any): boolean;
declare function freshRegistrySnapshot(profile: any, verificationTime: any): boolean;
declare function activeDirectoryEntry(entry: any, verificationTime: any): boolean;
declare function allowedOriginSet(profile: any): Set<string> | null;
declare function webauthnOrigin(webauthn: any): string | null;
declare function validUnicodeString(value: any): boolean;
declare function boundedJson(value: any): boolean;
/**
 * Built-in component verifiers. Each takes (evidence, ctx) and returns
 * { valid: boolean, action_digest: string|null, detail?: any }.
 * `action_digest` is the digest the component ITSELF attests it authorized — the
 * chain then checks every component's attested digest equals the chain's digest.
 */
declare function builtinVerifiers(): Obj;
/**
 * Requirement expressions (AEC -08, evaluator EP-AEC-EVALUATOR-08-v1).
 *
 * Case-sensitive grammar (RFC 5234 with RFC 7405 %s literals):
 *   expression = *WSP term *( *WSP operator *WSP term ) *WSP
 *   term       = "(" *WSP expression *WSP ")" / identifier
 *   operator   = %s"AND" / %s"OR" / "&&" / "||"
 *   identifier = 1*( ALPHA / DIGIT / "_" / "." / ":" / "-" )
 *   WSP        = SP / HTAB / CR / LF
 *
 * Token boundaries: the lexer takes the LONGEST run of identifier characters
 * and only then classifies the complete run. A run that is exactly AND or OR
 * is an operator; every other run, including `and`, `Or`, `aORb` and `ORb`,
 * is an identifier. Identifiers are case-sensitive. AND and OR are reserved
 * only inside expressions; they stay valid native component types.
 *
 * Operators have equal precedence and group left to right:
 * `a OR b AND c` is `((a OR b) AND c)`.
 *
 * Validity is separate from truth. A syntactically valid identifier naming no
 * eligible component type is false. Malformed syntax or an exceeded limit makes
 * the expression INVALID. Both evaluate UNSATISFIED; diagnostics keep them
 * apart. The whole input is lexed and parsed before any value is computed, so
 * short-circuiting can never skip a syntax or limit check.
 *
 * Fixed caps (part of the evaluator revision, not relying-party configurable):
 * 4096 UTF-8 octets, 256 tokens (identifiers, operators and parentheses all
 * count), 32 levels of parenthesis nesting. Refusal order is deterministic:
 * the length cap, then the lexer left to right (an invalid character is a
 * syntax refusal; the 257th token is a limit refusal), then the parser left
 * to right (nesting beyond 32 is a limit refusal; anything else a syntax one).
 *
 * One parser produces one tree. The canonical parse, the parse identity and
 * the Boolean value are all computed from that tree; nothing re-reads the
 * expression text with its own grouping rules.
 */
export declare const AEC_EXPRESSION_LIMITS: Readonly<{
    maxOctets: 4096;
    maxTokens: 256;
    maxDepth: 32;
}>;
/** Domain separator of the parse identity: SHA-256 over this ASCII string, one
 * 0x00 octet, then the ASCII canonical parse. */
export declare const AEC_EXPRESSION_PARSE_DOMAIN = "EP-AEC-EXPRESSION-PARSE-v1";
export type AecExpressionNode = {
    readonly kind: 'identifier';
    readonly name: string;
} | {
    readonly kind: 'operator';
    readonly operator: 'AND' | 'OR';
    readonly left: AecExpressionNode;
    readonly right: AecExpressionNode;
};
type AecExpressionToken = {
    kind: 'identifier';
    text: string;
} | {
    kind: 'operator';
    operator: 'AND' | 'OR';
    text: string;
} | {
    kind: '(' | ')';
    text: string;
};
export type AecExpressionInvalidClass = 'syntax' | 'limit';
type AecExpressionRefusal = {
    ok: false;
    invalid_class: AecExpressionInvalidClass;
    detail: string;
};
type AecLexResult = {
    ok: true;
    tokens: AecExpressionToken[];
} | AecExpressionRefusal;
type AecParseResult = {
    ok: true;
    tree: AecExpressionNode;
    token_count: number;
} | AecExpressionRefusal;
/** UTF-8 octet length. A lone surrogate counts as the three octets of the
 * replacement character a UTF-8 encoder substitutes for it. */
declare function utf8Octets(value: string): number;
declare function lexAecExpression(expression: unknown): AecLexResult;
declare function parseAecExpression(expression: unknown): AecParseResult;
/** Fully parenthesized ASCII rendering of the tree: every operator node is
 * `(` left SP AND|OR SP right `)`, `&&` and `||` render as AND and OR,
 * identifiers keep their exact case, source parentheses that do not change
 * grouping disappear, and operands are never commuted or reassociated. */
declare function renderAecExpression(node: AecExpressionNode): string;
declare function aecParseIdentity(canonical: string): string;
/** Evaluate the parsed tree. Only an exact, case-sensitive type match counts. */
declare function evaluateAecExpressionTree(node: AecExpressionNode, eligible: ReadonlySet<string>): boolean;
export interface AecExpressionEvaluation {
    syntax: 'VALID' | 'INVALID';
    invalid_class: AecExpressionInvalidClass | null;
    value: boolean | null;
    result: 'SATISFIED' | 'UNSATISFIED';
    canonical_parse: string | null;
    parse_identity: string | null;
}
export interface AecCompiledExpression {
    readonly valid: boolean;
    readonly invalid_class: AecExpressionInvalidClass | null;
    /** Finer refusal label for humans (e.g. `trailing_input`); not portable. */
    readonly detail: string | null;
    readonly token_count: number | null;
    readonly canonical_parse: string | null;
    readonly parse_identity: string | null;
    /** Evaluate THIS compilation's tree over a set of eligible component types. */
    evaluate(eligibleTypes: Iterable<string>): AecExpressionEvaluation;
}
/**
 * Parse a requirement expression once and expose the tree's diagnostics.
 *
 * The parse identity names how this implementation grouped the expression.
 * It is an interpretation diagnostic, not an authorization result: two
 * evaluators that report the same parse identity can still return different
 * answers (one can mis-evaluate an operator, case-fold a role lookup, or credit
 * evidence that failed native verification). It is never carried in the v1
 * requirement or replay objects, and it does not replace the requirement
 * profile digest, which commits to the expression exactly as stored.
 */
export declare function compileAecRequirementExpression(expression: unknown): AecCompiledExpression;
/** Convenience diagnostic: compile once, then evaluate that tree. */
export declare function evaluateAecRequirementExpression(expression: unknown, eligibleTypes: Iterable<string>): AecExpressionEvaluation;
declare function tokenizeRequirement(expr: any): string[] | null;
declare function evalRequirement(expr: string | AecCompiledExpression, satisfied: Set<string>): Obj;
/** Public fail-closed boundary. Parsed JSON is the intended wire input, but
 * framework callers can still supply proxies/getters that throw during shape
 * inspection. No host-language exception may turn verification into a crash.
 * @param {object} aec
 * @param {{requirement?:string, [key:string]:any}} [opts]
 */
export declare function verifyAuthorizationChain(aec: Obj, opts?: Obj): Obj;
export declare const AEC_REQUIREMENT_VERSION = "EP-AEC-REQUIREMENT-v1";
export declare const AEC_REPLAY_VERSION = "EP-AEC-REPLAY-v1";
export declare const AEC_EVALUATOR_REVISION = "EP-AEC-EVALUATOR-08-v1";
/** Revisions this evaluator has replaced. A record carrying one is reported
 * UNSUPPORTED_REVISION by replay(); it is never relabeled or compared as -08. */
export declare const AEC_SUPERSEDED_EVALUATOR_REVISIONS: readonly string[];
export declare const AEC_BUNDLE_COMPONENT = "ep-authorization-bundle";
export interface AecRequirement {
    '@version': typeof AEC_REQUIREMENT_VERSION;
    requirement_id: string;
    purpose?: string;
    expression: string;
    freshness_sec?: Record<string, number>;
    status_required?: string[];
    role_constraints?: Array<{
        type: 'distinct-subject-quorum';
        component_type: string;
        threshold: number;
        subject_id_source: 'native-verifier';
    }>;
    required_bindings?: Array<{
        from_type: string;
        relation: string;
        to_type: string;
    }>;
}
export interface AecNativeBinding {
    relation: string;
    target_evidence_digest: string;
}
export interface AecNativeStatus {
    authenticated: boolean;
    status: 'active' | 'revoked' | 'unknown';
    snapshot_digest: string;
    checked_at: string;
    expires_at: string;
}
/** A native verifier reports two separate results (AEC-07 Section 6):
 *
 *   verified  the artifact's cryptographic and structural checks passed under
 *             the verification key (carried by the artifact, or resolved from
 *             relying-party key material when the format names it only by
 *             reference);
 *   accepted  the relying party's pinned trust inputs for this component type
 *             (trust anchors or key directory entry status, issuer, audience,
 *             key class, native policy, validity at the verification time)
 *             accept that VERIFIED artifact.
 *
 * `verified: null` means VERIFIED could not be evaluated: no verification key
 * could be resolved from relying-party key material (reason `key_unresolved`),
 * or the relying party's own configuration for the format is unusable. The
 * fact then records native_verification NOT_EVALUATED, never FAILED, so an
 * unknown signer is not recorded the way a forgery is.
 *
 * `accepted: true` with `verified` other than true is refused as
 * inconsistent. A verifier that evaluated the checks but cannot tell which of
 * the two results a failure belongs to reports `verified: false`; it never
 * reports VERIFIED for bytes it did not check. The 5.x single `valid` Boolean
 * is refused by name (`native_result_legacy_valid_field`), because it cannot
 * say which result it carries.
 *
 * Every positive field must come from verified native bytes or the native
 * profile's authenticated status input, never from an unverified wrapper.
 * An absent claim stays absent: AEC does not infer subjects from signer keys,
 * current status from an issuer signature, or human operation from identity.
 */
export interface AecNativeVerification {
    verified: boolean | null;
    accepted: boolean;
    reason?: string;
    format_revision?: string;
    action_digest?: string | null;
    native_payload?: unknown;
    issued_at?: string | null;
    expires_at?: string | null;
    issuer?: string | null;
    audience?: string | string[] | null;
    subject_ids?: string[];
    bindings?: AecNativeBinding[];
    status?: AecNativeStatus | null;
}
export interface AecNativeContext {
    readonly action: Readonly<Obj>;
    readonly expected_action_digest: string;
    readonly expected_caid: string | null;
    readonly verification_time: string;
    readonly profile: Readonly<Obj>;
    readonly trust_snapshot: Readonly<Obj>;
    readonly signal: AbortSignal;
}
export interface AecNativeVerifierRegistration {
    profile: {
        id: string;
        revision: string;
        native_format_revision: string;
        [key: string]: unknown;
    };
    trustSnapshot: Obj;
    verify?: (evidence: unknown, context: AecNativeContext) => AecNativeVerification | Promise<AecNativeVerification>;
    mapping?: {
        profile: Obj;
        map: (native: Readonly<AecNativeVerification>, context: AecNativeContext) => {
            verdict: 'EQUIVALENT_UNDER_PROFILE' | 'NOT_EQUIVALENT' | 'INDETERMINATE';
            caid: string | null;
        } | Promise<{
            verdict: 'EQUIVALENT_UNDER_PROFILE' | 'NOT_EQUIVALENT' | 'INDETERMINATE';
            caid: string | null;
        }>;
    };
    statusMaxAgeSec?: number;
    /** Only the native Bundle profile's named cryptographic hooks are accepted.
     * They are captured at construction, not received with a presentation. */
    bundleHooks?: Pick<Parameters<typeof verifyAuthorizationBundle>[1], 'verifyClassASignoff' | 'verifyKeyProofs' | 'verifyPresentationEvidence'>;
}
export interface AecEvaluationLimits {
    maxDepth: number;
    maxNodes: number;
    maxStringBytes: number;
    maxWireBytes: number;
    maxComponents: number;
    maxBindings: number;
    maxSubjects: number;
    maxVerifierDurationMs: number;
}
export interface AecEvaluatorConfiguration {
    requirement: AecRequirement;
    nativeVerifiers: Record<string, AecNativeVerifierRegistration>;
    limits?: Partial<AecEvaluationLimits>;
}
export interface AecEvaluationInputs {
    expectedAction?: Obj;
    expectedActionDigest?: string;
    expectedCaid?: string;
    verificationTime: string;
}
export interface AecReplayRecord {
    '@version': typeof AEC_REPLAY_VERSION;
    algorithm_revision: typeof AEC_EVALUATOR_REVISION;
    evaluator_profile_digest: string;
    aec_digest: string | null;
    expected_action_digest: string | null;
    expected_caid: string | null;
    requirement_profile_digest: string;
    verification_time: string | null;
    facts: Obj[];
    satisfied: boolean;
    reasons: string[];
}
export interface AecEvaluationResult {
    satisfied: boolean;
    allow: boolean;
    authorization_decision: false;
    requirement_source: 'relying_party';
    replay: AecReplayRecord;
    replay_digest: string;
    reasons: string[];
}
/** The component types a requirement expression may count: exactly the facts
 * marked eligible (VERIFIED, ACCEPTED, MATCH or EQUIVALENT_UNDER_PROFILE, and
 * every freshness and status condition met). A FAILED, REJECTED or
 * NOT_EVALUATED fact is never eligible. */
declare function eligibleFactTypes(facts: readonly Obj[]): Set<string>;
/** Constructor-owned trust boundary for the structured current profile.
 * Callbacks are trusted native implementations, not code supplied by the
 * presentation. Input/work count is bounded and asynchronous work has an abort
 * deadline. Synchronous hostile code cannot be preempted by this process: host
 * untrusted verifier code in a worker/process with its own execution deadline.
 * A callback exceeding the deadline is refused even if it eventually returns.
 */
export declare function createAuthorizationChainEvaluator(configuration: AecEvaluatorConfiguration): Readonly<{
    requirement_profile_digest: string;
    evaluator_profile_digest: string;
    /** Interpretation diagnostic for the pinned expression, computed from the
     * one tree evaluation uses. Not part of any wire object, and a matching
     * parse identity does not guarantee a matching verdict. */
    requirement_expression: Readonly<{
        canonical_parse: string;
        parse_identity: string;
        token_count: number;
    }>;
    evaluate: (input: unknown, acceptance: AecEvaluationInputs) => Promise<AecEvaluationResult>;
    /** Reverify original evidence under this constructor's pins. A presenter
     * cannot turn serialized facts or a previously true Boolean into evidence.
     *
     * Migration: only a record made by this evaluator revision is compared, and
     * the comparison is over the complete record digest. A record from any
     * other revision (a stored -07 record, say) is reported
     * UNSUPPORTED_REVISION: it is not relabeled, its digest is not recomputed
     * under -08, and `matches` is false. `result` is always a fresh
     * evaluation under this revision, a new and separately identified record. */
    replay(chain: unknown, recorded: unknown, inputs: AecEvaluationInputs): Promise<Readonly<{
        matches: boolean;
        comparison: "MATCH" | "MISMATCH" | "UNSUPPORTED_REVISION" | "RECORD_INVALID";
        recorded_revision: string | null;
        claimed_replay_digest: string | null;
        result: AecEvaluationResult;
    }>>;
}>;
export declare const __aecSecurityInternals: Readonly<{
    builtinVerifiers: typeof builtinVerifiers;
    isRecord: typeof isRecord;
    own: typeof own;
    sha256hex: typeof sha256hex;
    normDigest: typeof normDigest;
    strictInstantMs: typeof strictInstantMs;
    freshAt: typeof freshAt;
    freshRegistrySnapshot: typeof freshRegistrySnapshot;
    activeDirectoryEntry: typeof activeDirectoryEntry;
    allowedOriginSet: typeof allowedOriginSet;
    webauthnOrigin: typeof webauthnOrigin;
    validUnicodeString: typeof validUnicodeString;
    boundedJson: typeof boundedJson;
    tokenizeRequirement: typeof tokenizeRequirement;
    evalRequirement: typeof evalRequirement;
    lexAecExpression: typeof lexAecExpression;
    parseAecExpression: typeof parseAecExpression;
    renderAecExpression: typeof renderAecExpression;
    aecParseIdentity: typeof aecParseIdentity;
    evaluateAecExpressionTree: typeof evaluateAecExpressionTree;
    eligibleFactTypes: typeof eligibleFactTypes;
    utf8Octets: typeof utf8Octets;
}>;
export {};
//# sourceMappingURL=evidence-chain.d.ts.map