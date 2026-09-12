import { verifyAuthorizationBundle } from './authorization-bundle.js';
type Obj = Record<string, any>;
export declare const AEC_VERSION = "EP-AEC-v1";
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
 * Evaluate a tiny boolean requirement expression over the SET of verified
 * component types. Grammar (safe, no eval):
 *   expr = term *(("AND"/"OR"/"&&"/"||") term)
 *   term = "(" expr ")" / IDENT
 * IDENT matches a verified component `type`. Labels are display-only.
 */
declare function tokenizeRequirement(expr: any): any[] | null;
declare function evalRequirement(expr: any, satisfied: Set<string>): Obj;
/** Public fail-closed boundary. Parsed JSON is the intended wire input, but
 * framework callers can still supply proxies/getters that throw during shape
 * inspection. No host-language exception may turn verification into a crash.
 * @param {object} aec
 * @param {{requirement?:string, [key:string]:any}} [opts]
 */
export declare function verifyAuthorizationChain(aec: Obj, opts?: Obj): Obj;
export declare const AEC_REQUIREMENT_VERSION = "EP-AEC-REQUIREMENT-v1";
export declare const AEC_REPLAY_VERSION = "EP-AEC-REPLAY-v1";
export declare const AEC_EVALUATOR_REVISION = "EP-AEC-EVALUATOR-05-v1";
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
/** Every positive field must come from verified native bytes or the native
 * profile's authenticated status input, never from an unverified wrapper.
 * An absent claim stays absent: AEC does not infer subjects from signer keys,
 * current status from an issuer signature, or human operation from identity.
 */
export interface AecNativeVerification {
    valid: boolean;
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
    evaluate: (input: unknown, acceptance: AecEvaluationInputs) => Promise<AecEvaluationResult>;
    /** Reverify original evidence under this constructor's pins. A presenter
     * cannot turn serialized facts or a previously true Boolean into evidence. */
    replay(chain: unknown, recorded: unknown, inputs: AecEvaluationInputs): Promise<Readonly<{
        matches: boolean;
        claimed_replay_digest: string | null;
        result: AecEvaluationResult;
    }>>;
}>;
export declare const __aecSecurityInternals: Readonly<{
    builtinVerifiers: typeof builtinVerifiers;
    isRecord: (v: any) => boolean;
    own: (obj: any, key: string) => boolean;
    sha256hex: (s: string) => string;
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
}>;
export {};
//# sourceMappingURL=evidence-chain.d.ts.map