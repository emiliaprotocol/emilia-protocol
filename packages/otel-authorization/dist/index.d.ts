/**
 * @emilia-protocol/otel-authorization
 *
 * Build the `gen_ai.tool.authorization.*` attribute map for an OpenTelemetry
 * `execute_tool` span from a runtime's own approval decision, and set it on a
 * span.
 *
 * Scope, stated plainly and not more:
 *
 *   - This module produces SPAN ATTRIBUTES. Attributes are an observation the
 *     producer makes about its own decision. They are not an authorization, not
 *     a verification, and not evidence. A consumer that reads
 *     `authorization.status = auto_approved` learns what the producer said, not
 *     what is true.
 *   - `evidence.grade` is the producer's own classification of the evidence it
 *     holds. Nothing in the telemetry path checks it. It exists so that a
 *     self-attested span LOOKS self-attested to the backend that indexes it.
 *   - `evidence.digest`, `action.digest` and `policy.digest` are opaque
 *     references. No payload, no prompt, no argument object, no policy body and
 *     no approver identity is carried by this group.
 *
 * Dependencies: none. The module never imports `@opentelemetry/api` statically.
 * `setToolAuthorizationAttributes` accepts any object exposing the OTel `Span`
 * `setAttributes(map)` (or `setAttribute(k, v)`) surface, so an application that
 * already has `@opentelemetry/api` passes its active span in and an application
 * that does not passes its own recorder or nothing at all.
 *
 * Fail-closed behaviour: malformed input returns a refusal
 * (`{ ok: false, reason }`) naming the reason, and the span is left untouched.
 * It does not throw and it does not emit a partial or guessed attribute map.
 * A wrong authorization status on a span is worse than no status.
 */
export declare const OTEL_TOOL_AUTHORIZATION_VERSION: "EMILIA-OTEL-TOOL-AUTHORIZATION-v0.1";
/**
 * Per-action authorization status. The first six values are the per-action
 * authorization-status vocabulary carried into this group from the insurance
 * taxonomy work; the last three are the decision outcomes a boolean approval
 * slot can honestly produce. See CROSSWALK.md for the mapping onto the shipped
 * `standards/aiuc/incident-fields-v0` enum, which uses different value names.
 */
export declare const TOOL_AUTHORIZATION_STATUS: Readonly<{
    /** A human authorization step ran and the executed action is inside its scope. */
    AUTHORIZED_IN_SCOPE: "authorized_in_scope";
    /** A human authorization step ran, but the executed action falls outside what was authorized. */
    AUTHORIZED_OUT_OF_SCOPE: "authorized_out_of_scope";
    /** A human authorized the action without holding the standing authority to do so. */
    AUTHORIZED_WITHOUT_STANDING: "authorized_without_standing";
    /** No per-action step ran; the call proceeded under a prior standing grant. */
    STANDING_PREAUTHORIZATION: "standing_preauthorization";
    /** No authorization step existed for this call at all. */
    NO_AUTHORIZATION_STEP: "no_authorization_step";
    /** An authorization step existed and the call reached execution without completing it. */
    STEP_BYPASSED: "step_bypassed";
    /** A non-human rule allowed the call; no human saw it. */
    AUTO_APPROVED: "auto_approved";
    /** The call was refused before execution. */
    REJECTED: "rejected";
    /** A human changed the arguments and authorized the changed call. */
    EDITED_THEN_APPROVED: "edited_then_approved";
}>;
export declare const TOOL_AUTHORIZATION_STATUS_VALUES: readonly string[];
/**
 * Producer-asserted class of the evidence behind the status.
 *
 *   self_attested            the emitting runtime asserts the decision; there is
 *                            no artifact another party can re-check.
 *   third_party_logged       a party other than the emitting runtime recorded the
 *                            decision and the record is retrievable by reference;
 *                            re-reading it requires trusting that party's store.
 *   independently_verifiable the producer names a digest, a format and a locator
 *                            for an artifact a party other than the producer can
 *                            check on its own, without trusting the producer's
 *                            runtime or storage.
 *
 * The grade is a claim. The telemetry pipeline does not verify it.
 */
export declare const EVIDENCE_GRADE: Readonly<{
    SELF_ATTESTED: "self_attested";
    THIRD_PARTY_LOGGED: "third_party_logged";
    INDEPENDENTLY_VERIFIABLE: "independently_verifiable";
}>;
export declare const EVIDENCE_GRADE_VALUES: readonly string[];
/** Registry attribute names, as proposed upstream. */
export declare const REGISTRY_ATTRIBUTE_KEYS: Readonly<{
    status: "gen_ai.tool.authorization.status";
    evidenceGrade: "gen_ai.tool.authorization.evidence.grade";
    evidenceDigest: "gen_ai.tool.authorization.evidence.digest";
    evidenceFormat: "gen_ai.tool.authorization.evidence.format";
    evidenceLocator: "gen_ai.tool.authorization.evidence.locator";
    actionDigest: "gen_ai.tool.authorization.action.digest";
    policyDigest: "gen_ai.tool.authorization.policy.digest";
}>;
/**
 * Vendor-prefixed fallback names, used until (and unless) the group is accepted
 * upstream. An attribute outside the registry is invisible to every consumer
 * that has not been told about it, so the default is the fallback namespace and
 * the registry names are opt-in.
 */
export declare const FALLBACK_ATTRIBUTE_KEYS: Readonly<{
    status: "emilia.tool.authorization.status";
    evidenceGrade: "emilia.tool.authorization.evidence.grade";
    evidenceDigest: "emilia.tool.authorization.evidence.digest";
    evidenceFormat: "emilia.tool.authorization.evidence.format";
    evidenceLocator: "emilia.tool.authorization.evidence.locator";
    actionDigest: "emilia.tool.authorization.action.digest";
    policyDigest: "emilia.tool.authorization.policy.digest";
}>;
export type AttributeNamespace = 'registry' | 'fallback' | 'both';
export interface ToolAuthorizationInput {
    status: string;
    evidence_grade: string;
    evidence_digest?: string | null;
    evidence_format?: string | null;
    evidence_locator?: string | null;
    action_digest?: string | null;
    policy_digest?: string | null;
}
export interface ToolAuthorizationAttributes {
    [key: string]: string;
}
export type BuildResult = {
    ok: true;
    attributes: ToolAuthorizationAttributes;
    namespace: AttributeNamespace;
} | {
    ok: false;
    reason: string;
};
export interface BuildOptions {
    /** Which attribute namespace to emit. Defaults to 'fallback'. */
    namespace?: AttributeNamespace;
}
/**
 * Build the attribute map for one tool call.
 *
 * Returns a refusal, never a partial map, when:
 *   - the input is not an object;
 *   - `status` is not one of the nine registered values;
 *   - `evidence_grade` is not one of the three registered values;
 *   - any supplied reference is not a short, printable, single-line token;
 *   - `evidence_digest` or `action_digest` is not a recognisable digest or CAID;
 *   - `evidence_grade` is `independently_verifiable` without the digest, format
 *     and locator that make the artifact checkable by someone else. A grade
 *     above self_attested with nothing to check is the claim this group exists
 *     to prevent, so it is refused rather than downgraded.
 */
export declare function buildToolAuthorizationAttributes(input: unknown, options?: BuildOptions): BuildResult;
/** The minimum of the OpenTelemetry `Span` surface this module uses. */
export interface SpanLike {
    setAttributes?: (attributes: Record<string, unknown>) => unknown;
    setAttribute?: (key: string, value: unknown) => unknown;
}
export type SetResult = {
    ok: true;
    attributes: ToolAuthorizationAttributes;
    written: boolean;
} | {
    ok: false;
    reason: string;
};
/**
 * Set the attribute map on a span-like object.
 *
 * `span` may be null or undefined: the attributes are still built and validated
 * and returned with `written: false`, so a caller with no tracer configured gets
 * the same refusal behaviour as one that has. A span that throws from
 * `setAttributes` is treated as a telemetry failure, never as an authorization
 * failure: the refusal is returned and the caller's control flow is unchanged.
 */
export declare function setToolAuthorizationAttributes(span: SpanLike | null | undefined, input: unknown, options?: BuildOptions): SetResult;
/**
 * Resolve the currently active OpenTelemetry span WITHOUT taking a dependency on
 * `@opentelemetry/api`. If the package is not installed, or the caller is not
 * inside a span, this returns null and emission becomes a no-op.
 *
 * `@opentelemetry/api` is an optional peer of this package. It is not in
 * `dependencies` and is not installed in this repository.
 */
export declare function resolveActiveSpan(): Promise<SpanLike | null>;
export interface MapperEvidence {
    evidence_digest?: string | null;
    evidence_format?: string | null;
    evidence_locator?: string | null;
    action_digest?: string | null;
    policy_digest?: string | null;
}
export type MapResult = {
    ok: true;
    input: ToolAuthorizationInput;
} | {
    ok: false;
    reason: string;
};
/**
 * OpenAI Agents SDK. The runtime's own slot is a boolean: `needsApproval` marks
 * the tool, `state.approve(item)` / `state.reject(item)` resolves it, and no
 * approver, signature or scope travels with either call.
 *
 * `decision` is what the adapter did:
 *   'approve'            -> a valid action-bound receipt was consumed
 *   'reject'             -> refused, with a reason
 *   'approve_no_receipt' -> the host approved without EMILIA in the path
 *
 * `receiptBound` says whether an action-bound authorization artifact backed the
 * approval. Without one, the honest status is auto_approved at self_attested,
 * because the boolean cannot say who approved or what they saw.
 */
export declare function mapOpenAIAgentsDecision(decision: unknown, evidence?: MapperEvidence): MapResult;
/**
 * LangGraph `HumanInTheLoopMiddleware` interrupt responses, as the EMILIA
 * adapter resolves them. This runtime is the one of the four whose slot is
 * richer than a boolean: it distinguishes accept from edit, which is the only
 * place `edited_then_approved` can be produced honestly.
 *
 * `decision` is the adapter's own `resolve()` outcome, `responseType` the
 * LangGraph response type ('accept' | 'edit' | 'ignore' | 'response').
 */
export declare function mapLangGraphDecision(decision: unknown, responseType: unknown, evidence?: MapperEvidence): MapResult;
/**
 * LangChain tool wrapper. The slot is a boolean: the wrapped tool either runs or
 * refuses. `allowed` true with an action-bound receipt is authorized_in_scope;
 * `allowed` true without one is auto_approved at self_attested; false is
 * rejected.
 */
export declare function mapLangChainDecision(allowed: unknown, receiptBound: unknown, evidence?: MapperEvidence): MapResult;
/**
 * MCP guard. `GUARD_DECISIONS` are allow | allow_with_signoff | deny, and the
 * guard additionally knows whether the call was classified irreversible.
 *
 *   allow on an irreversible tool with no receipt  -> no_authorization_step
 *   allow on a reversible tool                     -> auto_approved
 *   allow_with_signoff, receipt consumed           -> authorized_in_scope
 *   allow_with_signoff, no receipt presented       -> step_bypassed
 *   deny                                           -> rejected
 */
export declare function mapMcpGuardDecision(guardDecision: unknown, facts: unknown, evidence?: MapperEvidence): MapResult;
/**
 * Claude Code PreToolUse hook. Its slot is a three-valued permissionDecision
 * ('allow' | 'deny' | 'ask') and the EMILIA hook never emits 'allow': on a
 * matched high-risk call it emits 'ask' or 'deny'.
 *
 * 'ask' is not an authorization outcome. The hook has deferred the decision to a
 * human who has not answered yet, so there is no status to report for the call
 * and the mapper refuses rather than guessing. That refusal is deliberate: a
 * pending step recorded as auto_approved would be the exact false negative this
 * group exists to make visible.
 */
export declare function mapClaudeCodeHookDecision(permissionDecision: unknown, evidence?: MapperEvidence): MapResult;
export interface TelemetryOptions {
    /** Turn emission off entirely. Default true. */
    enabled?: boolean;
    /** An explicit span to write to. */
    span?: SpanLike | null;
    /** Resolve a span per call, given the adapter's context object. */
    spanFor?: (context: any) => SpanLike | null | undefined;
    /**
     * Fall back to the active `@opentelemetry/api` span when neither `span` nor
     * `spanFor` yields one. Default true; a no-op when the package is absent.
     */
    useActiveSpan?: boolean;
    /** 'registry' | 'fallback' | 'both'. Default 'fallback'. */
    namespace?: AttributeNamespace;
    /** Observe every emission, including refusals. Never affects control flow. */
    onEmit?: (result: SetResult, context: any) => void;
}
/**
 * Emit one mapped decision, honouring the caller's telemetry options.
 *
 * This never throws and never changes an adapter's authorization outcome. A
 * refusal from the mapper or the builder is reported through `onEmit` and
 * returned; the adapter keeps whatever decision it already made.
 */
export declare function emitToolAuthorization(telemetry: TelemetryOptions | null | undefined, mapped: MapResult, context?: any): Promise<SetResult>;
declare const otelAuthorizationExports: {
    OTEL_TOOL_AUTHORIZATION_VERSION: "EMILIA-OTEL-TOOL-AUTHORIZATION-v0.1";
    TOOL_AUTHORIZATION_STATUS: Readonly<{
        /** A human authorization step ran and the executed action is inside its scope. */
        AUTHORIZED_IN_SCOPE: "authorized_in_scope";
        /** A human authorization step ran, but the executed action falls outside what was authorized. */
        AUTHORIZED_OUT_OF_SCOPE: "authorized_out_of_scope";
        /** A human authorized the action without holding the standing authority to do so. */
        AUTHORIZED_WITHOUT_STANDING: "authorized_without_standing";
        /** No per-action step ran; the call proceeded under a prior standing grant. */
        STANDING_PREAUTHORIZATION: "standing_preauthorization";
        /** No authorization step existed for this call at all. */
        NO_AUTHORIZATION_STEP: "no_authorization_step";
        /** An authorization step existed and the call reached execution without completing it. */
        STEP_BYPASSED: "step_bypassed";
        /** A non-human rule allowed the call; no human saw it. */
        AUTO_APPROVED: "auto_approved";
        /** The call was refused before execution. */
        REJECTED: "rejected";
        /** A human changed the arguments and authorized the changed call. */
        EDITED_THEN_APPROVED: "edited_then_approved";
    }>;
    TOOL_AUTHORIZATION_STATUS_VALUES: readonly string[];
    EVIDENCE_GRADE: Readonly<{
        SELF_ATTESTED: "self_attested";
        THIRD_PARTY_LOGGED: "third_party_logged";
        INDEPENDENTLY_VERIFIABLE: "independently_verifiable";
    }>;
    EVIDENCE_GRADE_VALUES: readonly string[];
    REGISTRY_ATTRIBUTE_KEYS: Readonly<{
        status: "gen_ai.tool.authorization.status";
        evidenceGrade: "gen_ai.tool.authorization.evidence.grade";
        evidenceDigest: "gen_ai.tool.authorization.evidence.digest";
        evidenceFormat: "gen_ai.tool.authorization.evidence.format";
        evidenceLocator: "gen_ai.tool.authorization.evidence.locator";
        actionDigest: "gen_ai.tool.authorization.action.digest";
        policyDigest: "gen_ai.tool.authorization.policy.digest";
    }>;
    FALLBACK_ATTRIBUTE_KEYS: Readonly<{
        status: "emilia.tool.authorization.status";
        evidenceGrade: "emilia.tool.authorization.evidence.grade";
        evidenceDigest: "emilia.tool.authorization.evidence.digest";
        evidenceFormat: "emilia.tool.authorization.evidence.format";
        evidenceLocator: "emilia.tool.authorization.evidence.locator";
        actionDigest: "emilia.tool.authorization.action.digest";
        policyDigest: "emilia.tool.authorization.policy.digest";
    }>;
    buildToolAuthorizationAttributes: typeof buildToolAuthorizationAttributes;
    setToolAuthorizationAttributes: typeof setToolAuthorizationAttributes;
    resolveActiveSpan: typeof resolveActiveSpan;
    mapOpenAIAgentsDecision: typeof mapOpenAIAgentsDecision;
    mapLangGraphDecision: typeof mapLangGraphDecision;
    mapLangChainDecision: typeof mapLangChainDecision;
    mapMcpGuardDecision: typeof mapMcpGuardDecision;
    mapClaudeCodeHookDecision: typeof mapClaudeCodeHookDecision;
    emitToolAuthorization: typeof emitToolAuthorization;
};
export default otelAuthorizationExports;
//# sourceMappingURL=index.d.ts.map