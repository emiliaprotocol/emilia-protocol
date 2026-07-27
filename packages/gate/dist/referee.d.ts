/**
 * Deterministic, offline EMILIA Referee core.
 *
 * The referee does not discover trust roots, executables, protocols, policy,
 * or network state.  It evaluates one caller-pinned runner output as a
 * non-authorizing self-test claim and keeps native verification, relying-party
 * acceptance, binding, evidence composition, provider outcome, and observed
 * effect as independent facts.
 */
export declare const REFEREE_EVALUATION_VERSION = "EP-REFEREE-EVALUATION-v1";
export declare const REFEREE_RUNNER_REQUEST_VERSION = "EP-REFEREE-RUNNER-REQUEST-v1";
export declare const REFEREE_RUNNER_OUTPUT_VERSION = "EP-REFEREE-RUNNER-OUTPUT-v1";
export declare const REFEREE_RESULT_VERSION = "EP-REFEREE-RESULT-v1";
export declare const EP_REFEREE_EVALUATION_VERSION = "EP-REFEREE-EVALUATION-v1";
export declare const EP_REFEREE_RUNNER_REQUEST_VERSION = "EP-REFEREE-RUNNER-REQUEST-v1";
export declare const EP_REFEREE_RUNNER_OUTPUT_VERSION = "EP-REFEREE-RUNNER-OUTPUT-v1";
export declare const EP_REFEREE_RESULT_VERSION = "EP-REFEREE-RESULT-v1";
export type RefereeJson = null | boolean | number | string | RefereeJson[] | {
    [key: string]: RefereeJson;
};
export type RefereeStatus = 'CONFORMANT' | 'NON_CONFORMANT' | 'INDETERMINATE';
export type RefereeExecutionScope = 'local_atomic' | 'federated';
export type RefereeNativeVerification = 'VERIFIED' | 'REJECTED' | 'INDETERMINATE';
export type RefereeRpAcceptance = 'ACCEPTED' | 'REJECTED' | 'INDETERMINATE';
export type RefereeCaidActionMatch = 'MATCH' | 'MISMATCH' | 'INDETERMINATE';
export type RefereeAecSatisfaction = 'SATISFIED' | 'NOT_SATISFIED' | 'INDETERMINATE' | 'NOT_ASSESSED';
export type RefereeProviderOutcome = 'COMMITTED' | 'PROVEN_NOT_COMMITTED' | 'INDETERMINATE' | 'NOT_ASSESSED';
export type RefereeEffectRelation = 'OBSERVED_AS_REQUESTED' | 'DIVERGED' | 'INDETERMINATE' | 'NOT_ASSESSED';
export interface RefereeRunnerPinV1 {
    readonly executable: string;
    readonly executable_sha256: `sha256:${string}`;
    readonly args: readonly string[];
}
/** The only JSON document written to a protocol runner's stdin. */
export interface RefereeRunnerRequestV1 {
    readonly version: typeof REFEREE_RUNNER_REQUEST_VERSION;
    readonly case_id: string;
    readonly protocol_id: string;
    readonly expected_caid: string;
    readonly expected_action_digest: string;
    readonly aec_required: boolean;
    readonly execution_scope: RefereeExecutionScope;
    readonly input: RefereeJson;
}
/** The only accepted JSON document on a protocol runner's stdout. */
export interface RefereeRunnerOutputV1 {
    readonly version: typeof REFEREE_RUNNER_OUTPUT_VERSION;
    readonly case_id: string;
    readonly protocol_id: string;
    readonly native_verification: RefereeNativeVerification;
    readonly rp_acceptance: RefereeRpAcceptance;
    readonly caid: string | null;
    readonly action_digest: string | null;
    readonly aec_satisfaction: RefereeAecSatisfaction;
    readonly provider_outcome: RefereeProviderOutcome;
    readonly effect_relation: RefereeEffectRelation;
    readonly execution_scope: RefereeExecutionScope;
}
export interface RefereeEvaluationInputV1 {
    readonly version: typeof REFEREE_EVALUATION_VERSION;
    readonly runner_pin: RefereeRunnerPinV1;
    readonly request: RefereeRunnerRequestV1;
    readonly output: RefereeRunnerOutputV1;
}
export interface RefereeResultDimensionsV1 {
    readonly native_verification: Readonly<{
        value: RefereeNativeVerification;
    }>;
    readonly rp_acceptance: Readonly<{
        value: RefereeRpAcceptance;
    }>;
    readonly caid_action_match: Readonly<{
        value: RefereeCaidActionMatch;
        expected_caid: string;
        observed_caid: string | null;
        expected_action_digest: string;
        observed_action_digest: string | null;
    }>;
    readonly aec_satisfaction: Readonly<{
        required: boolean;
        value: RefereeAecSatisfaction;
    }>;
    readonly provider_outcome: Readonly<{
        value: RefereeProviderOutcome;
    }>;
    readonly effect_relation: Readonly<{
        value: RefereeEffectRelation;
    }>;
}
/**
 * A Referee result is evidence about one self-test only.  Its fixed false
 * execution_authorizing value is a semantic boundary, not configuration.
 */
export interface RefereeResultV1 {
    readonly version: typeof REFEREE_RESULT_VERSION;
    readonly status: RefereeStatus;
    readonly claim_scope: 'SELF_TEST';
    readonly execution_authorizing: false;
    readonly case_id: string;
    readonly protocol_id: string;
    readonly runner_pin: Readonly<RefereeRunnerPinV1>;
    readonly execution_scope: RefereeExecutionScope;
    readonly remote_atomicity_claimed: false;
    readonly dimensions: Readonly<RefereeResultDimensionsV1>;
    readonly reason_codes: readonly string[];
}
export interface RefereeIndeterminateInputV1 {
    readonly runner_pin: RefereeRunnerPinV1;
    readonly request: RefereeRunnerRequestV1;
    readonly reason_code: string;
}
export declare class RefereeValidationError extends TypeError {
    readonly code: string;
    constructor(code: string);
}
export declare function parseRefereeRunnerPin(value: unknown): Readonly<RefereeRunnerPinV1>;
export declare function parseRefereeRunnerRequest(value: unknown): Readonly<RefereeRunnerRequestV1>;
export declare function parseRefereeRunnerOutput(value: unknown): Readonly<RefereeRunnerOutputV1>;
export declare function parseRefereeEvaluationInput(value: unknown): Readonly<RefereeEvaluationInputV1>;
/** Evaluate one already-produced, caller-pinned protocol-runner output. */
export declare function evaluateReferee(value: unknown): Readonly<RefereeResultV1>;
/** Convert a bounded runner failure into an explicit no-claim result. */
export declare function createIndeterminateRefereeResult(value: RefereeIndeterminateInputV1): Readonly<RefereeResultV1>;
//# sourceMappingURL=referee.d.ts.map