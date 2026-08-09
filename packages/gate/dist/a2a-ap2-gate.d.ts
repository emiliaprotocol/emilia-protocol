/**
 * Experimental A2A/AP2 consequence-admission profile.
 *
 * A2A carries the authorization interruption and AE-CHALLENGE. AP2 remains
 * native evidence verified by a relying-party-pinned AP2 adapter. AEB joins
 * every required evidence leg to one executor-derived CAID. Gate claims the
 * issued challenge and atomically reserves the evaluation, native replay
 * identities, and A2A task before the credential-owning actuator may enter the
 * provider.
 *
 * The request supplies only the A2A task, signed AEB evaluation, and native
 * artifacts. Expected action, status, local policy, time, and execution
 * envelope are executor-owned dependencies and cannot be selected by a
 * presenter.
 */
import { type AebAdapter, type AebDurableConsumptionStore, type AebEvaluationRecord, type AebPinnedConfig, type AebStatusInput } from '@emilia-protocol/verify/aeb-adapter-contract';
import { type ConsequenceActuator, type ConsequenceActuatorExecutionInput } from './consequence-actuator.js';
export declare const A2A_AP2_GATE_PROFILE_VERSION = "EP-A2A-AP2-GATE-EXPERIMENTAL-v1";
export interface A2AAp2ChallengeStore {
    readonly durable: true;
    readonly atomicRegistration: true;
    readonly bodyBound: true;
    readonly permanentConsumption: true;
    /** Atomically consumes an exact, previously registered challenge body. */
    consume(challenge: unknown): Promise<boolean>;
}
export interface A2AAp2ResolvedAction {
    expected_action: unknown;
    expected_caid: string;
}
export interface A2AAp2ResolutionContext {
    task_id: string;
    context_id: string;
    evaluation: AebEvaluationRecord;
    artifacts: Readonly<Record<string, unknown>>;
}
export interface A2AAp2GateOptions<TResult> {
    aeb_config: AebPinnedConfig;
    adapters: Record<string, AebAdapter>;
    aeb_store: AebDurableConsumptionStore;
    challenge_store: A2AAp2ChallengeStore;
    actuator: ConsequenceActuator<TResult>;
    now(): string;
    resolve_action(input: Readonly<{
        task_id: string;
        context_id: string;
    }>): Promise<A2AAp2ResolvedAction> | A2AAp2ResolvedAction;
    resolve_current_statuses(input: Readonly<A2AAp2ResolutionContext>): Promise<Record<string, AebStatusInput>> | Record<string, AebStatusInput>;
    authorize_local(input: Readonly<A2AAp2ResolutionContext & A2AAp2ResolvedAction>): Promise<boolean> | boolean;
    resolve_execution(input: Readonly<A2AAp2ResolutionContext & A2AAp2ResolvedAction>): Promise<ConsequenceActuatorExecutionInput> | ConsequenceActuatorExecutionInput;
}
export interface A2AAp2GateExecutionInput {
    task: unknown;
    evaluation: unknown;
    /** Native artifacts keyed by the exact artifact_ref in the signed AEB record. */
    artifacts: Record<string, unknown>;
}
export interface A2AAp2NativeAuthorizationScope {
    protocol: 'AP2';
    artifact_refs: readonly string[];
    emilia_originated: false;
}
interface DecisionBase {
    profile: typeof A2A_AP2_GATE_PROFILE_VERSION;
    invoked: boolean;
    retry_allowed: boolean;
    reason: string;
    native_authorization: A2AAp2NativeAuthorizationScope;
    aeb_reservation_key?: string;
}
export type A2AAp2GateDecision<TResult> = (DecisionBase & {
    state: 'ADMIT';
    invoked: true;
    retry_allowed: false;
    result: TResult;
}) | (DecisionBase & {
    state: 'REFUSE';
    invoked: false;
}) | (DecisionBase & {
    state: 'INDETERMINATE';
    retry_allowed: false;
});
export declare class A2AAp2Gate<TResult = unknown> {
    #private;
    constructor(options: A2AAp2GateOptions<TResult>);
    execute(input: A2AAp2GateExecutionInput): Promise<A2AAp2GateDecision<TResult>>;
}
export declare function a2aAp2ReservationKey(record: AebEvaluationRecord): string;
export {};
//# sourceMappingURL=a2a-ap2-gate.d.ts.map