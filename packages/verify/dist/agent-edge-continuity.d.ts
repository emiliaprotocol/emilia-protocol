/**
 * EP-AGENT-EDGE-CONTINUITY-v1.
 *
 * A relying-party-pinned provenance and action-lineage profile for carrying
 * one material action across user, harness, model, tool, agent, and effect
 * boundaries. It contributes evidence to AEB; it never creates authority.
 */
import { type KeyObject } from 'node:crypto';
import { type AebConsumptionStore, type AebDigest, type AebEvaluationRecord, type AebEvaluationVerification, type AebExecutionDecision } from './aeb-adapter-contract.js';
export declare const AGENT_CONTINUITY_VERSION = "EP-AGENT-EDGE-CONTINUITY-v1";
export declare const AGENT_CONTINUITY_DOMAIN = "EP-AGENT-EDGE-CONTINUITY-v1\0";
export type AgentEdge = 'user-harness' | 'harness-model' | 'model-harness' | 'harness-tool' | 'agent-agent' | 'effect';
export type AgentProtocol = 'native' | 'MCP' | 'A2A';
export type AgentOutcome = 'COMMITTED' | 'NOT_COMMITTED' | 'INDETERMINATE';
export interface ContinuityScope {
    action_types: readonly string[];
    resources: readonly string[];
    /** Decimal integer in the policy's smallest unit; no floating point. */
    max_amount_minor?: string;
}
export interface AgentContinuityClaims {
    /** User intent and exact rendered approval surface. */
    intent_digest?: AebDigest;
    display_digest?: AebDigest;
    /** Software provenance only; never behavioral attestation. */
    model_id?: string;
    model_version?: string;
    model_manifest_digest?: AebDigest;
    harness_digest?: AebDigest;
    prompt_context_digest?: AebDigest;
    output_digest?: AebDigest;
    /** Tool or handoff profile mapping. */
    protocol?: AgentProtocol;
    tool_id?: string;
    tool_schema_digest?: AebDigest;
    request_digest?: AebDigest;
    from_agent?: string;
    to_agent?: string;
    delegation_digest?: AebDigest;
    scope_digest?: AebDigest;
    scope?: ContinuityScope;
    /** Digests of evidence already validated by a separately pinned adapter. */
    source_identity_digest?: AebDigest;
    destination_identity_digest?: AebDigest;
    source_discovery_digest?: AebDigest;
    destination_discovery_digest?: AebDigest;
    source_attestation_digest?: AebDigest;
    destination_attestation_digest?: AebDigest;
    /** Post-effect observation. Outcome evidence never authorizes. */
    executor_id?: string;
    effect_digest?: AebDigest;
    outcome?: AgentOutcome;
}
export interface AgentContinuitySigner {
    key_id: string;
    private_key: KeyObject;
}
export interface AgentContinuitySignature {
    alg: 'Ed25519';
    key_id: string;
    value: string;
}
export interface AgentContinuityEnvelope {
    '@type': typeof AGENT_CONTINUITY_VERSION;
    continuity_id: string;
    parent_continuity_id: string | null;
    edge: AgentEdge;
    source: string;
    destination: string;
    relying_party_id: string;
    pinned_config_digest: AebDigest;
    initiator_id: string;
    executor_id: string;
    caid: string;
    action_digest: AebDigest;
    proposal_digest: AebDigest;
    operation_id: string;
    evidence_refs: readonly AebDigest[];
    claims: AgentContinuityClaims;
    sequence: number;
    issued_at: string;
    expires_at: string;
    handoff_nonce: string;
    signature: AgentContinuitySignature;
}
export interface ContinuityBuildOptions {
    parent_continuity_id: string | null;
    edge: AgentEdge;
    source: string;
    destination: string;
    relying_party_id: string;
    pinned_config_digest: AebDigest;
    initiator_id: string;
    executor_id: string;
    caid: string;
    action_digest: AebDigest;
    proposal_digest: AebDigest;
    operation_id: string;
    evidence_refs?: readonly AebDigest[];
    claims: AgentContinuityClaims;
    sequence: number;
    issued_at: string;
    expires_at: string;
    handoff_nonce: string;
    signer: AgentContinuitySigner;
}
export interface ContinuityTopologyPolicy {
    accepted_edges: readonly AgentEdge[];
    root_edges: readonly AgentEdge[];
    allowed_transitions: Partial<Record<AgentEdge, readonly AgentEdge[]>>;
    /** At least one of these must be present before execution can reserve. */
    execution_edges: readonly AgentEdge[];
    max_depth: number;
    max_validity_seconds: number;
    max_age_seconds?: number;
}
export interface ContinuitySignerPin {
    public_key: string | KeyObject;
    status: 'active' | 'revoked';
    valid_from: string;
    valid_until: string;
    allowed_sources: readonly string[];
    allowed_edges: readonly AgentEdge[];
}
export interface ContinuityVerifyOptions {
    /** Every signer is scoped by source, edge, status, and validity. */
    signer_pins: Record<string, ContinuitySignerPin>;
    topology: ContinuityTopologyPolicy;
    /** Trusted verifier clock. Execution wrappers do not accept this here. */
    now?: string;
    expected_caid?: string;
    expected_action_digest?: AebDigest;
    expected_operation_id?: string;
    expected_proposal_digest?: AebDigest;
    expected_relying_party_id?: string;
    expected_pinned_config_digest?: AebDigest;
    expected_initiator_id?: string;
    expected_executor_id?: string;
    endpoint_pins?: Record<string, {
        identity_digest?: AebDigest;
        discovery_digest?: AebDigest;
        attestation_digest?: AebDigest;
    }>;
}
export interface ContinuityVerification {
    valid: boolean;
    checks: {
        schema: boolean;
        identity: boolean;
        signature: boolean;
        signer_authority: boolean;
        time: boolean;
        expected_action: boolean;
        expected_operation: boolean;
        expected_context: boolean;
    };
    reasons: string[];
}
export interface ContinuityGraphVerification extends ContinuityVerification {
    checks: ContinuityVerification['checks'] & {
        parents: boolean;
        sequence: boolean;
        joins: boolean;
        topology: boolean;
        scope: boolean;
        replay: boolean;
    };
}
/** Build and sign an immutable continuity envelope. */
export declare function createAgentContinuityEnvelope(options: ContinuityBuildOptions): AgentContinuityEnvelope;
type ContinuityEdgeOptions = Omit<ContinuityBuildOptions, 'edge' | 'claims'>;
export declare function createUserHarnessContinuity(options: ContinuityEdgeOptions & {
    intent: unknown;
    display: unknown;
    scope?: ContinuityScope;
}): AgentContinuityEnvelope;
export declare function createHarnessModelContinuity(options: ContinuityEdgeOptions & {
    model_id: string;
    model_version: string;
    model_manifest: unknown;
    harness: unknown;
    prompt_context: unknown;
    output: unknown;
    scope?: ContinuityScope;
}): AgentContinuityEnvelope;
export declare function createMcpToolContinuity(options: ContinuityEdgeOptions & {
    tool_id: string;
    tool_schema: unknown;
    request: unknown;
    scope?: ContinuityScope;
}): AgentContinuityEnvelope;
export declare function createA2AHandoffContinuity(options: ContinuityEdgeOptions & {
    from_agent: string;
    to_agent: string;
    delegation: unknown;
    scope: ContinuityScope;
}): AgentContinuityEnvelope;
export declare function createEffectContinuity(options: ContinuityEdgeOptions & {
    executor_id: string;
    effect: unknown;
    outcome: AgentOutcome;
}): AgentContinuityEnvelope;
/** Offline deterministic verification under relying-party-pinned topology and signer authority. */
export declare function verifyAgentContinuityEnvelope(value: unknown, options: ContinuityVerifyOptions): ContinuityVerification;
/** Verify a connected cross-edge graph. Branches are allowed; every parent is pinned. */
export declare function verifyAgentContinuityGraph(values: readonly unknown[], options: ContinuityVerifyOptions): ContinuityGraphVerification;
export declare const verifyAgentContinuityChain: typeof verifyAgentContinuityGraph;
type ExecutionVerifierOptions = Omit<ContinuityVerifyOptions, 'now' | 'expected_caid' | 'expected_action_digest' | 'expected_operation_id' | 'expected_proposal_digest' | 'expected_relying_party_id' | 'expected_pinned_config_digest' | 'expected_initiator_id' | 'expected_executor_id'>;
export interface ContinuityExecutionOptions {
    continuity: readonly unknown[];
    aeb_record: AebEvaluationRecord;
    aeb_verification: Pick<AebEvaluationVerification, 'valid' | 'execution_authorizing'>;
    expected_proposal_digest: AebDigest;
    local_authorization: boolean;
    store: AebConsumptionStore;
    verifier: ExecutionVerifierOptions;
    /** Must come from the trusted Gate clock, never request data. */
    execution_now?: string;
}
export interface ContinuityExecutionDecision extends AebExecutionDecision {
    continuity: ContinuityGraphVerification;
}
/** Reference single-process path. Production callers must use the durable variant. */
export declare function authorizeAgentContinuityExecution(options: ContinuityExecutionOptions): ContinuityExecutionDecision;
export type DurableContinuityExecutionOptions = Omit<ContinuityExecutionOptions, 'store'> & {
    store: unknown;
};
/** Fleet-safe path: continuity and native replay keys reserve atomically. */
export declare function authorizeAgentContinuityExecutionDurable(options: DurableContinuityExecutionOptions): Promise<ContinuityExecutionDecision>;
export {};
//# sourceMappingURL=agent-edge-continuity.d.ts.map