/**
 * EP-AGENT-EDGE-CONTINUITY-v1.
 *
 * A relying-party-pinned provenance and action-lineage profile for carrying
 * one material action across user, harness, model, tool, agent, and effect
 * boundaries. It contributes evidence to AEB; it never creates authority.
 */
import { type KeyObject } from 'node:crypto';
import { type AebConsumptionStore, type AebDigest, type AebEvaluationRecord, type AebEvaluationVerification, type AebExecutionDecision } from './aeb-adapter-contract.js';
import { type AgileSignature, type AgileSigningKey, type AgilityOptions } from './pq-signature-agility.js';
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
    aeb_verification: Pick<AebEvaluationVerification, 'valid' | 'execution_authorizing' | 'record_digest'>;
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
/**
 * REFERENCE-DERIVED HYBRID MIGRATION. Copies, move for move, the reference
 * hybrid migration documented in docs/protocol/pq-hybrid-program.md, section
 * "PATTERN: the reference hybrid migration" (EP-REVOCATION-v2 in
 * packages/verify/src/revocation.ts). The five moves, applied to the
 * continuity envelope:
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second signature changes the SHAPE of
 *    the proof, a wire-format change, so the envelope takes a new `@type`
 *    (EP-AGENT-EDGE-CONTINUITY-v1 -> -v2) rather than growing an optional
 *    field. verifyAgentContinuityEnvelope() above is untouched and refuses a
 *    v2 envelope on `shapeReasons()`'s `@type` check (`invalid_type`) before
 *    it inspects any signature, and it never throws.
 * 2. SET SHAPE. The single `signature` object is replaced by `proof`, carrying
 *    `required_algorithms` plus a `signatures` array shaped exactly like
 *    EP-SIG-AGILITY-v1's AgileSignature ({ alg, sig, key_id? }), one entry per
 *    algorithm in the registered order.
 * 3. ANTI-STRIPPING BYTES. The required algorithm SET is committed INSIDE the
 *    signed bytes (continuityV2SigningBytes below). Drop the ML-DSA leg and
 *    narrow `required_algorithms` and the surviving Ed25519 signature no
 *    longer verifies, because the bytes changed.
 * 4. V1 COMPATIBILITY. v1 envelopes keep verifying, unchanged, through
 *    verifyAgentContinuityEnvelope. v2 verification is ASYNC (ML-DSA
 *    verification is async), so it is a SEPARATE entry point;
 *    verifyAgentContinuityEnvelopeAny() routes on `@type` for callers holding
 *    a mixed bag. The v1 verifier is never made async.
 * 5. NAMED REFUSALS. Every failure path pushes a readable reason string;
 *    nothing throws on caller input. An absent ML-DSA backend is a refusal
 *    surfaced through the agility result, never a skipped check and never a
 *    pass on the classical leg alone.
 *
 * SCOPE BOUNDARY (honest, not a hedge): this migration covers the single
 * envelope signature only (verifyAgentContinuityEnvelopeV2), the cryptographic
 * surface a PQ adversary can attack. verifyAgentContinuityGraph/
 * authorizeAgentContinuityExecution and their durable twin remain v1-only
 * here; a graph made of v2 envelopes still needs its per-envelope signature
 * checked through verifyAgentContinuityEnvelopeV2 (or the Any router) by the
 * caller before folding the result into a v1-shaped graph/execution decision.
 * Unlike v1, signer_pins carries BOTH key halves per signer; a pin providing
 * only one half fails verification, never a silent single-leg pass.
 *
 * HONEST BOUNDARIES carry over from v1: continuity contributes evidence, never
 * authority. The ML-DSA backend is @noble/post-quantum's pure-JS FIPS 204
 * implementation, not independently audited and not a FIPS validated module.
 * v2 does NOT retroactively protect envelopes already issued under v1.
 */
export declare const AGENT_CONTINUITY_V2_VERSION = "EP-AGENT-EDGE-CONTINUITY-v2";
export declare const AGENT_CONTINUITY_V2_DOMAIN = "EP-AGENT-EDGE-CONTINUITY-v2\0";
/** The registered required algorithm set, in canonical order. */
export declare const AGENT_CONTINUITY_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface AgentContinuityV2Proof {
    profile: typeof AGENT_CONTINUITY_V2_VERSION;
    required_algorithms: readonly string[];
    key_id: string;
    signatures: AgileSignature[];
}
export interface AgentContinuityEnvelopeV2 extends Omit<AgentContinuityEnvelope, '@type' | 'signature'> {
    '@type': typeof AGENT_CONTINUITY_V2_VERSION;
    proof: AgentContinuityV2Proof;
}
export interface ContinuityBuildOptionsV2 extends Omit<ContinuityBuildOptions, 'signer'> {
    /** BOTH legs sign the same bytes; duplicate algorithms are refused by signAgileSet. */
    signers: AgileSigningKey[];
    proof_key_id: string;
}
/** v2 signer pin: BOTH public halves, keyed by the opaque `proof.key_id`. */
export interface ContinuitySignerPinV2 {
    public_key: string | KeyObject;
    pq_public_key: string | Uint8Array;
    status: 'active' | 'revoked';
    valid_from: string;
    valid_until: string;
    allowed_sources: readonly string[];
    allowed_edges: readonly AgentEdge[];
}
export interface ContinuityVerifyOptionsV2 extends Omit<ContinuityVerifyOptions, 'signer_pins'> {
    signer_pins: Record<string, ContinuitySignerPinV2>;
    mldsaBackend?: AgilityOptions['mldsaBackend'];
    mldsaBackendLoader?: AgilityOptions['mldsaBackendLoader'];
}
/**
 * The bytes BOTH legs sign: the same body v1 signs (everything but the
 * proof/signature field) plus the committed `required_algorithms` set, under
 * the v2 domain tag. Recomputed independently by the verifier from the
 * PRESENTED fields and the REGISTERED set.
 */
export declare function continuityV2SigningBytes(unsignedEnvelope: unknown, requiredAlgorithms?: readonly string[]): Buffer;
/** Build and sign an immutable hybrid continuity envelope. Throws on issuer misuse. */
export declare function createAgentContinuityEnvelopeV2(options: ContinuityBuildOptionsV2): Promise<AgentContinuityEnvelopeV2>;
/** Offline deterministic hybrid verification. Never throws on caller input. */
export declare function verifyAgentContinuityEnvelopeV2(value: unknown, options: ContinuityVerifyOptionsV2): Promise<ContinuityVerification>;
/**
 * Route an envelope of EITHER version to its own verifier. v1 envelopes keep
 * the exact v1 verdict (synchronous, wrapped in a resolved promise); v2
 * envelopes get the hybrid check. An envelope whose `@type` is neither
 * refuses through the v1 verifier's `invalid_type` reason.
 */
export declare function verifyAgentContinuityEnvelopeAny(value: unknown, options: ContinuityVerifyOptions | ContinuityVerifyOptionsV2): Promise<ContinuityVerification>;
export {};
//# sourceMappingURL=agent-edge-continuity.d.ts.map