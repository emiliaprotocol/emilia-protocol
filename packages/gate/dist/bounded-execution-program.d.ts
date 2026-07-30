/**
 * Signed, closed execution programs for bounded autonomous action.
 *
 * This module owns immutable program syntax and verification only. Runtime
 * reachability and attempt-budget transitions are enforced by a program-aware
 * AdmissionStore in the same linearizable execution-right domain.
 */
import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
export declare const BOUNDED_EXECUTION_PROGRAM_VERSION = "EP-BOUNDED-EXECUTION-PROGRAM-v1";
export declare const EXECUTION_PROGRAM_CLAIM_BOUNDARY = "typed_reachability_and_attempt_budget_not_intent_safety_effect_truth_or_complete_mediation";
export declare const EXECUTION_PROGRAM_LIMITS: Readonly<{
    budgets: 64;
    nodes: 256;
    dependenciesPerNode: 64;
    chargesPerNode: 64;
    maxOccurrences: 1000000;
    maxTotalOccurrences: 1000000;
    maxBudget: number;
}>;
export type ExecutionProgramTerminalOutcome = 'COMMITTED' | 'PROVEN_NOT_COMMITTED';
export interface ExecutionProgramBudget {
    budget_id: string;
    unit: string;
    limit: number;
}
export type ExecutionProgramAction = {
    mode: 'exact';
    caid: string;
    action_digest: string;
} | {
    mode: 'profile';
    profile_id: string;
    profile_digest: string;
};
export interface ExecutionProgramDependency {
    node_id: string;
    outcomes: ExecutionProgramTerminalOutcome[];
}
export interface ExecutionProgramCharge {
    budget_id: string;
    amount: number;
}
export interface ExecutionProgramNode {
    node_id: string;
    action: ExecutionProgramAction;
    trust_program_digest: string;
    depends_on: ExecutionProgramDependency[];
    max_occurrences: number;
    charges: ExecutionProgramCharge[];
}
export interface BoundedExecutionProgramInput {
    program_id: string;
    tenant_id: string;
    version: number;
    subject_id: string;
    audience: string;
    objective_digest: string;
    authorization_digest: string;
    presentation_digest: string;
    supersedes_program_digest: string | null;
    issued_at: string;
    valid_from: string;
    expires_at: string;
    max_total_occurrences: number;
    budgets: ExecutionProgramBudget[];
    nodes: ExecutionProgramNode[];
}
export interface ExecutionProgramVerificationOptions {
    trusted_keys?: TrustedRiskKeys;
    now?: string | number;
    expected_program_id?: string;
    expected_tenant_id?: string;
    expected_authorizer_id?: string;
    expected_authorization_digest?: string;
    expected_audience?: string;
}
export interface VerifiedBoundedExecutionProgram extends BoundedExecutionProgramInput {
    '@version': typeof BOUNDED_EXECUTION_PROGRAM_VERSION;
    claim_boundary: typeof EXECUTION_PROGRAM_CLAIM_BOUNDARY;
}
export declare function signBoundedExecutionProgram(input: BoundedExecutionProgramInput | RiskRecord, signer: {
    issuer_id: string;
    key_id: string;
    private_key: any;
}): RiskRecord;
export declare function executionProgramDigest(artifact: unknown): string;
export declare function verifyBoundedExecutionProgram(artifact: unknown, options?: ExecutionProgramVerificationOptions): {
    accepted: boolean;
    verified: boolean;
    reason: string;
    program_digest: string | null;
    program: null;
    claim_boundary: string;
} | {
    accepted: boolean;
    verified: boolean;
    reason: null;
    program_digest: string;
    program: Readonly<VerifiedBoundedExecutionProgram>;
    authorizer_id: any;
    claim_boundary: string;
};
//# sourceMappingURL=bounded-execution-program.d.ts.map