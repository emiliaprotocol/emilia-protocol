import { type AebEvaluationRecord } from './aeb-adapter-contract.js';
export declare const CROSSING_LAB_WORKSPACE_VERSION: "EMILIA-CROSSING-LAB-LOCAL-WORKSPACE-v1";
export declare const CROSSING_LAB_REPORT_VERSION: "EMILIA-CROSSING-LAB-LOCAL-REPORT-v1";
export declare const CROSSING_LAB_STATEMENT: "SELF_ATTESTED_ADAPTER_COMPATIBILITY_TEST_NOT_CERTIFICATION";
export declare const CROSSING_LAB_LIMITS: Readonly<{
    max_file_bytes: 1048576;
    max_adapter_bytes: 262144;
    max_depth: 32;
    max_nodes: 65536;
    required_file_count: 3;
    adapter_timeout_ms: 2000;
    max_adapter_output_bytes: 262144;
}>;
type Digest = `sha256:${string}`;
export type CrossingLabAxes = {
    native_verification: 'VERIFIED' | 'FAILED' | 'INDETERMINATE';
    acceptance: 'ACCEPTED' | 'REJECTED' | 'INDETERMINATE';
    mapping: 'MATCH' | 'MISMATCH' | 'INDETERMINATE';
    freshness: 'FRESH' | 'STALE' | 'UNAVAILABLE' | 'REVOKED' | 'CONSUMED' | 'INDETERMINATE';
    satisfaction: 'SATISFIED' | 'UNSATISFIED' | 'INDETERMINATE';
};
export type CrossingLabExpectationRule = 'POSITIVE_SATISFIED' | 'ACTION_SUBSTITUTION_SAFE' | 'TRUST_SUBSTITUTION_SAFE' | 'STALE_STATUS_INDETERMINATE' | 'UNAVAILABLE_STATUS_INDETERMINATE' | 'REWRAPPED_REPLAY_IDENTITY_STABLE';
export interface CrossingLabExpectation {
    rule: CrossingLabExpectationRule;
    description: string;
}
export interface CrossingLabAdapterRow {
    id: string;
    category: 'positive' | 'hostile' | 'boundary';
    passed: boolean;
    expected: CrossingLabExpectation;
    actual: CrossingLabAxes & {
        evaluation_valid: boolean;
    };
    reasons: string[];
    evaluation: AebEvaluationRecord;
}
export interface CrossingLabHarnessSelfTest {
    id: string;
    passed: boolean;
    observed: string;
}
export interface CrossingLabReport {
    '@version': typeof CROSSING_LAB_REPORT_VERSION;
    workspace_digest: Digest;
    adapter: {
        id: string;
        version: string;
        module_digest: Digest;
    };
    evaluated_at: string;
    adapter_rows: CrossingLabAdapterRow[];
    harness_self_tests: CrossingLabHarnessSelfTest[];
    summary: {
        adapter_rows: number;
        passed: number;
        failed: number;
        harness_passed: number;
        harness_failed: number;
    };
    lab_passed: boolean;
    assurance: {
        self_attested: true;
        certification: false;
        statement: typeof CROSSING_LAB_STATEMENT;
        evaluator_key_id: typeof LAB_EVALUATOR_KEY_ID;
        evaluator_key_purpose: 'PUBLIC_FIXED_SELF_TEST_KEY_NO_ATTRIBUTION';
    };
    non_claims: readonly string[];
    report_digest: Digest;
}
declare const LAB_EVALUATOR_KEY_ID = "crossing-lab:self-test";
export declare function canonicalizeCrossingLab(value: unknown): string;
export declare function digestCrossingLab(value: unknown): Digest;
export declare function runCrossingLab(workspaceDirectory: string): CrossingLabReport;
export declare function initCrossingLab(targetDirectory: string): {
    directory: string;
    files: string[];
};
/**
 * Recompute local development pins after the author deliberately edits a
 * workspace. This does not validate native semantics, trust choices, or
 * material-field selection and never executes adapter code.
 */
export declare function sealCrossingLab(workspaceDirectory: string): {
    workspace_digest: Digest;
};
export declare function writeCrossingLabReport(path: string, report: CrossingLabReport): void;
export {};
//# sourceMappingURL=crossing-lab.d.ts.map