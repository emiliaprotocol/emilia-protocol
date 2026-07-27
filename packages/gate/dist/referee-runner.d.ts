/**
 * Bounded subprocess transport for EMILIA protocol Referee runners.
 *
 * The caller pins an absolute executable, its SHA-256 byte digest, and the
 * complete argument vector.  The child receives only a closed JSON request on
 * stdin and must return one closed JSON output on stdout.  This is a bounded,
 * no-shell subprocess self-test harness; it is not an OS sandbox and does not
 * claim to confine a hostile executable's filesystem or network access.
 */
import { type RefereeResultV1, type RefereeRunnerOutputV1, type RefereeRunnerPinV1, type RefereeRunnerRequestV1 } from './referee.js';
export declare const REFEREE_RUNNER_MAX_INPUT_BYTES: number;
export declare const REFEREE_RUNNER_MAX_OUTPUT_BYTES: number;
export declare const REFEREE_RUNNER_MAX_TIMEOUT_MS = 300000;
export type RefereeRunnerFailureCode = 'ABORTED' | 'INPUT_TOO_LARGE' | 'OUTPUT_TOO_LARGE' | 'TIMEOUT' | 'EXECUTABLE_DIGEST_MISMATCH' | 'SPAWN_FAILED' | 'NONZERO_EXIT' | 'MALFORMED_OUTPUT' | 'INVALID_OUTPUT_SCHEMA';
export interface RefereeRunnerInvocationV1 {
    readonly runner_pin: RefereeRunnerPinV1;
    readonly request: RefereeRunnerRequestV1;
    readonly timeout_ms: number;
}
export interface RefereeRunnerOptions {
    readonly signal?: AbortSignal;
}
export type RefereeRunnerExecutionResult = Readonly<{
    ok: true;
    output: Readonly<RefereeRunnerOutputV1>;
}> | Readonly<{
    ok: false;
    code: RefereeRunnerFailureCode;
}>;
export declare function parseRefereeRunnerInvocation(value: unknown): Readonly<RefereeRunnerInvocationV1>;
/** Execute a caller-pinned protocol runner without shell or ambient config. */
export declare function runPinnedProtocolRunner(value: unknown, rawOptions?: unknown): Promise<RefereeRunnerExecutionResult>;
/** Execute and evaluate one self-test, mapping every runner failure to no-claim. */
export declare function runReferee(value: unknown, rawOptions?: unknown): Promise<Readonly<RefereeResultV1>>;
//# sourceMappingURL=referee-runner.d.ts.map