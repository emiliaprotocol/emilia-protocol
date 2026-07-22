/**
 * EMILIA Gate Remedy Program Profile v1.
 *
 * A fail-closed, post-effect compensation state machine. The kernel never
 * rewrites an already-observed effect: it verifies the original effect,
 * records disputes and late revocations, and authorizes separately bound
 * compensating operations through atomic compare-and-swap transitions.
 */
export declare const REMEDY_PROGRAM_VERSION = "EP-GATE-REMEDY-PROGRAM-PROFILE-v1";
type DataRecord = Record<string, any>;
export interface RemedyProgramState extends Record<string, unknown> {
    version: string;
    instance_id: string;
    status: string;
    revision: number;
    remedied_units: number;
    remaining_units: number;
}
export interface RemedyProgramResult extends Record<string, unknown> {
    ok: boolean;
    reason?: string;
    state?: RemedyProgramState;
}
export interface RemedyProgramStore {
    readonly durable: boolean;
    create(state: RemedyProgramState): Promise<RemedyProgramResult>;
    get(input: {
        tenantId: string;
        instanceId: string;
    }): Promise<RemedyProgramResult>;
    compareAndSwap(input: {
        tenantId: string;
        instanceId: string;
        expectedRevision: number;
        state: RemedyProgramState;
    }): Promise<RemedyProgramResult>;
}
export interface RemedyProgramKernelConfig extends Record<string, unknown> {
    store: RemedyProgramStore;
    verifyOriginalEffect: (input: Readonly<DataRecord>) => unknown | Promise<unknown>;
    verifyRevocation: (input: Readonly<DataRecord>) => unknown | Promise<unknown>;
    verifyDispute: (input: Readonly<DataRecord>) => unknown | Promise<unknown>;
    verifyRemedyAuthorization: (input: Readonly<DataRecord>) => unknown | Promise<unknown>;
    verifyRemedyOutcome: (input: Readonly<DataRecord>) => unknown | Promise<unknown>;
    verifyOriginalReconciliation: (input: Readonly<DataRecord>) => unknown | Promise<unknown>;
    verifyResolution?: (input: Readonly<DataRecord>) => unknown | Promise<unknown>;
    now?: () => number;
    maxDisputeAgeMs?: number;
    allowEphemeralState?: boolean;
    production?: boolean;
}
/**
 * In-process atomic CAS store. It is intentionally marked non-durable; callers
 * selecting production mode must provide a durable external CAS store.
 */
export declare function createRemedyMemoryStore(): RemedyProgramStore;
/** Build a remedy kernel with all trust callbacks and store methods pinned. */
export declare function createRemedyProgramKernel(options: RemedyProgramKernelConfig): Readonly<{
    create: (input: unknown) => Promise<RemedyProgramResult>;
    status: (input: unknown) => Promise<RemedyProgramResult>;
    recordRevocation: (input: unknown) => Promise<RemedyProgramResult>;
    reconcileOriginalEffect: (input: unknown) => Promise<RemedyProgramResult>;
    openDispute: (input: unknown) => Promise<RemedyProgramResult>;
    authorizeRemedy: (input: unknown) => Promise<RemedyProgramResult>;
    claimRemedy: (input: unknown) => Promise<RemedyProgramResult>;
    finalizeRemedy: (input: unknown) => Promise<RemedyProgramResult>;
    reconcileRemedy: (input: unknown) => Promise<RemedyProgramResult>;
    resolveDispute: (input: unknown) => Promise<RemedyProgramResult>;
}>;
declare const _default: {
    REMEDY_PROGRAM_VERSION: string;
    createRemedyMemoryStore: typeof createRemedyMemoryStore;
    createRemedyProgramKernel: typeof createRemedyProgramKernel;
};
export default _default;
//# sourceMappingURL=remedy-program.d.ts.map