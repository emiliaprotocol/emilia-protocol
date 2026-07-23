export declare const REMEDY_CASE_SET_VERSION = "EP-GATE-REMEDY-CASE-SET-v1";
export interface RemedyCaseSetState extends Record<string, unknown> {
    version: string;
    tenant_id: string;
    case_set_id: string;
    status: 'open' | 'indeterminate' | 'completed';
    revision: number;
}
export interface RemedyCaseSetResult extends Record<string, unknown> {
    ok: boolean;
    reason?: string;
    state?: RemedyCaseSetState;
}
export interface RemedyCaseSetStore {
    readonly durable: boolean;
    create(state: RemedyCaseSetState): unknown | Promise<unknown>;
    get(input: Readonly<{
        tenantId: string;
        caseSetId: string;
    }>): unknown | Promise<unknown>;
    compareAndSwap(input: Readonly<{
        tenantId: string;
        caseSetId: string;
        expectedRevision: number;
        ownerTokenDigest: string;
        state: RemedyCaseSetState;
    }>): unknown | Promise<unknown>;
}
export interface RemedyCaseSetCoordinatorOptions {
    store: RemedyCaseSetStore;
    tenantId: string;
    trustedReceiptKeys: Record<string, string>;
    expectedReceiptIssuer: {
        issuer: string;
        tenant: string;
        environment: string;
        audience: string;
        key_id: string;
    };
    now?: () => number;
}
/** Build a durable, ownership-fenced coordinator for one pinned tenant. */
export declare function createRemedyCaseSetCoordinator(options: RemedyCaseSetCoordinatorOptions): Readonly<{
    create: (input: unknown) => Promise<RemedyCaseSetResult>;
    recordChildren: (input: unknown) => Promise<RemedyCaseSetResult>;
    status: (input: unknown) => Promise<RemedyCaseSetResult>;
}>;
declare const _default: Readonly<{
    REMEDY_CASE_SET_VERSION: "EP-GATE-REMEDY-CASE-SET-v1";
    createRemedyCaseSetCoordinator: typeof createRemedyCaseSetCoordinator;
}>;
export default _default;
//# sourceMappingURL=remedy-case-set.d.ts.map