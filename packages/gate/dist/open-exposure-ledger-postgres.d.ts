/**
 * Deployment-bound PostgreSQL adapter for the Open Exposure Ledger.
 *
 * Each mutation is one PostgreSQL function call. Authentication is the
 * PostgreSQL session principal plus its private tenant/authority mapping; the
 * application credential field is deliberately never serialized to SQL.
 */
import { type OpenExposureLedger } from './open-exposure-ledger.js';
export interface OpenExposurePostgresQueryResult {
    rowCount: number;
    rows?: Array<Record<string, unknown>>;
}
export type OpenExposurePostgresQuery = (text: string, params: readonly unknown[]) => Promise<OpenExposurePostgresQueryResult>;
export interface CreateOpenExposurePostgresLedgerOptions {
    query: OpenExposurePostgresQuery;
    tenantId: string;
}
export interface OpenExposurePostgresLedger extends OpenExposureLedger {
    readonly durable: true;
    readonly deploymentBound: true;
    readonly singleTenant: true;
    readonly authentication: 'postgres_session_principal';
}
export declare const OPEN_EXPOSURE_POSTGRES_SQL: Readonly<{
    registerCeiling: "SELECT open_exposure_private.register_ceiling($1::jsonb) AS result";
    reserve: "SELECT open_exposure_private.reserve($1::jsonb) AS result";
    beginInvocation: "SELECT open_exposure_private.begin_invocation($1::jsonb) AS result";
    markIndeterminate: "SELECT open_exposure_private.mark_indeterminate($1::jsonb) AS result";
    reconcile: "SELECT open_exposure_private.reconcile($1::jsonb) AS result";
    read: "SELECT open_exposure_private.read_exposure($1::jsonb) AS result";
    history: "SELECT open_exposure_private.read_history($1::jsonb) AS result";
    sumOpen: "SELECT open_exposure_private.sum_open($1::jsonb) AS result";
    listAging: "SELECT open_exposure_private.list_aging($1::jsonb) AS result";
    listDeadlines: "SELECT open_exposure_private.list_deadlines($1::jsonb) AS result";
}>;
export declare class OpenExposurePostgresProtocolError extends Error {
    constructor(message: string, options?: ErrorOptions);
}
export declare function createOpenExposurePostgresLedger(options: CreateOpenExposurePostgresLedgerOptions): OpenExposurePostgresLedger;
//# sourceMappingURL=open-exposure-ledger-postgres.d.ts.map