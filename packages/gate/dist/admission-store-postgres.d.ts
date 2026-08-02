/**
 * Deployment-bound PostgreSQL Admission Store.
 *
 * Every mutation is one PostgreSQL function call.  The SQL functions use
 * explicit row locks and permanent unique fences; this adapter retries only
 * SQLSTATE 40001 (serialization failure) and 40P01 (deadlock), with the same
 * caller-generated capabilities.  It never retries an ambiguous provider
 * effect.  A lost beginInvocation acknowledgement is recovered only when an
 * authoritative read proves that this exact invocation-token digest committed.
 */
import { type AdmissionStore } from './admission-store.js';
export interface AdmissionPostgresQueryResult {
    rowCount: number;
    rows?: Array<Record<string, unknown>>;
}
export type AdmissionPostgresQuery = (text: string, params: readonly unknown[]) => Promise<AdmissionPostgresQueryResult>;
export interface CreateAdmissionPostgresStoreOptions {
    query: AdmissionPostgresQuery;
    deploymentId: string;
    tenantId: string;
    /** Test seam only. Production callers should use the cryptographic default. */
    ownerTokenFactory?: () => string;
    /** Test seam only. Production callers should use the cryptographic default. */
    invocationTokenFactory?: () => string;
    /** Number of retries after the first attempt for SQLSTATE 40001/40P01. */
    maxTransactionRetries?: number;
}
export interface AdmissionPostgresStore extends AdmissionStore {
    readonly guaranteeClass: 'local_atomic';
    readonly singleTenant: true;
    readonly deploymentBound: true;
    readonly managedTenantPrincipalMapping: false;
    readonly maxTransactionRetries: number;
}
export declare const ADMISSION_POSTGRES_SQL: Readonly<{
    reserve: "SELECT public.ep_gate_admission_reserve($1::text, $2::text, $3::jsonb, $4::text) AS result";
    release: "SELECT public.ep_gate_admission_release($1::text, $2::text, $3::text, $4::bigint, $5::text, $6::text) AS result";
    expire: "SELECT public.ep_gate_admission_expire($1::text, $2::text, $3::text, $4::bigint, $5::text) AS result";
    reapExpiredReservation: "SELECT public.ep_gate_admission_reap_expired($1::text, $2::text, $3::text, $4::bigint) AS result";
    supersede: "SELECT public.ep_gate_admission_supersede($1::text, $2::text, $3::text, $4::bigint, $5::text, $6::jsonb, $7::text) AS result";
    beginInvocation: "SELECT public.ep_gate_admission_begin_invocation($1::text, $2::text, $3::text, $4::bigint, $5::text, $6::text) AS result";
    recoverIndeterminate: "SELECT public.ep_gate_admission_recover_indeterminate($1::text, $2::text, $3::text, $4::text, $5::text) AS result";
    recordProviderOutcome: "SELECT public.ep_gate_admission_record_provider_outcome($1::text, $2::text, $3::text, $4::bigint, $5::text, $6::text, $7::text, $8::text, $9::text) AS result";
    recordEffectRelation: "SELECT public.ep_gate_admission_record_effect_relation($1::text, $2::text, $3::text, $4::bigint, $5::text, $6::text, $7::text, $8::text, $9::text) AS result";
    read: "SELECT public.ep_gate_admission_read($1::text, $2::text, $3::text) AS result";
    readByOperation: "SELECT public.ep_gate_admission_read_by_operation($1::text, $2::text, $3::text) AS result";
    readSnapshot: "SELECT public.ep_gate_admission_read_snapshot($1::text, $2::text, $3::text) AS result";
    journal: "SELECT public.ep_gate_admission_journal($1::text, $2::text, $3::text) AS result";
    checkInvariants: "SELECT public.ep_gate_admission_check_invariants($1::text, $2::text) AS result";
}>;
export declare class AdmissionPostgresProtocolError extends Error {
    constructor(message: string, options?: ErrorOptions);
}
export declare class AdmissionPostgresAmbiguousBeginError extends Error {
    readonly admissionId: string;
    constructor(admissionId: string, message: string, options?: ErrorOptions);
}
/**
 * Creates a durable single-tenant store bound to one installed deployment row.
 * The SQL deliberately has no session-user-to-tenant mapping: database access
 * is the deployment boundary and every RPC rechecks the singleton binding.
 */
export declare function createAdmissionPostgresStore(options: CreateAdmissionPostgresStoreOptions): AdmissionPostgresStore;
/** Compatibility alias following the noun-first naming used by some stores. */
export declare const createPostgresAdmissionStore: typeof createAdmissionPostgresStore;
export default createAdmissionPostgresStore;
//# sourceMappingURL=admission-store-postgres.d.ts.map