/**
 * Complete-mediation boundary for provider effects.
 *
 * Gate presents a short-lived signed execution envelope. The actuator verifies
 * every binding under immutable local pins, atomically reserves the envelope,
 * and only then enters a provider callback that owns its credential. Provider
 * credentials are deliberately absent from every public type in this module.
 */
import { type KeyObject } from 'node:crypto';
export declare const CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION = "EP-CONSEQUENCE-ACTUATOR-ENVELOPE-v1";
export declare const CONSEQUENCE_ACTUATOR_SIGNATURE_ALGORITHM = "Ed25519";
export declare const CONSEQUENCE_ACTUATOR_SIGNATURE_DOMAIN = "EP-CONSEQUENCE-ACTUATOR-ENVELOPE-v1";
export declare const DEFAULT_CONSEQUENCE_ACTUATOR_MAX_TTL_MS = 60000;
export declare const DEFAULT_CONSEQUENCE_ACTUATOR_CLOCK_SKEW_MS = 2000;
export declare const CONSEQUENCE_ACTUATOR_STORE_TABLE = "public.consequence_actuator_envelopes";
export declare const CONSEQUENCE_ACTUATOR_EXECUTOR_ROLE = "consequence_actuator_executor";
export declare const CONSEQUENCE_ACTUATOR_STORE_OWNER_ROLE = "consequence_actuator_store_owner";
export declare const CONSEQUENCE_ACTUATOR_SQL: {
    reserve: string;
    consume: string;
};
type KeyMaterial = KeyObject | string | Buffer;
export interface ConsequenceExecutionEnvelopePayload {
    '@version': typeof CONSEQUENCE_ACTUATOR_ENVELOPE_VERSION;
    issuer_id: string;
    tenant_id: string;
    attempt_id: string;
    action_digest: string;
    caid: string;
    provider_account_id: string;
    target_digest: string;
    operation: string;
    idempotency_key: string;
    nonce: string;
    issued_at: string;
    expires_at: string;
}
export interface ConsequenceExecutionEnvelopeSignature {
    algorithm: typeof CONSEQUENCE_ACTUATOR_SIGNATURE_ALGORITHM;
    key_id: string;
    value: string;
}
export interface SignedConsequenceExecutionEnvelope {
    payload: ConsequenceExecutionEnvelopePayload;
    signature: ConsequenceExecutionEnvelopeSignature;
}
export interface ConsequenceActuatorPins {
    tenantId: string;
    caid: string;
    providerAccountId: string;
    targetDigest: string;
    operation: string;
    envelopeIssuerId: string;
    envelopeKeyId: string;
    envelopePublicKey: KeyMaterial;
    maxEnvelopeTtlMs?: number;
    clockSkewMs?: number;
}
export interface VisibleConsequenceActuatorPins {
    readonly tenantId: string;
    readonly caid: string;
    readonly providerAccountId: string;
    readonly targetDigest: string;
    readonly operation: string;
    readonly envelopeIssuerId: string;
    readonly envelopeKeyId: string;
    readonly envelopePublicKeyFingerprint: string;
    readonly maxEnvelopeTtlMs: number;
    readonly clockSkewMs: number;
}
export interface ConsequenceActuatorReservation {
    readonly tenantId: string;
    readonly attemptId: string;
    readonly actionDigest: string;
    readonly caid: string;
    readonly providerAccountId: string;
    readonly targetDigest: string;
    readonly operation: string;
    readonly idempotencyKey: string;
    readonly nonce: string;
    readonly issuedAt: string;
    readonly expiresAt: string;
    readonly envelopeDigest: string;
}
export type ConsequenceActuatorOutcome = 'COMMITTED' | 'INDETERMINATE';
export interface ConsequenceActuatorConsumption extends ConsequenceActuatorReservation {
    readonly outcome: ConsequenceActuatorOutcome;
}
export interface ConsequenceActuatorStore {
    /** Explicit marker for the built-in non-production test store. */
    readonly testOnly?: true;
    readonly durable: boolean;
    readonly atomic: boolean;
    readonly ownershipFenced: boolean;
    readonly permanentConsumption: boolean;
    reserve(reservation: ConsequenceActuatorReservation): Promise<boolean>;
    consume(consumption: ConsequenceActuatorConsumption): Promise<boolean>;
}
export interface ConsequenceActuatorPgQueryResult {
    readonly rowCount: number | null;
    readonly rows: readonly unknown[];
}
/**
 * A dedicated pool wrapper must label the login principal configured in its
 * connection string. PostgreSQL independently enforces that SESSION_USER is a
 * tenant-mapped member of consequence_actuator_executor.
 */
export interface DedicatedConsequenceActuatorExecutorPool {
    readonly principal: string;
    query(text: string, values: readonly unknown[]): Promise<ConsequenceActuatorPgQueryResult>;
}
export interface PostgresConsequenceActuatorStoreOptions {
    readonly tenantId: string;
    readonly executorPrincipal: string;
    readonly executorPool: DedicatedConsequenceActuatorExecutorPool;
}
export interface ConsequenceActuatorExecutionInput {
    envelope: unknown;
    attemptId: string;
    actionDigest: string;
    idempotencyKey: string;
}
export type ConsequenceActuatorRefusalReason = 'malformed_envelope' | 'unsupported_version' | 'signer_key_mismatch' | 'issuer_mismatch' | 'tenant_mismatch' | 'caid_mismatch' | 'provider_account_mismatch' | 'target_mismatch' | 'operation_mismatch' | 'attempt_mismatch' | 'action_digest_mismatch' | 'idempotency_key_mismatch' | 'envelope_not_yet_valid' | 'envelope_expired' | 'envelope_ttl_exceeded' | 'signature_invalid' | 'store_reserve_failed' | 'envelope_replayed' | 'provider_outcome_indeterminate' | 'store_consume_unconfirmed';
export type ConsequenceActuatorExecutionResult<TResult> = {
    readonly ok: true;
    readonly invoked: true;
    readonly result: TResult;
    readonly envelopeDigest: string;
} | {
    readonly ok: false;
    readonly invoked: boolean;
    readonly reason: ConsequenceActuatorRefusalReason;
    readonly envelopeDigest?: string;
};
export type ConsequenceEnvelopeVerification = {
    readonly ok: true;
    readonly payload: Readonly<ConsequenceExecutionEnvelopePayload>;
    readonly envelopeDigest: string;
} | {
    readonly ok: false;
    readonly reason: Exclude<ConsequenceActuatorRefusalReason, 'store_reserve_failed' | 'envelope_replayed' | 'provider_outcome_indeterminate' | 'store_consume_unconfirmed'>;
};
interface VerifyExpectedBinding {
    attemptId: string;
    actionDigest: string;
    idempotencyKey: string;
}
interface VerifyOptions {
    pins: ConsequenceActuatorPins;
    expected: VerifyExpectedBinding;
    now?: number | (() => number);
}
interface ConsequenceActuatorOptions<TResult> {
    pins: ConsequenceActuatorPins;
    store: ConsequenceActuatorStore;
    readonly testOnly?: true;
    perform: (binding: Readonly<ConsequenceExecutionEnvelopePayload>) => TResult | Promise<TResult>;
    now?: number | (() => number);
}
interface SignEnvelopeOptions {
    privateKey: KeyMaterial;
    keyId: string;
}
export interface MemoryConsequenceActuatorSnapshot extends ConsequenceActuatorReservation {
    readonly state: 'RESERVED' | 'CONSUMED';
    readonly outcome: ConsequenceActuatorOutcome | null;
    readonly reservedAt: string;
    readonly consumedAt: string | null;
}
/** Create a closed Ed25519 execution envelope for an already-authorized effect. */
export declare function signConsequenceExecutionEnvelope(payload: ConsequenceExecutionEnvelopePayload, options: SignEnvelopeOptions): SignedConsequenceExecutionEnvelope;
/** Verify an envelope without invoking a provider or mutating replay state. */
export declare function verifyConsequenceExecutionEnvelope(envelope: unknown, options: VerifyOptions): ConsequenceEnvelopeVerification;
/**
 * Credential-owning actuator. `perform` captures the provider credential in
 * the actuator process; callers cannot submit or replace that credential.
 */
export declare class ConsequenceActuator<TResult = unknown> {
    #private;
    readonly pins: VisibleConsequenceActuatorPins;
    constructor(options: ConsequenceActuatorOptions<TResult>);
    execute(input: ConsequenceActuatorExecutionInput): Promise<ConsequenceActuatorExecutionResult<TResult>>;
}
/**
 * Race-safe, process-local reference store for tests. Map mutations occur
 * before each async method yields, so concurrent calls have one reservation
 * winner. Production must use the RPC-only durable store from the migration.
 */
export declare class MemoryConsequenceActuatorStore implements ConsequenceActuatorStore {
    #private;
    readonly testOnly: true;
    readonly durable = false;
    readonly atomic = true;
    readonly ownershipFenced = false;
    readonly permanentConsumption = false;
    constructor(options?: {
        now?: number | (() => number);
    });
    reserve(reservation: ConsequenceActuatorReservation): Promise<boolean>;
    consume(consumption: ConsequenceActuatorConsumption): Promise<boolean>;
    snapshot(tenantId: string, nonce: string): MemoryConsequenceActuatorSnapshot | null;
    get size(): number;
}
export declare function createMemoryConsequenceActuatorStore(options?: {
    now?: number | (() => number);
}): MemoryConsequenceActuatorStore;
/**
 * Production adapter for the RPC-only PostgreSQL store. The supplied pool must
 * be dedicated to one tenant-mapped executor login; the adapter never emits
 * direct table SQL.
 */
export declare class PostgresConsequenceActuatorStore implements ConsequenceActuatorStore {
    #private;
    readonly durable = true;
    readonly atomic = true;
    readonly ownershipFenced = true;
    readonly permanentConsumption = true;
    readonly tenantId: string;
    readonly executorPrincipal: string;
    constructor(options: PostgresConsequenceActuatorStoreOptions);
    reserve(reservation: ConsequenceActuatorReservation): Promise<boolean>;
    consume(consumption: ConsequenceActuatorConsumption): Promise<boolean>;
}
export declare function createPostgresConsequenceActuatorStore(options: PostgresConsequenceActuatorStoreOptions): PostgresConsequenceActuatorStore;
export {};
//# sourceMappingURL=consequence-actuator.d.ts.map