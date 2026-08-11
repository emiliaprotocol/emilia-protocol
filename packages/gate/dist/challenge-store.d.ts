export declare const DURABLE_CHALLENGE_STORE_VERSION = "EP-DURABLE-CHALLENGE-STORE-v3";
export declare const AUTHORITATIVE_CHALLENGE_OWNER_VERSION = "EP-AE-CHALLENGE-OWNER-v1";
export type ChallengeCapacityBucket = Readonly<{
    key: string;
    limit: number;
}>;
type CapacityBucket = ChallengeCapacityBucket;
type CapacityVector = Readonly<Record<string, number>>;
export type ChallengeOwnerRecord = {
    body_digest: string;
    challenge: any;
    state: 'open' | 'reserved' | 'finalized';
    units: Record<string, number>;
    owner_token_digest: string | null;
    generation: number;
    reserved_at_ms: number | null;
    outcome: string | null;
};
type OwnerRecord = ChallengeOwnerRecord;
export type ChallengeOwnerTransaction = {
    authoritativeNowMs: () => Promise<number>;
    lockChallenge: (key: string) => Promise<void>;
    readChallenge: (key: string) => Promise<OwnerRecord | null>;
    insertChallenge: (key: string, record: OwnerRecord) => Promise<boolean>;
    writeChallenge: (key: string, record: OwnerRecord) => Promise<void>;
    lockCapacity: (buckets: CapacityBucket[]) => Promise<Record<string, {
        used: number;
        limit: number;
    }>>;
    writeCapacity: (used: CapacityVector) => Promise<void>;
};
type OwnerTransaction = ChallengeOwnerTransaction;
export type ChallengeOwnerBackend = {
    durable: boolean;
    transaction: <T>(work: (tx: OwnerTransaction) => Promise<T>) => Promise<T>;
};
type OwnerBackend = ChallengeOwnerBackend;
/**
 * Build the owner-side state machine required by AE-CHALLENGE -07.
 *
 * The injected backend supplies one serializable transaction, row locks, and
 * authoritative database time. The algorithm, capacity ordering, ownership
 * fence, and result grammar live here rather than in caller-provided booleans.
 */
export declare function createAuthoritativeChallengeOwnerStore(backend: OwnerBackend, { issuerIdentity, capacityPolicy, ownerTokenFactory, recoveryAuthorizer, recoveryAfterMs, }: {
    issuerIdentity: string;
    capacityPolicy: (challenge: any, context: {
        authenticated_presenter?: string;
    }) => CapacityBucket[];
    ownerTokenFactory?: () => string;
    recoveryAuthorizer: (authorization: unknown) => boolean | Promise<boolean>;
    recoveryAfterMs?: number;
}): Readonly<{
    version: "EP-AE-CHALLENGE-OWNER-v1";
    durable: boolean;
    issuerIdentity: string;
    register: (challenge: any) => Promise<boolean>;
    registerOutstanding: (challenge: any) => Promise<boolean>;
    compoundClaimAndCapacity: (challenge: any, context?: {
        audience?: string;
        authenticated_presenter?: string;
    }) => Promise<{
        result: string;
        reservation?: undefined;
    } | {
        result: string;
        reservation: Readonly<{
            version: "EP-AE-CHALLENGE-OWNER-v1";
            replay_key: string;
            body_digest: string;
            generation: number;
            owner_token: string;
        }>;
    }>;
    finalizeReservation: (handle: any, { outcome, followup, }: {
        outcome: string;
        followup?: any | null;
    }) => Promise<{
        result: string;
        authoritative_at_ms: number;
    }>;
    recoverReservation: (challenge: any, { authorization }?: {
        authorization?: unknown;
    }) => Promise<{
        result: string;
        reservation: Readonly<{
            version: "EP-AE-CHALLENGE-OWNER-v1";
            replay_key: string;
            body_digest: string;
            generation: number;
            owner_token: string;
        }>;
    } | {
        result: string;
    }>;
}>;
export declare function isAuthoritativeChallengeOwnerStore(store: any): boolean;
/** Serialized in-memory backend for executable contract tests only. */
export declare function createMemoryChallengeOwnerBackend({ now }?: {
    now?: (() => number) | undefined;
}): {
    durable: boolean;
    records: Map<string, ChallengeOwnerRecord>;
    capacity: Map<string, {
        used: number;
        limit: number;
    }>;
    transaction<T>(work: (tx: OwnerTransaction) => Promise<T>): Promise<T>;
};
export declare function challengeStorageKey(challenge: any, issuerIdentity?: string): string;
export declare function challengeBodyDigest(challenge: any): string;
export declare function createDurableChallengeStore(backend: any, { issuerIdentity }?: {
    issuerIdentity?: string;
}): {
    has(challenge: any): Promise<boolean>;
    classify?: ((challenge: any) => Promise<"absent" | "open-exact" | "open-body-collision" | "claimed-exact" | "claimed-body-collision">) | undefined;
    durable: boolean;
    atomicRegistration: boolean;
    bodyBound: boolean;
    permanentConsumption: boolean;
    authoritativeClassification: boolean;
    issuerScoped: boolean;
    issuerIdentity: string;
    register(challenge: any): Promise<boolean>;
    consume(challenge: any): Promise<boolean>;
};
declare const _default: {
    createDurableChallengeStore: typeof createDurableChallengeStore;
    createAuthoritativeChallengeOwnerStore: typeof createAuthoritativeChallengeOwnerStore;
    createMemoryChallengeOwnerBackend: typeof createMemoryChallengeOwnerBackend;
    isAuthoritativeChallengeOwnerStore: typeof isAuthoritativeChallengeOwnerStore;
    challengeStorageKey: typeof challengeStorageKey;
    challengeBodyDigest: typeof challengeBodyDigest;
    DURABLE_CHALLENGE_STORE_VERSION: string;
    AUTHORITATIVE_CHALLENGE_OWNER_VERSION: string;
};
export default _default;
//# sourceMappingURL=challenge-store.d.ts.map