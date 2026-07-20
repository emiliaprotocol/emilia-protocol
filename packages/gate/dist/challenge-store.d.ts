export declare const DURABLE_CHALLENGE_STORE_VERSION = "EP-DURABLE-CHALLENGE-STORE-v1";
export declare function challengeStorageKey(challenge: any): string;
export declare function challengeBodyDigest(challenge: any): string;
export declare function createDurableChallengeStore(backend: any): {
    durable: boolean;
    atomicRegistration: boolean;
    bodyBound: boolean;
    permanentConsumption: boolean;
    register(challenge: any): Promise<boolean>;
    consume(challenge: any): Promise<boolean>;
    has(challenge: any): Promise<boolean>;
};
declare const _default: {
    createDurableChallengeStore: typeof createDurableChallengeStore;
    challengeStorageKey: typeof challengeStorageKey;
    challengeBodyDigest: typeof challengeBodyDigest;
    DURABLE_CHALLENGE_STORE_VERSION: string;
};
export default _default;
//# sourceMappingURL=challenge-store.d.ts.map