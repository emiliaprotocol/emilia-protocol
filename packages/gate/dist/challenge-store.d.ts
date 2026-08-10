export declare const DURABLE_CHALLENGE_STORE_VERSION = "EP-DURABLE-CHALLENGE-STORE-v3";
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
    challengeStorageKey: typeof challengeStorageKey;
    challengeBodyDigest: typeof challengeBodyDigest;
    DURABLE_CHALLENGE_STORE_VERSION: string;
};
export default _default;
//# sourceMappingURL=challenge-store.d.ts.map