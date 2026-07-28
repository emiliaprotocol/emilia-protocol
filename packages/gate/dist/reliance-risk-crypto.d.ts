import crypto from 'node:crypto';
export type RiskRecord = Record<string, any>;
export type TrustedRiskKeys = Record<string, {
    issuer_id: string;
    public_key: string;
}>;
export declare const RISK_DIGEST: RegExp;
export declare const RISK_CAID: RegExp;
export declare const RISK_ID: RegExp;
export declare function riskRecord(value: unknown): value is RiskRecord;
export declare function riskExact(value: unknown, keys: readonly string[]): value is RiskRecord;
export declare function riskIdentifier(value: unknown): value is string;
export declare function riskInstant(value: unknown): number;
export declare function riskDigest(value: unknown): string;
export declare function riskClone<T>(value: T): T;
export declare function riskFreeze<T>(value: T): T;
export declare function signRiskBody(version: string, bodyInput: RiskRecord, signer: {
    issuer_id: string;
    key_id: string;
    private_key: crypto.KeyLike;
}): RiskRecord;
export declare function verifyRiskBody(artifact: unknown, version: string, trustedKeys: TrustedRiskKeys | undefined): {
    valid: boolean;
    reason: string | null;
    body: RiskRecord | null;
    artifact_digest: string | null;
};
//# sourceMappingURL=reliance-risk-crypto.d.ts.map