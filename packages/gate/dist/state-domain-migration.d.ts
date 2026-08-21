import { type RiskRecord, type TrustedRiskKeys } from './reliance-risk-crypto.js';
export declare const STATE_DOMAIN_MIGRATION_RECEIPT_VERSION = "EP-STATE-DOMAIN-MIGRATION-RECEIPT-v1";
export declare const STATE_DOMAIN_MIGRATION_CLAIM_BOUNDARY = "receipted_source_freeze_sealed_import_external_fence_activation_and_tombstone_not_destination_safety_external_truth_or_physical_exclusivity";
export declare function signStateDomainMigrationReceipt(input: RiskRecord, signer: {
    issuer_id: string;
    key_id: string;
    private_key: import('node:crypto').KeyLike;
}): RiskRecord;
export declare function verifyStateDomainMigrationReceipt(artifact: unknown, options?: {
    trusted_keys?: TrustedRiskKeys;
    expected?: RiskRecord;
}): RiskRecord;
export declare function migrateStateDomain(input?: RiskRecord): Promise<RiskRecord>;
declare const _default: {
    STATE_DOMAIN_MIGRATION_RECEIPT_VERSION: string;
    STATE_DOMAIN_MIGRATION_CLAIM_BOUNDARY: string;
    signStateDomainMigrationReceipt: typeof signStateDomainMigrationReceipt;
    verifyStateDomainMigrationReceipt: typeof verifyStateDomainMigrationReceipt;
    migrateStateDomain: typeof migrateStateDomain;
};
export default _default;
//# sourceMappingURL=state-domain-migration.d.ts.map