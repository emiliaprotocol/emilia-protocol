export declare const STATUS_VERSION = "EP-STATUS-v1";
export declare const STATUS_DOMAIN = "EP-STATUS-v1\0";
export declare const REVOCER_AUTHORITY_VERSION = "EP-REVOKER-AUTHORITY-v1";
export declare const REVOCER_AUTHORITY_DOMAIN = "EP-REVOKER-AUTHORITY-v1\0";
export declare const STATUS_TARGET_TYPES: readonly ["receipt", "commit", "delegation"];
export declare const STATUS_TARGET_USAGES: readonly ["authorization", "execution", "delegation"];
export type StatusTargetType = typeof STATUS_TARGET_TYPES[number];
export type StatusTargetUsage = typeof STATUS_TARGET_USAGES[number];
export type StatusState = 'not_revoked' | 'revoked';
export type StatusOutcome = 'current_not_revoked' | 'revoked' | 'indeterminate';
export interface StatusTarget {
    type: StatusTargetType;
    id: string;
    digest: string;
    usage: StatusTargetUsage;
}
export interface RevokerAuthorityPin {
    authority_domain: string;
    authority_id: string;
    key_id: string;
    public_key: string;
}
export interface RevokerAuthorityOptions {
    authorityPin?: RevokerAuthorityPin;
    now?: number | string | Date;
}
export interface StatusVerificationOptions extends RevokerAuthorityOptions {
    certificate?: unknown;
    /** The relying party's previously accepted head, never presenter state. */
    previousStatus?: unknown;
}
export interface RevokerAuthorityVerification {
    valid: boolean;
    checks: {
        structure: boolean;
        authority: boolean;
        scope: boolean;
        validity: boolean;
        signature: boolean;
    };
    reasons: string[];
    certificate_digest: string | null;
}
export interface StatusVerification {
    outcome: StatusOutcome;
    valid: boolean;
    checks: {
        structure: boolean;
        certificate: boolean;
        authority: boolean;
        target: boolean;
        scope: boolean;
        signature: boolean;
        freshness: boolean;
        sequence: boolean;
        terminal: boolean;
    };
    reasons: string[];
    status_digest: string | null;
    sequence: number | null;
    next_update: string | null;
}
/** Digest of the exact closed, signed revoker-authority certificate envelope. */
export declare function revokerAuthorityCertificateDigest(certificate: unknown): string;
/** Digest of the exact closed, signed status envelope. */
export declare function statusArtifactDigest(status: unknown): string;
/** Verify one root-signed, time-bounded, target-scoped status-key certificate. */
export declare function verifyRevokerAuthorityCertificate(certificate: unknown, options?: RevokerAuthorityOptions): RevokerAuthorityVerification;
/**
 * Verify current status for one exact target.
 *
 * Sequence > 0 requires the relying party's previously accepted status head.
 * This prevents a presenter from rolling the verifier back to an older signed
 * non-revocation artifact or severing the signed predecessor digest chain.
 */
export declare function verifyStatusArtifact(expectedTarget: unknown, status: unknown, options?: StatusVerificationOptions): StatusVerification;
//# sourceMappingURL=status.d.ts.map