/**
 * Canonical Action Identifier scheme boundary.
 *
 * New identifiers use the `canactid` URI scheme, provisionally registered by
 * IANA. Provisional registration is not IETF endorsement. Historical CAID-04
 * signed artifacts remain byte-immutable and are available only through the
 * explicitly selected legacy profile below. Callers must never translate a
 * signed `caid:` value into `canactid:` because the identifier is part of the
 * signed material.
 */
export declare const CANACTID_V1_PROFILE: "canactid-v1";
export declare const LEGACY_CAID_V04_PROFILE: "legacy-caid-v04";
export type CanonicalActionIdentifierProfile = typeof CANACTID_V1_PROFILE | typeof LEGACY_CAID_V04_PROFILE;
export declare const CANACTID_V1_PATTERN: RegExp;
export declare const LEGACY_CAID_V04_PATTERN: RegExp;
export interface ParsedCanonicalActionIdentifier {
    profile: CanonicalActionIdentifierProfile;
    scheme: 'canactid' | 'caid';
    version: 1;
    action_type: string;
    canonicalization: string;
    digest: string;
}
export declare function isCanonicalActionIdentifier(value: unknown): value is string;
export declare function isLegacyCaidV04(value: unknown): value is string;
export declare function parseCanonicalActionIdentifier(value: unknown, profile?: CanonicalActionIdentifierProfile): ParsedCanonicalActionIdentifier | null;
export declare function canonicalActionIdentifierMatchesActionType(value: unknown, actionType: string, profile?: CanonicalActionIdentifierProfile): boolean;
//# sourceMappingURL=canonical-action-identifier.d.ts.map