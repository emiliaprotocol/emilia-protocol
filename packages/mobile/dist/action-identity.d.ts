export declare const MOBILE_ACTION_CAID_TYPE = "emilia.mobile.authorized-action.1";
export declare const MOBILE_ACTION_CAID_PATTERN: RegExp;
type AnyRecord = Record<string, any>;
export declare function mobileActionFingerprint(actionCaid: string): string | null;
export declare function buildMobileActionIdentity({ actionReference, action, }?: {
    actionReference?: string;
    action?: AnyRecord;
}): Readonly<{
    action_caid: string;
    action_digest: string;
    caid_digest: string;
    fingerprint: string | null;
}>;
export declare function verifyMobileActionIdentity({ actionReference, action, actionCaid, actionDigest, }?: {
    actionReference?: string;
    action?: AnyRecord;
    actionCaid?: string;
    actionDigest?: string;
}): {
    valid: boolean;
    computed: ReturnType<typeof buildMobileActionIdentity> | null;
};
export declare const _internals: Readonly<{
    DEFINITION: Readonly<{
        action_type: "emilia.mobile.authorized-action.1";
        status: "active";
        risk_class: "external-communication";
        summary: "Exact authoritative action presented for a device-bound EMILIA decision.";
        required_fields: readonly (Readonly<{
            name: "source_action_type";
            type: "string";
        }> | Readonly<{
            name: "source_action_digest";
            type: "digest";
        }>)[];
        optional_fields: readonly never[];
        digest_notes: "The source digest commits the complete authoritative action object.";
        references: readonly never[];
    }>;
}>;
export {};
//# sourceMappingURL=action-identity.d.ts.map