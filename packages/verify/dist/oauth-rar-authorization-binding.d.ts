export declare const OAUTH_RAR_AUTHORIZATION_BINDING_VERSION = "EP-OAUTH-RAR-AUTHORIZATION-BINDING-v1";
export interface OAuthRarAuthorizationBinding {
    profile: typeof OAUTH_RAR_AUTHORIZATION_BINDING_VERSION;
    authorization_server: string;
    transaction_id: string;
    actor: string;
    delegated_subject?: string;
    authorization_details_digest: string;
    action_mapping_profile: string;
}
export type OAuthRarAuthorizationBindingVerdict = 'MATCH' | 'MISMATCH' | 'INDETERMINATE';
export interface OAuthRarAuthorizationBindingResult {
    verdict: OAuthRarAuthorizationBindingVerdict;
    binding: OAuthRarAuthorizationBinding | null;
    reason: string | null;
}
/** Return a safe normalized copy of the closed OAuth/RAR projection. */
export declare function parseOAuthRarAuthorizationBinding(value: unknown): OAuthRarAuthorizationBinding | null;
/**
 * Compare a presented projection with one independently derived from a
 * natively verified OAuth/RAR transaction. Missing or malformed expected input
 * is indeterminate; malformed presented input and unequal projections are hard
 * mismatches.
 */
export declare function matchOAuthRarAuthorizationBinding(presented: unknown, expected: unknown): OAuthRarAuthorizationBindingResult;
declare const _default: Readonly<{
    OAUTH_RAR_AUTHORIZATION_BINDING_VERSION: "EP-OAUTH-RAR-AUTHORIZATION-BINDING-v1";
    parseOAuthRarAuthorizationBinding: typeof parseOAuthRarAuthorizationBinding;
    matchOAuthRarAuthorizationBinding: typeof matchOAuthRarAuthorizationBinding;
}>;
export default _default;
//# sourceMappingURL=oauth-rar-authorization-binding.d.ts.map