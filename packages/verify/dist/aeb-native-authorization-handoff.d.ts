/**
 * Direct native-authorization handoff for the Action Evidence Boundary.
 *
 * A native system makes the authorization decision. A relying-party-pinned
 * gateway signs the exact action and execution bindings it observed. This
 * module verifies that statement; it does not run policy, reinterpret the
 * native decision, or require CAID or AEC.
 */
import { type KeyObject } from 'node:crypto';
export declare const AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION = "AEB-NATIVE-AUTHORIZATION-HANDOFF-v1";
export declare const AEB_NATIVE_AUTHORIZATION_HANDOFF_DOMAIN = "AEB-NATIVE-AUTHORIZATION-HANDOFF-v1\0";
export declare const AEB_NATIVE_AUTHORIZATION_REPLAY_DOMAIN = "AEB-NATIVE-AUTHORIZATION-REPLAY-v1";
export declare const AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN = "AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v1";
export declare const AEB_NATIVE_AUTHORIZATION_ACTION_DOMAIN = "AEB-NATIVE-AUTHORIZATION-ACTION-v1";
export declare const AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION = "AEB-NATIVE-AUTHORIZATION-GATEWAY-KEY-v1";
export declare const AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION = "AEB-NATIVE-AUTHORIZATION-SOURCE-PIN-v1";
export declare const AEB_NATIVE_AUTHORIZATION_PINS_VERSION = "AEB-NATIVE-AUTHORIZATION-PINS-v1";
export declare const AEB_NATIVE_AUTHORIZATION_STATUS_VERSION = "AEB-NATIVE-AUTHORIZATION-STATUS-v1";
export type AebNativeAuthorizationSystem = 'aims' | 'authzen' | 'coaz' | 'ap2' | 'oauth' | 'local';
export type AebNativeAuthorizationDigest = `sha256:${string}`;
export interface AebNativeAuthorizationProviderBinding {
    tenant_id: string;
    provider_id: string;
    provider_account_id: string;
    environment: string;
}
export interface AebNativeAuthorizationSource {
    system: AebNativeAuthorizationSystem;
    profile: string;
    issuer: string;
    authorization_id: string;
    /** Stable across wrapper and operation identifiers for this native grant. */
    replay_unit: AebNativeAuthorizationDigest;
}
export interface AebNativeAuthorizationHandoffBody {
    '@version': typeof AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION;
    gateway_id: string;
    decision: 'PERMIT';
    native_authorization: AebNativeAuthorizationSource;
    relying_party_id: string;
    audience: string;
    executor_id: string;
    provider: AebNativeAuthorizationProviderBinding;
    action_digest: AebNativeAuthorizationDigest;
    issued_at: string;
    not_before: string;
    expires_at: string;
    revocation_id: string;
}
export interface AebNativeAuthorizationHandoff extends AebNativeAuthorizationHandoffBody {
    signature: {
        alg: 'Ed25519';
        key_id: string;
        value: string;
    };
}
export interface AebNativeAuthorizationGatewayKey {
    '@version': typeof AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION;
    gateway_id: string;
    key_id: string;
    algorithm: 'Ed25519';
    /** Canonical unpadded base64url DER SubjectPublicKeyInfo. */
    public_key: string;
}
export interface AebNativeAuthorizationSourcePin {
    '@version': typeof AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION;
    gateway_id: string;
    system: AebNativeAuthorizationSystem;
    profile: string;
    issuer: string;
}
export interface AebNativeAuthorizationPins {
    '@version': typeof AEB_NATIVE_AUTHORIZATION_PINS_VERSION;
    relying_party_id: string;
    audience: string;
    executor_id: string;
    provider: AebNativeAuthorizationProviderBinding;
    max_handoff_age_seconds: number;
    max_status_age_seconds: number;
    clock_skew_seconds: number;
    gateway_keys: readonly AebNativeAuthorizationGatewayKey[];
    accepted_sources: readonly AebNativeAuthorizationSourcePin[];
}
export interface AebNativeAuthorizationStatus {
    '@version': typeof AEB_NATIVE_AUTHORIZATION_STATUS_VERSION;
    /** The pinned gateway whose statement this status result covers. */
    gateway_id: string;
    /** Exact native-source identity, including the derived replay unit. */
    native_authorization: AebNativeAuthorizationSource;
    revocation_id: string;
    checked_at: string;
    valid_until: string;
    revoked: boolean;
}
export interface IssueAebNativeAuthorizationHandoffInput {
    gateway_id: string;
    native_authorization: Omit<AebNativeAuthorizationSource, 'replay_unit'>;
    relying_party_id: string;
    audience: string;
    executor_id: string;
    provider: AebNativeAuthorizationProviderBinding;
    action: unknown;
    issued_at: string;
    not_before: string;
    expires_at: string;
    revocation_id: string;
}
export interface AebNativeAuthorizationHandoffSigner {
    key_id: string;
    private_key: KeyObject;
}
export interface AebNativeAuthorizationHandoffChecks {
    schema: boolean;
    key_pinned: boolean;
    signature: boolean;
    source_pinned: boolean;
    decision: boolean;
    exact_action: boolean;
    relying_party: boolean;
    audience: boolean;
    executor: boolean;
    provider: boolean;
    freshness: boolean;
    revocation: boolean;
}
export interface AebNativeAuthorizationHandoffVerification {
    mode: 'execution' | 'historical';
    valid: boolean;
    execution_authorizing: boolean;
    reasons: readonly string[];
    checks: Readonly<AebNativeAuthorizationHandoffChecks>;
    record_digest: AebNativeAuthorizationDigest;
    action_digest: AebNativeAuthorizationDigest | null;
    native_replay_unit: AebNativeAuthorizationDigest | null;
    replay_key: string | null;
    handoff: Readonly<AebNativeAuthorizationHandoff> | null;
}
export declare function digestAebNativeAuthorizationAction(action: unknown): AebNativeAuthorizationDigest;
export declare function deriveAebNativeAuthorizationReplayUnit(source: Omit<AebNativeAuthorizationSource, 'replay_unit'>): AebNativeAuthorizationDigest;
export declare function aebNativeAuthorizationReplayKey(input: Pick<AebNativeAuthorizationHandoffBody, 'relying_party_id' | 'native_authorization'>): string;
/**
 * Issue a gateway statement for one native PERMIT. The caller supplies the
 * native system's stable authorization identifier. Operation and wrapper IDs
 * are deliberately absent from the replay-unit derivation.
 */
export declare function issueAebNativeAuthorizationHandoff(input: IssueAebNativeAuthorizationHandoffInput, signer: AebNativeAuthorizationHandoffSigner): AebNativeAuthorizationHandoff;
/**
 * Verify a gateway-signed native-authorization handoff under relying-party
 * pins. This verifies the gateway statement, not the native permit or artifact.
 * `execution_authorizing` reports only whether the statement is usable at this
 * boundary. It is not a fresh policy decision.
 */
export declare function verifyAebNativeAuthorizationHandoff(handoffValue: unknown, options: {
    pins: AebNativeAuthorizationPins;
    expected_action: unknown;
    status?: AebNativeAuthorizationStatus;
    now: string;
    mode?: 'execution' | 'historical';
}): AebNativeAuthorizationHandoffVerification;
declare const _default: Readonly<{
    AEB_NATIVE_AUTHORIZATION_HANDOFF_VERSION: "AEB-NATIVE-AUTHORIZATION-HANDOFF-v1";
    AEB_NATIVE_AUTHORIZATION_HANDOFF_DOMAIN: "AEB-NATIVE-AUTHORIZATION-HANDOFF-v1\0";
    AEB_NATIVE_AUTHORIZATION_REPLAY_DOMAIN: "AEB-NATIVE-AUTHORIZATION-REPLAY-v1";
    AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN: "AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v1";
    AEB_NATIVE_AUTHORIZATION_ACTION_DOMAIN: "AEB-NATIVE-AUTHORIZATION-ACTION-v1";
    AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION: "AEB-NATIVE-AUTHORIZATION-GATEWAY-KEY-v1";
    AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION: "AEB-NATIVE-AUTHORIZATION-SOURCE-PIN-v1";
    AEB_NATIVE_AUTHORIZATION_PINS_VERSION: "AEB-NATIVE-AUTHORIZATION-PINS-v1";
    AEB_NATIVE_AUTHORIZATION_STATUS_VERSION: "AEB-NATIVE-AUTHORIZATION-STATUS-v1";
    digestAebNativeAuthorizationAction: typeof digestAebNativeAuthorizationAction;
    deriveAebNativeAuthorizationReplayUnit: typeof deriveAebNativeAuthorizationReplayUnit;
    aebNativeAuthorizationReplayKey: typeof aebNativeAuthorizationReplayKey;
    issueAebNativeAuthorizationHandoff: typeof issueAebNativeAuthorizationHandoff;
    verifyAebNativeAuthorizationHandoff: typeof verifyAebNativeAuthorizationHandoff;
}>;
export default _default;
//# sourceMappingURL=aeb-native-authorization-handoff.d.ts.map