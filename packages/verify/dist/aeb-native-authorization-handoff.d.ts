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
/**
 * Domain of the wire `native_authorization.replay_unit` that a gateway signs.
 * It is unchanged from verify 4.1.0 and still hashes the `system` and
 * `profile` labels, so handoffs stay byte-compatible in both directions. The
 * verifier checks the wire value but never uses it for replay enforcement.
 */
export declare const AEB_NATIVE_AUTHORIZATION_REPLAY_DOMAIN = "AEB-NATIVE-AUTHORIZATION-REPLAY-v1";
/**
 * Domain of the label-free native replay identity the verifier derives
 * locally: (authority namespace, native authorization identifier). The
 * default namespace is the issuer. A declared namespace replaces the issuer,
 * so pins that spell one issuer two ways can share one identity.
 */
export declare const AEB_NATIVE_AUTHORIZATION_REPLAY_IDENTITY_DOMAIN = "AEB-NATIVE-AUTHORIZATION-REPLAY-IDENTITY-v1";
/**
 * Domain of the relying-party-scoped durable replay key over the native replay
 * identity. Verify 4.1.0 used `AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v1` over the
 * label-bearing wire unit, so keys derived by 4.1.0 do not match these.
 */
export declare const AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN = "AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v2";
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
    /**
     * Gateway-computed wire digest of (system, profile, issuer, authorization
     * ID) under `AEB-NATIVE-AUTHORIZATION-REPLAY-v1`, exactly as verify 4.1.0
     * signs it. The verifier checks it for wire compatibility and never uses it
     * as a replay identity: it changes when a grant is relabelled. The
     * enforcement identity is AebNativeAuthorizationHandoffVerification
     * `.native_replay_unit`.
     */
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
    /**
     * Relying-party-pinned namespace for this issuer's authorization
     * identifiers. When omitted the namespace is the issuer string. A declared
     * namespace replaces the issuer in the replay identity, so two pins that
     * declare one namespace share one replay identity per authorization ID.
     * Every pin that accepts one issuer shares one namespace unless each of
     * those pins declares one explicitly; a pin set that mixes declared and
     * default namespaces for one issuer is refused. Pins whose issuers differ
     * only by URL spelling (scheme or host case, a default port, a trailing
     * slash) are refused unless all of them declare the same namespace.
     * Changing a declared namespace changes every replay key derived under it,
     * so it is a key rotation: drain in-flight and burned grants first.
     */
    authority_namespace?: string;
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
    /**
     * Label-free native replay identity under the matched pin's authority
     * namespace: (namespace, authorization ID), with the issuer as the default
     * namespace. Null unless the native source is pinned. It never equals the
     * wire `handoff.native_authorization.replay_unit`, which is a
     * label-bearing compatibility digest.
     */
    native_replay_unit: AebNativeAuthorizationDigest | null;
    /** Relying-party-scoped durable replay key for `native_replay_unit`. */
    replay_key: string | null;
    handoff: Readonly<AebNativeAuthorizationHandoff> | null;
}
export declare function digestAebNativeAuthorizationAction(action: unknown): AebNativeAuthorizationDigest;
/**
 * Derive the wire `replay_unit` a gateway signs, byte-identical to verify
 * 4.1.0: a domain-separated digest of (system, profile, issuer,
 * authorization ID). It is a wire-compatibility value, not a replay identity;
 * use deriveAebNativeAuthorizationReplayIdentity() for enforcement.
 */
export declare function deriveAebNativeAuthorizationReplayUnit(source: Omit<AebNativeAuthorizationSource, 'replay_unit'>): AebNativeAuthorizationDigest;
/**
 * Derive the label-free native replay identity used for enforcement:
 * (authority namespace, native authorization identifier). The namespace is
 * the relying-party-pinned `authority_namespace`, or the issuer when the pin
 * declares none. The `system` and `profile` labels are validated but are never
 * inputs, so relabelling one grant cannot make it spendable again, and a
 * declared namespace replaces the issuer string entirely.
 */
export declare function deriveAebNativeAuthorizationReplayIdentity(source: Omit<AebNativeAuthorizationSource, 'replay_unit'>, options?: {
    authority_namespace?: string;
}): AebNativeAuthorizationDigest;
/**
 * Relying-party-scoped durable replay key over the native replay identity.
 * `authority_namespace` is the value pinned by the relying party for the
 * accepted source; omit it for the default (issuer) namespace. The input's
 * wire `replay_unit` must be the 4.1.0-compatible value for its labels.
 */
export declare function aebNativeAuthorizationReplayKey(input: Pick<AebNativeAuthorizationHandoffBody, 'relying_party_id' | 'native_authorization'> & {
    authority_namespace?: string;
}): string;
export interface AebNativeAuthorizationPinsVerification {
    valid: boolean;
    /** Empty when valid; otherwise one `native_pins_*` refusal reason. */
    reasons: readonly string[];
}
/**
 * Validate a relying-party pin set before it is used, so a consequence
 * boundary can refuse an unsafe configuration at construction instead of at
 * run time. Never throws: an unreadable value is `native_pins_schema_invalid`.
 */
export declare function verifyAebNativeAuthorizationPins(pins: unknown): AebNativeAuthorizationPinsVerification;
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
    AEB_NATIVE_AUTHORIZATION_REPLAY_IDENTITY_DOMAIN: "AEB-NATIVE-AUTHORIZATION-REPLAY-IDENTITY-v1";
    AEB_NATIVE_AUTHORIZATION_REPLAY_KEY_DOMAIN: "AEB-NATIVE-AUTHORIZATION-REPLAY-KEY-v2";
    AEB_NATIVE_AUTHORIZATION_ACTION_DOMAIN: "AEB-NATIVE-AUTHORIZATION-ACTION-v1";
    AEB_NATIVE_AUTHORIZATION_GATEWAY_KEY_VERSION: "AEB-NATIVE-AUTHORIZATION-GATEWAY-KEY-v1";
    AEB_NATIVE_AUTHORIZATION_SOURCE_PIN_VERSION: "AEB-NATIVE-AUTHORIZATION-SOURCE-PIN-v1";
    AEB_NATIVE_AUTHORIZATION_PINS_VERSION: "AEB-NATIVE-AUTHORIZATION-PINS-v1";
    AEB_NATIVE_AUTHORIZATION_STATUS_VERSION: "AEB-NATIVE-AUTHORIZATION-STATUS-v1";
    digestAebNativeAuthorizationAction: typeof digestAebNativeAuthorizationAction;
    deriveAebNativeAuthorizationReplayUnit: typeof deriveAebNativeAuthorizationReplayUnit;
    deriveAebNativeAuthorizationReplayIdentity: typeof deriveAebNativeAuthorizationReplayIdentity;
    aebNativeAuthorizationReplayKey: typeof aebNativeAuthorizationReplayKey;
    issueAebNativeAuthorizationHandoff: typeof issueAebNativeAuthorizationHandoff;
    verifyAebNativeAuthorizationPins: typeof verifyAebNativeAuthorizationPins;
    verifyAebNativeAuthorizationHandoff: typeof verifyAebNativeAuthorizationHandoff;
}>;
export default _default;
//# sourceMappingURL=aeb-native-authorization-handoff.d.ts.map