/**
 * Authorization Server confirmation evidence for AEB/AEC.
 *
 * This profile consumes an independently signed AS grant. It never turns that
 * grant into a relying-party authorization verdict. The adapter verifies the
 * AS signature under relying-party-pinned trust, binds it to one exact action,
 * one exact human-evidence artifact, one human subject, and one resource-server
 * audience, then emits an ordinary AEB evidence leg. A separate AEB
 * `evidence-binding` requirement joins it to the natively verified human leg.
 *
 * The profile is deliberately an implementation surface, not a new wire-format
 * standards claim. It is shaped to compose with AS confirmation records such
 * as draft-liu-agent-operation-authorization and with the AS-owned decision
 * boundary in draft-klrc-aiagent-auth.
 */
import { type KeyObject } from 'node:crypto';
import { type AebAdapter, type AebDigest } from './aeb-adapter-contract.js';
import { type AgilityOptions } from './pq-signature-agility.js';
type Obj = Record<string, unknown>;
export declare const AUTHORIZATION_SERVER_CONFIRMATION_TOKEN_VERSION = "EP-AUTHORIZATION-SERVER-CONFIRMATION-v1";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_ARTIFACT_VERSION = "EP-AUTHORIZATION-SERVER-CONFIRMATION-ARTIFACT-v1";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_CONFIG_VERSION = "EP-AUTHORIZATION-SERVER-CONFIRMATION-CONFIG-v1";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_TRUST_ROOT_VERSION = "EP-AUTHORIZATION-SERVER-CONFIRMATION-ROOT-v1";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_ID = "native:authorization-server-confirmation";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_ADAPTER_VERSION = "1";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_MAPPING_VERSION = "EP-AUTHORIZATION-SERVER-CONFIRMATION-CAID-MAPPING-v1";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_MAPPER_ID = "mapper:authorization-server-confirmation-exact-action-v1";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_TYP = "ep-as-confirmation+jwt";
export interface AuthorizationServerConfirmationClaims {
    ep_version: typeof AUTHORIZATION_SERVER_CONFIRMATION_TOKEN_VERSION;
    iss: string;
    /** Human principal vouched for by the enterprise Authorization Server. */
    sub: string;
    /** Exact Resource Server / Gate audience. */
    aud: string;
    iat: number;
    nbf: number;
    exp: number;
    jti: string;
    authorization_server_decision: 'AUTHORIZED';
    /** Closed exact-action projection: { action_type, parameters }. */
    action: Obj;
    action_digest: AebDigest;
    /** Digest of the exact human artifact included in the adapter envelope. */
    human_evidence_digest: AebDigest;
    policy_digest: AebDigest;
    /** Customer-owned identity-directory state used for this decision. */
    directory_digest: AebDigest;
    /** What the timestamp below actually means; it is not instantaneous HR truth. */
    directory_observation_basis: 'AUTHORIZATION_SERVER_OBSERVED_SNAPSHOT';
    /** Unix time when the AS observed the directory snapshot it used. */
    directory_observed_at: number;
    /** Pins the intended resource-server verification key or KMS identity. */
    resource_server_key_id: string;
    resource_server_key_digest: AebDigest;
}
export interface AuthorizationServerConfirmationArtifact {
    '@version': typeof AUTHORIZATION_SERVER_CONFIRMATION_ARTIFACT_VERSION;
    grant: string;
    human_evidence: unknown;
}
export interface AuthorizationServerConfirmationAdapterConfig {
    '@version': typeof AUTHORIZATION_SERVER_CONFIRMATION_CONFIG_VERSION;
    evidence_role: 'authorization-server-confirmation';
    human_evidence_role: 'human-authorization';
    issuer: string;
    audience: string;
    resource_server_key_id: string;
    resource_server_key_digest: AebDigest;
    action_type: string;
    clock_skew_seconds: number;
    max_token_age_seconds: number;
    max_directory_snapshot_age_seconds: number;
}
export interface AuthorizationServerConfirmationTrustRoot {
    '@version': typeof AUTHORIZATION_SERVER_CONFIRMATION_TRUST_ROOT_VERSION;
    use: 'authorization-server';
    issuer: string;
    key_id: string;
    algorithm: 'EdDSA';
    /** Canonical unpadded base64url DER SubjectPublicKeyInfo. */
    public_key: string;
}
export interface AuthorizationServerConfirmationSigner {
    key_id: string;
    private_key: KeyObject;
}
export interface AuthorizationServerConfirmationConstructorPins {
    config: AuthorizationServerConfirmationAdapterConfig;
    trust_roots: readonly AuthorizationServerConfirmationTrustRoot[];
}
export declare function createAuthorizationServerConfirmationActionDefinition(actionType: string): Obj;
export declare function signAuthorizationServerConfirmation(claims: AuthorizationServerConfirmationClaims, signer: AuthorizationServerConfirmationSigner): string;
export declare function createAuthorizationServerConfirmationAdapter(constructorPins: AuthorizationServerConfirmationConstructorPins): AebAdapter;
/**
 * WHY THE JOSE `alg` HEADER IS GONE IN v2, STATED PLAINLY.
 *
 * v1's grant is a compact JWS whose protected header carries `alg: "EdDSA"`, a
 * value from the IANA JOSE Algorithms registry. There is no JOSE `alg` value
 * for ML-DSA-65 that this repository can trace to a source: the only ML-DSA
 * algorithm identifier carried anywhere in this tree is the COSE one (see
 * packages/verify/src/aeb-mcgraw-delegation-adapter.ts, RFC 9964), and
 * docs/protocol/pq-hybrid-program.md records that the JOSE registration is
 * still draft work. Putting an invented value in the JOSE `alg` slot would be
 * squatting on a foreign registry, so v2 does not do it.
 *
 * Instead the v2 protected header carries NO `alg` at all. Each signature
 * carries its own algorithm label from EP's OWN closed registry
 * (EP-SIG-AGILITY-v1: exactly { Ed25519, ML-DSA-65 }) in the AgileSignature
 * shape, and the header commits to the required SET. The envelope is therefore
 * EP-owned end to end and makes no claim on JOSE. It is deliberately NOT a
 * compact JWS and deliberately NOT presented as one: `typ` changes too.
 *
 * The five moves from EP-REVOCATION-v2, applied here:
 *
 * 1. VERSION BUMP. The artifact takes ARTIFACT-v2 and the claims take
 *    ep_version v2. The v1 parser (parseArtifact) pins `@version` to the v1
 *    marker with an exact closed key set, so it refuses a v2 artifact on the
 *    version marker before any signature work and does not throw. Asserted by
 *    test.
 * 2. SET SHAPE. `signatures` is an array of { alg, sig, key_id }, one entry per
 *    registered algorithm, verified through verifyAgileSignatureSet.
 * 3. ANTI-STRIPPING BYTES. `required_algorithms` lives INSIDE the protected
 *    header, and the protected header is inside the ASCII signing input
 *    (`<protected>.<payload>`), exactly the v1 convention. Narrow the set and
 *    the classical signature no longer verifies, because the signing input
 *    changed. The verifier additionally rebuilds the expected header from the
 *    REGISTERED set and refuses a mismatch structurally.
 * 4. V1 COMPATIBILITY. signAuthorizationServerConfirmation() and the whole
 *    synchronous AebAdapter path are UNCHANGED. ML-DSA verification is async
 *    and AebAdapter.verifyNative() is synchronous by contract, so v2 is a
 *    separate async entry point and there is no hybrid adapter in this release.
 * 5. NAMED REFUSALS. Nothing throws on caller input; an absent ML-DSA backend
 *    surfaces as `pq_backend_unavailable` and never passes on the classical leg.
 *
 * COORDINATION BOUNDARY, kept. The signer here is logically a third-party
 * Authorization Server that vendored this helper. Shipping the v2 verifier does
 * not make any AS emit v2 grants: every AS integration must deploy a second
 * (ML-DSA-65) key and the v2 signer before a relying party can REQUIRE both
 * legs. This profile is opt-in and is not deployed, default, or certified.
 */
export declare const AUTHORIZATION_SERVER_CONFIRMATION_V2_TOKEN_VERSION = "EP-AUTHORIZATION-SERVER-CONFIRMATION-v2";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_V2_ARTIFACT_VERSION = "EP-AUTHORIZATION-SERVER-CONFIRMATION-ARTIFACT-v2";
export declare const AUTHORIZATION_SERVER_CONFIRMATION_V2_TYP = "ep-as-confirmation+hybrid";
/** The registered required algorithm set, in canonical order. */
export declare const AUTHORIZATION_SERVER_CONFIRMATION_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
export interface AuthorizationServerConfirmationV2Claims extends Omit<AuthorizationServerConfirmationClaims, 'ep_version'> {
    ep_version: typeof AUTHORIZATION_SERVER_CONFIRMATION_V2_TOKEN_VERSION;
}
export interface AuthorizationServerConfirmationHybridGrant {
    /** base64url of the canonical-JSON protected header. */
    protected: string;
    /** base64url of the canonical-JSON claims. */
    payload: string;
    /** EP-SIG-AGILITY-v1 AgileSignature entries, one per registered algorithm. */
    signatures: Array<{
        alg: string;
        sig: string;
        key_id: string;
    }>;
}
/** A v2 AS pin: BOTH public halves, pinned out of band by the relying party. */
export interface AuthorizationServerConfirmationV2KeyPin {
    key_id: string;
    /** Ed25519 base64url SPKI DER. */
    public_key: string;
    pq_key_id: string;
    /** ML-DSA-65 base64url raw 1952-byte public key. */
    pq_public_key: string;
}
export interface AuthorizationServerConfirmationV2Signer {
    key_id: string;
    private_key: KeyObject;
    pq_key_id: string;
    /** ML-DSA-65 raw 4032-byte secret key (Uint8Array or base64url). */
    pq_secret_key: Uint8Array | string;
}
export interface AuthorizationServerConfirmationV2Result {
    valid: boolean;
    checks: Record<string, boolean>;
    errors: string[];
    claims?: AuthorizationServerConfirmationV2Claims;
}
/**
 * The v2 protected header. `required_algorithms` is a MEMBER of it, so it is
 * inside the signing input both legs cover. Rebuilt by the verifier from the
 * REGISTERED set; the presented grant never chooses what it is checked against.
 */
export declare function authorizationServerConfirmationV2ProtectedHeader(keyId: string, pqKeyId: string, requiredAlgorithms?: readonly string[]): Obj;
/** ASCII `<protected>.<payload>`: the exact v1 signing-input convention. */
export declare function authorizationServerConfirmationV2SigningInput(protectedB64u: string, payloadB64u: string): Buffer;
/**
 * Sign a v2 confirmation grant under BOTH registered algorithms. Issuer-side
 * misuse throws; an unavailable ML-DSA backend throws rather than minting a
 * one-legged v2 grant.
 */
export declare function signAuthorizationServerConfirmationV2(claims: AuthorizationServerConfirmationV2Claims, signer: AuthorizationServerConfirmationV2Signer, options?: AgilityOptions): Promise<AuthorizationServerConfirmationHybridGrant>;
/**
 * verifyAuthorizationServerConfirmationV2 -- FAIL-CLOSED hybrid check of a v2
 * grant against a pinned AS key pair and a pinned adapter config. Never throws
 * on caller input; a v2 grant NEVER verifies on one leg alone.
 *
 * SCOPE. This checks the GRANT: header shape, committed algorithm set, both
 * signature legs under pinned keys, and closed claim validity against the
 * config's issuer/audience/action_type. It does not evaluate status, freshness
 * windows, directory-snapshot age, or AEB acceptance; those stay with the
 * synchronous v1 adapter, which is unchanged.
 */
export declare function verifyAuthorizationServerConfirmationV2(grant: unknown, pin: AuthorizationServerConfirmationV2KeyPin | null | undefined, config: AuthorizationServerConfirmationAdapterConfig | null | undefined, options?: AgilityOptions): Promise<AuthorizationServerConfirmationV2Result>;
export {};
//# sourceMappingURL=authorization-server-confirmation.d.ts.map