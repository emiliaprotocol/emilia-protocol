/**
 * EP-RELIANCE-AGREEMENT-v1 / EP-RELIANCE-EVENT-v1 — machine-readable, signed
 * reliance agreements and per-action reliance events.
 *
 * THE OBJECT
 * ----------
 * The reliance kernel (EP-RELIANCE-KERNEL-v1) answers "may I rely on this
 * evidence packet under MY pinned profile?" This module carries the layer the
 * insurance market writes in prose today: a signed, portable object in which
 * named parties condition a liability transfer or an indemnity on
 * authorization-evidence sufficiency — "if the presented evidence satisfies
 * reliance profile P, terms T (mode, caps, currency) apply between us." The
 * agreement references the evidence condition by DIGEST of a reliance profile
 * (EP-RELIANCE-PROFILE-v1); it never reinvents evidence policy. The per-action
 * RELIANCE EVENT then binds ONE action's reliance verdict to the agreement,
 * making both the commitment and the act of reliance non-repudiable.
 *
 * WHAT VERIFICATION PROVES — AND DOES NOT
 * ---------------------------------------
 * verifyRelianceAgreement proves WHO agreed to WHAT terms over WHICH evidence
 * conditions: every signature required by the agreement's own required_signers
 * verifies under a key the verifier pinned out of band, over the JCS-canonical
 * agreement payload, inside the agreement's own validity window. It does NOT
 * prove enforceability (a jurisdiction question), does NOT escrow the cap
 * amounts (they are claims about intent), and CANNOT prevent a party from
 * dishonoring the commitment — it makes dishonor attributable and the record
 * portable to a dispute forum. The object is designed to be incorporated by
 * reference into a prose master agreement; it is the interoperable expression
 * of the agreement, not a substitute for contract law.
 *
 * PURE. OFFLINE. FAIL-CLOSED. No deps beyond node:crypto. Monetary amounts are
 * decimal STRINGS, never JSON numbers (floating-point representation of money
 * is a refusal, not a warning). All vocabularies are closed.
 */
import crypto from 'node:crypto';
import { type AgilityOptions } from './pq-signature-agility.js';
type Obj = Record<string, any>;
type KeyRef = string | {
    public_key: string;
};
type Signer = {
    party: string;
    privateKey: crypto.KeyObject;
};
interface AgreementOptions {
    now?: number | string | Date;
    trustedKeys?: Record<string, KeyRef>;
}
interface EventOptions extends AgreementOptions {
    agreement?: Obj;
    relianceResult?: Obj;
}
export declare const RELIANCE_AGREEMENT_VERSION = "EP-RELIANCE-AGREEMENT-v1";
export declare const RELIANCE_EVENT_VERSION = "EP-RELIANCE-EVENT-v1";
export declare const RELIANCE_AGREEMENT_DOMAIN = "EP-RELIANCE-AGREEMENT-v1\0";
export declare const RELIANCE_EVENT_DOMAIN = "EP-RELIANCE-EVENT-v1\0";
/** The CLOSED set of agreement term modes. */
export declare const AGREEMENT_MODES: readonly string[];
/** The CLOSED set of party roles. */
export declare const AGREEMENT_ROLES: readonly string[];
/** Digest of the agreement body (domain-separated, signature envelope excluded). */
export declare function relianceAgreementDigest(agreement: Obj): string;
/** Digest of the event body (domain-separated, signature envelope excluded). */
export declare function relianceEventDigest(event: Obj): string;
/** Content digest of a reliance result record (plain JCS, no signing domain). */
export declare function relianceResultDigest(result: Obj): string;
/**
 * Sign an agreement payload as one or more parties. Test/issuance convenience;
 * verification never trusts the carried public keys, only pinned ones.
 * @param {object} payload  the agreement WITHOUT signatures
 * @param {Array<{party:string, privateKey:import('node:crypto').KeyObject}>} signers
 * @returns {object} the agreement with a signatures[] envelope appended
 */
export declare function signRelianceAgreement(payload: Obj, signers?: Signer[]): Obj;
/**
 * Sign a reliance event payload as the relying party.
 * @param {object} payload  the event WITHOUT signature
 * @param {import('node:crypto').KeyObject} privateKey
 * @returns {object} the event with a signature envelope appended
 */
export declare function signRelianceEvent(payload: Obj, privateKey: crypto.KeyObject): Obj;
/**
 * Verify an EP-RELIANCE-AGREEMENT-v1 against pinned party keys.
 *
 * Proves: well-formed closed-vocabulary payload; the agreement is inside its
 * own validity window at `now`; every party named by the agreement's OWN
 * required_signers[] has exactly one Ed25519 signature that verifies under the
 * key pinned (out of band) for that party's key_id; any additional signature
 * present also verifies. Fail-closed: any missing pin, missing signature,
 * unknown vocabulary value, or amount-as-number is a refusal with a reason.
 *
 * @param {object} agreement
 * @param {object} [opts]
 * @param {Object<string,(string|{public_key:string})>} [opts.trustedKeys]  key_id -> pinned base64url SPKI Ed25519 key
 * @param {number|string|Date} [opts.now]
 * @returns {{valid:boolean, reasons:string[], digest?:string, required_signers?:string[]}}
 */
export declare function verifyRelianceAgreement(agreement: Obj, opts?: AgreementOptions): Obj;
/**
 * Verify an EP-RELIANCE-EVENT-v1: the per-action claim instrument binding one
 * action's reliance verdict to a reliance agreement.
 *
 * Proves: the referenced agreement verifies (all required signatures, pinned
 * keys) and was inside its validity window AT relied_at; the event's
 * agreement_digest matches the supplied agreement; the event's action_digest
 * is the action the supplied reliance result attests; the result digest
 * matches the supplied result byte-for-byte (JCS); the result's action family
 * is inside the agreement scope; when the result names the profile it was
 * evaluated under, it is the profile the agreement conditions on; and the
 * event is signed by the agreement's relying_party under its pinned key.
 *
 * Does NOT re-evaluate the evidence: whether the verdict inside the result is
 * honest is established by replaying the reliance kernel over the evidence,
 * not by this binding check.
 *
 * @param {object} event
 * @param {object} [opts]
 * @param {object} [opts.agreement]       the EP-RELIANCE-AGREEMENT-v1 relied on
 * @param {object} [opts.relianceResult]  the reliance result record the event binds
 *                                      (must carry action_digest and action_family;
 *                                      may carry profile_digest and verdict)
 * @param {Object<string,(string|{public_key:string})>} [opts.trustedKeys]
 * @param {number|string|Date} [opts.now]
 * @returns {{valid:boolean, reasons:string[], agreement_digest?:string, event_digest?:string}}
 */
export declare function verifyRelianceEvent(event: Obj, opts?: EventOptions): Obj;
/**
 * HYBRID MIGRATION, following the same five moves as packages/verify/src/
 * revocation.ts's EP-REVOCATION-v2 addition (read that file's comment block
 * for the full write-up; this is the short form for this artifact pair):
 *
 * 1. VERSION BUMP, NOT A FIELD BUMP. A second per-party leg changes the SHAPE
 *    of `signatures` / `signature`, which is a wire-format change, so each
 *    artifact takes a new `version` (EP-RELIANCE-AGREEMENT-v1 -> -v2,
 *    EP-RELIANCE-EVENT-v1 -> -v2) rather than growing an optional field on
 *    v1. verifyRelianceAgreement()/verifyRelianceEvent() above are untouched
 *    and refuse a v2 object on the version marker before inspecting any
 *    signature -- proven by the version-refusal tests below.
 *
 * 2. SET SHAPE. v1's `agreement.signatures` is already an array of one entry
 *    PER PARTY; v2 adds a second dimension by turning each party's own entry
 *    from a flat Ed25519 signature into a per-party AgileSignature SET
 *    ({party, signatures:[{alg,sig,key_id?}, ...]}), mirroring
 *    EP-SIG-AGILITY-v1's shape verbatim. v1's flat `event.signature` becomes
 *    `{party:'relying_party', signatures:[...]}` the same way. Neither shape
 *    carries a public key any more (v1 did, but the verifier only ever
 *    trusted the PINNED key -- see the "signs nothing away" invariant test in
 *    tests/reliance-agreement.test.ts); v2 drops the carried key entirely and
 *    resolves both halves from `opts.trustedKeys[party's key_id]`.
 *
 * 3. ANTI-STRIPPING BYTES. `agreementV2SigningBytes`/`eventV2SigningBytes`
 *    recompute the canonical body bytes from the PRESENTED fields with
 *    `required_algorithms` forced to the REGISTERED set (never the value the
 *    object happens to carry), under a v2-only domain separator distinct from
 *    v1's. The registered-set guard means a caller can never trick these
 *    functions into signing/verifying over a narrowed set; a narrowed
 *    `required_algorithms` on the wire is instead caught structurally, up
 *    front, by name.
 *
 * 4. V1 COMPATIBILITY. v1 stays synchronous and unchanged. v2 verification is
 *    ASYNC (ML-DSA verification is async), so it is a separate entry point.
 *    v2's non-signature structural checks (closed vocabularies, amount
 *    strings, validity window, required_signers completeness, event-to-
 *    agreement binding) are a deliberate DUPLICATE of v1's, not a shared
 *    refactor: this file's harness only runs tests/reliance-agreement-v2.test.ts
 *    for this change, so v1's own conformance suite cannot be re-run here to
 *    prove a refactor left it byte-for-byte identical. Duplicating is the
 *    honest choice under that constraint -- v1's existing body above is
 *    untouched and unreachable from any v2 code path.
 *
 * 5. NAMED REFUSALS. Same house style as v1 in this file: an ordered
 *    `reasons` array and a `fail(reason)` early-return helper (not
 *    revocation.ts's `checks` object -- this file's own convention already
 *    differs from that one, so v2 follows v1's local style rather than
 *    importing a second one). Nothing throws on caller-controlled content; an
 *    unavailable ML-DSA backend surfaces as a named refusal via
 *    verifyAgileSignatureSet's own reason, never a silent pass.
 */
export declare const RELIANCE_AGREEMENT_V2_VERSION = "EP-RELIANCE-AGREEMENT-v2";
export declare const RELIANCE_EVENT_V2_VERSION = "EP-RELIANCE-EVENT-v2";
export declare const RELIANCE_AGREEMENT_V2_DOMAIN = "EP-RELIANCE-AGREEMENT-v2\0";
export declare const RELIANCE_EVENT_V2_DOMAIN = "EP-RELIANCE-EVENT-v2\0";
/** The registered required algorithm set, in canonical order (agreement side). */
export declare const RELIANCE_AGREEMENT_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/** The registered required algorithm set, in canonical order (event side). */
export declare const RELIANCE_EVENT_V2_REQUIRED_ALGORITHMS: readonly ["Ed25519", "ML-DSA-65"];
/** A v2 party/relying-party key pin: BOTH public halves, pinned out of band. */
export interface RelianceV2KeyPin {
    /** Ed25519 base64url SPKI DER. */
    public_key?: string;
    /** ML-DSA-65 base64url raw public key bytes. */
    pq_public_key?: string;
}
export interface RelianceAgreementV2Options extends AgilityOptions {
    now?: number | string | Date;
    trustedKeys?: Record<string, RelianceV2KeyPin>;
}
export interface RelianceEventV2Options extends RelianceAgreementV2Options {
    agreement?: Obj;
    relianceResult?: Obj;
}
/** One issuer-side hybrid signer: Ed25519 + ML-DSA-65 key material for one party. */
export interface RelianceHybridSigner {
    /** Required for agreement signers; ignored for the single event signer. */
    party?: string;
    privateKey: crypto.KeyObject;
    /** ML-DSA-65 secret key: 4032 raw bytes, or base64url of them. */
    pqSecretKey: Uint8Array | string;
    /** ML-DSA-65 public key: 1952 raw bytes, or base64url of them. */
    pqPublicKeyB64u: Uint8Array | string;
}
/**
 * The bytes EVERY party's signature set covers for an EP-RELIANCE-AGREEMENT-v2
 * agreement: the whole unsigned body (same whole-body convention as v1's
 * agreementSigningBytes), with `required_algorithms` forced to the REGISTERED
 * set, under a v2-only domain separator. Narrowing `required_algorithms` on
 * the wire, or stripping any party's leg, changes nothing about these bytes
 * (they are always computed over the true registered set); it is instead
 * caught structurally, by name, before signature verification is attempted.
 */
export declare function agreementV2SigningBytes(unsignedBodyV2: Obj, requiredAlgorithms?: readonly string[]): Buffer;
/** The bytes the relying party's signature set covers for an EP-RELIANCE-EVENT-v2 event. */
export declare function eventV2SigningBytes(unsignedBodyV2: Obj, requiredAlgorithms?: readonly string[]): Buffer;
/** Digest of the v2 agreement body (domain-separated, signature envelope excluded). */
export declare function relianceAgreementV2Digest(agreement: Obj): string;
/** Digest of the v2 event body (domain-separated, signature envelope excluded). */
export declare function relianceEventV2Digest(event: Obj): string;
/**
 * Sign an EP-RELIANCE-AGREEMENT-v2 payload as one or more parties, each under
 * BOTH Ed25519 and ML-DSA-65 over the SAME bytes. Issuer-side test/reference
 * tooling; verification never trusts carried key material, only pinned keys
 * (opts.trustedKeys). THROWS rather than emit a half-hybrid agreement: a
 * signer missing either half, or a signing pass that fails to produce both
 * legs, is a programming error, not attacker input.
 */
export declare function signRelianceAgreementV2(payload: Obj, signers?: RelianceHybridSigner[]): Promise<Obj>;
/**
 * Sign an EP-RELIANCE-EVENT-v2 payload as the relying party, under BOTH
 * Ed25519 and ML-DSA-65 over the SAME bytes. THROWS rather than emit a
 * half-hybrid event.
 */
export declare function signRelianceEventV2(payload: Obj, signer: RelianceHybridSigner): Promise<Obj>;
/**
 * Verify an EP-RELIANCE-AGREEMENT-v2 against pinned party key PAIRS (Ed25519 +
 * ML-DSA-65 per party). Same non-signature structural proof as
 * verifyRelianceAgreement (v1) -- see that function's doc comment -- except
 * every REQUIRED party must carry a full hybrid signature SET that verifies
 * under BOTH pinned halves. ASYNC (ML-DSA verification is async). Fail-closed:
 * never throws on caller input; a v1 object refuses immediately on the
 * version marker.
 *
 * @param {object} agreement
 * @param {object} [opts]
 * @param {Object<string,{public_key?:string, pq_public_key?:string}>} [opts.trustedKeys]
 *   key_id -> pinned {Ed25519 SPKI b64u, ML-DSA-65 raw b64u} pair
 * @param {number|string|Date} [opts.now]
 * @returns {{valid:boolean, reasons:string[], digest?:string, required_signers?:string[]}}
 */
export declare function verifyRelianceAgreementV2(agreement: Obj, opts?: RelianceAgreementV2Options): Promise<Obj>;
/**
 * Verify an EP-RELIANCE-EVENT-v2: the per-action claim instrument binding one
 * action's reliance verdict to an EP-RELIANCE-AGREEMENT-v2. Same proof shape
 * as verifyRelianceEvent (v1) -- see that function's doc comment -- except
 * the referenced agreement is checked with verifyRelianceAgreementV2 and the
 * event's own signature is a hybrid SET verified under the agreement's
 * relying_party pinned key PAIR. ASYNC. Fail-closed; never throws.
 *
 * @param {object} event
 * @param {object} [opts]
 * @param {object} [opts.agreement]       the EP-RELIANCE-AGREEMENT-v2 relied on
 * @param {object} [opts.relianceResult]  the reliance result record the event binds
 * @param {Object<string,{public_key?:string, pq_public_key?:string}>} [opts.trustedKeys]
 * @param {number|string|Date} [opts.now]
 * @returns {{valid:boolean, reasons:string[], agreement_digest?:string, event_digest?:string}}
 */
export declare function verifyRelianceEventV2(event: Obj, opts?: RelianceEventV2Options): Promise<Obj>;
/**
 * Route an agreement of EITHER version to its verifier. v1 agreements get the
 * exact v1 verdict (unchanged, synchronous body); v2 agreements get the
 * hybrid check. Mirrors verifyRevocationStatement in revocation.ts.
 */
export declare function verifyRelianceAgreementStatement(agreement: Obj, opts?: RelianceAgreementV2Options): Promise<Obj>;
/** Route an event of EITHER version to its verifier. Mirrors verifyRevocationStatement. */
export declare function verifyRelianceEventStatement(event: Obj, opts?: RelianceEventV2Options): Promise<Obj>;
export {};
//# sourceMappingURL=reliance-agreement.d.ts.map