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
export {};
//# sourceMappingURL=reliance-agreement.d.ts.map