/**
 * Concrete ORPRG JSON/JCS verifier profile.
 *
 * HONESTY BOUNDARY
 * ----------------
 * draft-lee-orprg-permit-receipts-00 defines an abstract PermitReceipt model
 * and verifier behavior. It deliberately does not select a mandatory wire
 * format. This module therefore does NOT claim to verify every ORPRG receipt.
 * It defines and verifies one explicitly named, closed JSON profile:
 *
 *   ORPRG-JSON-JCS-ED25519-v1
 *
 * The profile uses an ORPRG-JCS-ACTION-v1 canonical request envelope,
 * RFC 8785 JSON Canonicalization Scheme semantics over an I-JSON/safe-integer
 * subset, SHA-256 action digests, Ed25519 issuer signatures, exact policy and
 * epoch pins, signed status recency, exact scope/audience checks, integer-unit
 * budget ceilings, and atomic durable single-use consumption.
 *
 * The verifier returns the component contract consumed by EP-AEC:
 *
 *   { valid: boolean, action_digest: string|null, detail: object }
 *
 * `valid` establishes a machine-policy permit under this concrete profile. It
 * does not establish human authorization, successful execution, legal effect,
 * or non-bypassable deployment.
 */
type Obj = Record<string, any>;
export declare const ORPRG_JSON_JCS_PROFILE = "ORPRG-JSON-JCS-ED25519-v1";
export declare const ORPRG_ACTION_PROFILE = "ORPRG-JCS-ACTION-v1";
declare function validUnicodeString(value: any): boolean;
declare function canonicalJsonSafety(value: any): boolean;
declare function canonicalizeJcs(value: any): string | null;
declare function parseInstant(value: any): number;
declare function actionShapeValid(action: any): boolean;
/**
 * Compute the RFC 8785/SHA-256 digest for an ORPRG-JCS-ACTION-v1 request.
 * Returns null for a malformed, open-schema, cyclic, non-I-JSON, or otherwise
 * ambiguous request.
 */
export declare function computeOrprgActionDigest(action: any): string | null;
declare function scopeShapeValid(scope: any): boolean;
declare function receiptShapeValid(receipt: any): boolean;
declare function scopeMatchesAction(scope: any, action: any, requireBudget: boolean): boolean;
declare function signedPayload(receipt: any): Obj;
/**
 * Verify every native ORPRG predicate except the final anti-replay mutation.
 *
 * This is the first half of a two-phase composition contract. It never returns
 * `valid:true` and never calls an anti-replay hook, so it cannot be mistaken for
 * an executable permit. A caller may use the returned stable `replay_key` only
 * when its own execution gate atomically reserves that key before invocation
 * and commits it after a conclusive effect. The ordinary verify functions below
 * remain the one-step consume-and-verify APIs.
 */
export declare function inspectOrprgJsonJcsPermit(input: any, options?: any): Obj;
/**
 * Synchronous verifier suitable for the current synchronous EP-AEC component
 * contract. The anti-replay hook MUST synchronously and atomically consume the
 * supplied key. If it returns a Promise, throws, returns an ambiguous value, or
 * reports replay, verification denies. Use verifyOrprgJsonJcsPermitAsync when
 * the durable backend is asynchronous.
 */
export declare function verifyOrprgJsonJcsPermit(input: any, options?: any): Obj;
/**
 * Asynchronous variant for production stores whose atomic consume operation
 * returns a Promise. The result is byte-for-byte the same AEC component shape.
 */
export declare function verifyOrprgJsonJcsPermitAsync(input: any, options?: any): Promise<Obj>;
/**
 * Capture relying-party policy and trust anchors for direct registration in
 * EP-AEC's `opts.verifiers` map:
 *
 *   const verifier = createOrprgAecVerifier(profile);
 *   verifyAuthorizationChain(chain, {
 *     expectedAction,
 *     verificationTime,
 *     requirement: 'orprg-json-jcs',
 *     verifiers: { 'orprg-json-jcs': verifier }
 *   });
 *
 * AEC supplies the already executor-bound chain action and verification time.
 * This adapter captures the policy digest, epoch, issuer pins, recency limits,
 * budget requirement, and anti-replay method at construction.
 */
export declare function createOrprgAecVerifier(profile?: any): (evidence: any, context?: any) => Obj;
export declare const __orprgSecurityInternals: Readonly<{
    validUnicodeString: typeof validUnicodeString;
    canonicalJsonSafety: typeof canonicalJsonSafety;
    canonicalizeJcs: typeof canonicalizeJcs;
    parseInstant: typeof parseInstant;
    actionShapeValid: typeof actionShapeValid;
    scopeShapeValid: typeof scopeShapeValid;
    receiptShapeValid: typeof receiptShapeValid;
    scopeMatchesAction: typeof scopeMatchesAction;
    signedPayload: typeof signedPayload;
}>;
export {};
//# sourceMappingURL=orprg.d.ts.map