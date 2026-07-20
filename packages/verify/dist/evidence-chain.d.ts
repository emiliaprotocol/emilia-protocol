type Obj = Record<string, any>;
export declare const AEC_VERSION = "EP-AEC-v1";
/** Canonical action digest (hex). NOTE: uses EP's canonicalize(); see the JCS
 *  conformance note in the spec — the shared substrate MUST be true RFC 8785. */
export declare function actionDigest(action: any): string;
/** Normalize a digest claim to bare lowercase hex (strip any "sha256:" prefix). */
declare function normDigest(d: any): string | null;
declare function strictInstantMs(value: any): number;
declare function freshAt(context: any, verificationTime: any, maxAgeSec: any): boolean;
declare function freshRegistrySnapshot(profile: any, verificationTime: any): boolean;
declare function activeDirectoryEntry(entry: any, verificationTime: any): boolean;
declare function allowedOriginSet(profile: any): Set<string> | null;
declare function webauthnOrigin(webauthn: any): string | null;
declare function validUnicodeString(value: any): boolean;
declare function boundedJson(value: any): boolean;
/**
 * Evaluate a tiny boolean requirement expression over the SET of verified
 * component types. Grammar (safe, no eval):
 *   expr = term *(("AND"/"OR"/"&&"/"||") term)
 *   term = "(" expr ")" / IDENT
 * IDENT matches a verified component `type`. Labels are display-only.
 */
declare function tokenizeRequirement(expr: any): any[] | null;
declare function evalRequirement(expr: any, satisfied: Set<string>): Obj;
/** Public fail-closed boundary. Parsed JSON is the intended wire input, but
 * framework callers can still supply proxies/getters that throw during shape
 * inspection. No host-language exception may turn verification into a crash.
 * @param {object} aec
 * @param {{requirement?:string, [key:string]:any}} [opts]
 */
export declare function verifyAuthorizationChain(aec: Obj, opts?: Obj): Obj;
export declare const __aecSecurityInternals: Readonly<{
    normDigest: typeof normDigest;
    strictInstantMs: typeof strictInstantMs;
    freshAt: typeof freshAt;
    freshRegistrySnapshot: typeof freshRegistrySnapshot;
    activeDirectoryEntry: typeof activeDirectoryEntry;
    allowedOriginSet: typeof allowedOriginSet;
    webauthnOrigin: typeof webauthnOrigin;
    validUnicodeString: typeof validUnicodeString;
    boundedJson: typeof boundedJson;
    tokenizeRequirement: typeof tokenizeRequirement;
    evalRequirement: typeof evalRequirement;
}>;
export {};
//# sourceMappingURL=evidence-chain.d.ts.map