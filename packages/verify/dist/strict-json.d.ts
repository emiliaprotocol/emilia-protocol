export declare const MAX_JSON_DEPTH = 64;
export interface StrictCanonicalJsonLimits {
    maxDepth?: number;
    maxNodes?: number;
    maxStringBytes?: number;
}
export interface StrictJsonSuccess {
    ok: true;
}
export interface StrictJsonFailure {
    ok: false;
    reason: string;
}
export type StrictJsonResult = StrictJsonSuccess | StrictJsonFailure;
export declare function strictJsonGate(raw: unknown): StrictJsonResult;
/**
 * Canonical bytes for the closed EP JSON domain. Unlike JSON.stringify, this
 * refuses values that can disappear, execute code, or collapse to the same
 * bytes: non-plain objects, sparse arrays, accessors, symbols, cycles,
 * undefined/functions/bigints, non-safe-integer numbers, and malformed UTF-16.
 */
export declare function canonicalizeStrictJson(value: unknown, limits?: StrictCanonicalJsonLimits): string;
/** Pure predicate companion to canonicalizeStrictJson(). */
export declare function isStrictCanonicalJson(value: unknown): boolean;
declare const strictJson: {
    strictJsonGate: typeof strictJsonGate;
    canonicalizeStrictJson: typeof canonicalizeStrictJson;
    isStrictCanonicalJson: typeof isStrictCanonicalJson;
    MAX_JSON_DEPTH: number;
};
export default strictJson;
//# sourceMappingURL=strict-json.d.ts.map