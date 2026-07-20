export declare const PREDICATE_OPS: readonly string[];
export declare const DIVERGENCE_OUTCOMES: readonly string[];
export declare const MAX_PREDICTED_EFFECTS = 64;
export declare const MAX_OBSERVED_EFFECTS = 256;
export declare const MAX_EFFECT_STRING_LENGTH = 512;
/**
 * Digest of a predicted-effects array: sha256 over its canonical bytes.
 * This is the value the receipt payload binds as predicted_effects_digest.
 */
export declare function predictedEffectsDigest(predictedEffects: any): string;
/** Is s a decimal string this module can order exactly? */
export declare function isDecimalString(s: unknown): boolean;
/**
 * Exact ordering of two decimal strings: -1 | 0 | 1, or null when either
 * input is not a decimal string (callers MUST treat null as incomparable,
 * never as equality — fail closed).
 */
export declare function compareDecimalStrings(a: unknown, b: unknown): number | null;
/**
 * Validate a predicted_effects array structurally. Returns {ok, reasons}.
 * Strict on the SIGNED side: unknown ops, unknown members, and numeric
 * comparison values are all malformed (fail closed — never evaluate a
 * prediction whose intent this evaluator might silently misread).
 */
export declare function validatePredictedEffects(predicted: any): {
    ok: boolean;
    reasons: string[];
};
/**
 * Evaluate a signed predicted_effects array against executor-attested
 * observed effects. Pure and deterministic: same inputs -> same outcome,
 * same reasons, in the same order (replayable by any third party).
 *
 * @param {Array} predicted  [{effect_type, target, predicate}] — the array
 *                           the human signed (validated strictly here).
 * @param {Array} observed   [{effect_type, target, value?|values?}] —
 *                           executor-attested closed objects.
 * @returns {{ outcome: 'in_bounds'|'divergent'|'incomparable',
 *            results: Array<{effect_type,target,op,outcome,reason}>,
 *            reasons: string[] }}
 */
export declare function evaluatePredictedEffects(predicted: any, observed: any): {
    outcome: 'in_bounds' | 'divergent' | 'incomparable';
    results: Array<{
        effect_type: string;
        target: string;
        op: string;
        outcome: string;
        reason: string | null;
    }>;
    reasons: string[];
};
//# sourceMappingURL=effect-predicates.d.ts.map