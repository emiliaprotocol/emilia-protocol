/**
 * hostile-text — the single implementation of presentation-attack codepoint
 * classification for every surface that puts attacker-influenced text in front
 * of a human approver.
 *
 * WHY THIS MODULE EXISTS. Two surfaces need the same judgement and used to
 * disagree about whether they needed it at all:
 *
 *   1. The initiator `statement` (initiator-attestation.ts) is openly hostile
 *      free text and has always been neutralized before display.
 *   2. The WYSIWYS render profile renders a CLOSED set of action fields, which
 *      was documented as making a neutralizer unnecessary. That reasoning was
 *      wrong: a closed set of FIELD NAMES says nothing about the bytes inside
 *      those fields, and `target_resource_id`, `actor_id` and `policy_id` are
 *      initiator-supplied strings. A right-to-left override inside an account
 *      identifier reorders the visible glyph run, so the approver reads one
 *      account and signs another. Both hashes cover the hostile bytes, so the
 *      display attestation is faithful and verification passes — the deception
 *      is purely visual, aimed at exactly the human WYSIWYS exists to protect.
 *
 * The two surfaces still respond differently, and that difference is deliberate.
 * Free text is ESCAPED (it must still be shown). Structured action fields are
 * REFUSED at input (there is no legitimate bidi override in an account id, and
 * refusing keeps the frozen render profile byte-identical). Both decisions read
 * from the one classification below, so they can never drift apart.
 */
export declare const BIDI_CODEPOINTS: ReadonlySet<number>;
export declare const INVISIBLE_CODEPOINTS: ReadonlySet<number>;
/**
 * C0 controls 0x00–0x1F and C1 controls 0x7F–0x9F, minus the everyday
 * whitespace allowed to pass (tab, newline, carriage return).
 */
export declare function isControlCodepoint(cp: number): boolean;
/** True for any codepoint that can misrepresent a rendering to a human. */
export declare function isHostileCodepoint(cp: number): boolean;
/** The visible, unambiguous escape form. Never a silent drop. */
export declare function escapeCodepoint(cp: number): string;
/**
 * scanHostileText(value) — classify a value without transforming it.
 *
 * Fail-closed shape: a non-string is reported as clean rather than coerced into
 * displayable content. Callers that accept structured values walk them first.
 *
 * @returns the offending codepoints in order of first appearance (deduplicated),
 *   empty when the value is safe to render.
 */
export declare function scanHostileText(value: unknown): number[];
/** Convenience predicate over {@link scanHostileText}. */
export declare function hasHostileText(value: unknown): boolean;
/**
 * Recursively scan a structured value (the shape action fields actually take:
 * strings, numbers, arrays, plain objects). Object KEYS are scanned too — a
 * hostile key renders just as visibly as a hostile value once the object is
 * canonicalized into a rendered line.
 */
export declare function scanHostileDeep(value: unknown, depth?: number): number[];
/** Render the codepoint list for a refusal reason: "U+202E, U+200B". */
export declare function formatCodepoints(codepoints: number[]): string;
//# sourceMappingURL=hostile-text.d.ts.map