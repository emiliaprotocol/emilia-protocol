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

// Bidi controls (Unicode Bidirectional Algorithm formatting + isolate chars):
// LRE LRO RLE RLO PDF (202A–202E), LRI RLI FSI PDI (2066–2069), and the marks
// LRM RLM ALM (200E, 200F, 061C). These reorder the VISIBLE glyph run relative
// to logical order — the canonical "amount: 100 USD" that displays as a refund.
export const BIDI_CODEPOINTS: ReadonlySet<number> = new Set([
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // LRE RLE PDF LRO RLO
  0x2066, 0x2067, 0x2068, 0x2069,         // LRI RLI FSI PDI
  0x200e, 0x200f, 0x061c,                 // LRM RLM ALM
]);

// Zero-width / joiners / BOM that hide or fuse content: ZWSP ZWNJ ZWJ (200B–200D),
// WORD JOINER (2060), and BOM/ZWNBSP (FEFF).
export const INVISIBLE_CODEPOINTS: ReadonlySet<number> = new Set([
  0x200b, 0x200c, 0x200d, 0x2060, 0xfeff,
]);

/**
 * C0 controls 0x00–0x1F and C1 controls 0x7F–0x9F, minus the everyday
 * whitespace allowed to pass (tab, newline, carriage return).
 */
export function isControlCodepoint(cp: number): boolean {
  return (cp <= 0x1f && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d)
    || (cp >= 0x7f && cp <= 0x9f);
}

/** True for any codepoint that can misrepresent a rendering to a human. */
export function isHostileCodepoint(cp: number): boolean {
  return BIDI_CODEPOINTS.has(cp) || INVISIBLE_CODEPOINTS.has(cp) || isControlCodepoint(cp);
}

/** The visible, unambiguous escape form. Never a silent drop. */
export function escapeCodepoint(cp: number): string {
  return `<U+${cp.toString(16).toUpperCase().padStart(4, '0')}>`;
}

/**
 * scanHostileText(value) — classify a value without transforming it.
 *
 * Fail-closed shape: a non-string is reported as clean rather than coerced into
 * displayable content. Callers that accept structured values walk them first.
 *
 * @returns the offending codepoints in order of first appearance (deduplicated),
 *   empty when the value is safe to render.
 */
export function scanHostileText(value: unknown): number[] {
  if (typeof value !== 'string' || value.length === 0) return [];
  const found: number[] = [];
  const seen = new Set<number>();
  for (const ch of value) {
    const cp = ch.codePointAt(0) as number;
    if (isHostileCodepoint(cp) && !seen.has(cp)) {
      seen.add(cp);
      found.push(cp);
    }
  }
  return found;
}

/** Convenience predicate over {@link scanHostileText}. */
export function hasHostileText(value: unknown): boolean {
  return scanHostileText(value).length > 0;
}

/**
 * Recursively scan a structured value (the shape action fields actually take:
 * strings, numbers, arrays, plain objects). Object KEYS are scanned too — a
 * hostile key renders just as visibly as a hostile value once the object is
 * canonicalized into a rendered line.
 */
export function scanHostileDeep(value: unknown, depth = 0): number[] {
  if (depth > 16) return [];
  if (typeof value === 'string') return scanHostileText(value);
  if (Array.isArray(value)) {
    const out: number[] = [];
    for (const item of value) out.push(...scanHostileDeep(item, depth + 1));
    return [...new Set(out)];
  }
  if (value && typeof value === 'object') {
    const out: number[] = [];
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out.push(...scanHostileText(k), ...scanHostileDeep(v, depth + 1));
    }
    return [...new Set(out)];
  }
  return [];
}

/** Render the codepoint list for a refusal reason: "U+202E, U+200B". */
export function formatCodepoints(codepoints: number[]): string {
  return codepoints.map((cp) => `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`).join(', ');
}
