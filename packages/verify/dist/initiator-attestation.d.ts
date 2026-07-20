/**
 * EP-INITIATOR-ATTESTATION-v1 — WHICH software asked (Step 6 knob).
 *
 * A receipt records that a human approved an action. It does not, on its own,
 * record which agent/model composed the request that the human was shown. This
 * module defines a small, canonicalizable attestation that names the initiating
 * software (model id + version) and pins the tool/prompt context it ran, plus an
 * optional free-text statement the software offers to the human.
 *
 *   { "@version": "EP-INITIATOR-ATTESTATION-v1",
 *     model_id:          "anthropic/claude-...",     // WHICH software asked
 *     model_version:     "2026-01-05",               // its build/version
 *     tool_chain_digest: "sha256:<hex>",             // hash of the tool/prompt context it ran
 *     statement:         "<optional free text>" }    // HOSTILE input; see below
 *
 * ──────────────────────────────────────────────────────────────────────────
 * HONEST BOUNDARY — READ THIS. An initiator attestation says WHICH software
 * asked. It does NOT prove the software behaved. model_id/model_version are
 * self-asserted labels: they identify the claimed initiator, they do not attest
 * that the named model actually produced these bytes, nor that it was honest,
 * unmodified, or free of prompt injection. tool_chain_digest binds THIS
 * attestation to a specific tool/prompt context, so a verifier can detect a
 * SWAPPED context, but the digest is over whatever the producer chose to hash;
 * it is authentic-as-supplied, not a proof of correct execution. Binding
 * model_id/model_version into the action digest domain (bindInto()) makes those
 * labels covered by the human's signature, so a later party cannot silently
 * rewrite WHICH software the human was told asked. That is attribution under
 * signature, still not proof of behavior.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * HOSTILE FREE TEXT. `statement` is attacker-influenceable: the initiating
 * software (or an injector upstream of it) chooses the bytes, and those bytes
 * are rendered to a human who is about to approve an irreversible action. It is
 * a presentation-attack surface (bidi overrides that reorder the visible line,
 * C0/C1 controls that hide or spoof content, homoglyphs that impersonate a
 * trusted string). It MUST be neutralized before it reaches a human.
 *
 * NOTE ON REUSE. The frozen WYSIWYS render profile (lib/wysiwys/render.js)
 * neutralizes presentation attacks by making its rendering a PURE, DETERMINISTIC
 * function of a CLOSED set of action fields — it never renders free text, so it
 * carries no bidi/control/homoglyph neutralizer to import. There is no exported
 * hostile-text neutralizer anywhere in the WYSIWYS layer to reuse. That neutralizer
 * SHOULD be factored out and exported (e.g. lib/wysiwys/neutralize.js) so a
 * single implementation covers every free-text surface. Until it is, this module
 * implements the minimal equivalent below: it strips/escapes bidi controls and
 * C0/C1 controls and FLAGS homoglyph risk. neutralizeStatement() is the single
 * entry point; when a shared neutralizer lands, replace the body, not the API.
 *
 * FAIL CLOSED. validateInitiatorAttestation() refuses on any missing required
 * field, any wrong type, any unknown member, and any malformed tool_chain_digest.
 * It never repairs a malformed attestation into a passing one, and it never
 * infers a default model/version/digest — a missing identity is a rejection, not
 * a blank. neutralizeStatement() treats a non-string as the empty statement and
 * escapes rather than silently dropping dangerous codepoints, so nothing hostile
 * passes through unmarked.
 */
export declare const INITIATOR_ATTESTATION_VERSION = "EP-INITIATOR-ATTESTATION-v1";
/** The action-object member under which a bound attestation is placed (bindInto). */
export declare const INITIATOR_ATTESTATION_FIELD = "initiator_software";
/** Free-text `statement` hard cap (characters, post-neutralization is measured pre-escape). */
export declare const INITIATOR_STATEMENT_MAX = 280;
/**
 * Normalize a claimed SHA-256 digest to bare lowercase hex, or '' when malformed.
 * Returning '' on malformed input is the fail-closed convention shared with the
 * sibling modules (time-attestation.js, revocation.js, provenance.js): a bad
 * digest can never compare-equal to a real one. Accepts an OPTIONAL "sha256:"
 * prefix; the canonical stored form re-adds it.
 *
 * @param {unknown} h
 * @returns {string} 64-char lowercase hex, or '' if not a well-formed SHA-256.
 */
export declare function normalizeDigest(h: unknown): string;
/**
 * neutralizeStatement(statement) — render a HOSTILE free-text statement into a
 * form that is safe to place in front of a human.
 *
 * Fail-closed shape: a non-string statement is treated as the empty statement
 * (`""`), never as trusted content. Dangerous codepoints are ESCAPED (visible
 * `<U+XXXX>` markers), not silently deleted, so an attacker cannot hide content
 * behind a drop and a human can see that something was neutralized. C0/C1 control
 * characters (except the everyday whitespace \t \n \r) are escaped; bidi and
 * zero-width/BOM codepoints are escaped; a homoglyph/mixed-script risk is FLAGGED.
 *
 * @param {unknown} statement
 * @returns {{
 *   safe: string,               // the render-safe statement (dangerous codepoints escaped)
 *   changed: boolean,           // true iff any codepoint was escaped
 *   homoglyph_risk: boolean,    // true iff mixed-script / Latin-confusable codepoints present
 *   escaped_codepoints: number[], // the codepoints that were escaped (for forensics)
 *   truncated: boolean,         // true iff the input exceeded INITIATOR_STATEMENT_MAX
 * }}
 */
export declare function neutralizeStatement(statement: unknown): {
    safe: string;
    changed: boolean;
    homoglyph_risk: boolean;
    escaped_codepoints: number[];
    truncated: boolean;
};
/**
 * validateInitiatorAttestation(att) — FAIL-CLOSED structural validation.
 *
 * Enforces: object shape; only the closed member set (unknown member => reject);
 * model_id and model_version present and non-empty strings; @version, when
 * present, equals INITIATOR_ATTESTATION_VERSION; tool_chain_digest present and a
 * well-formed SHA-256; statement, when present, a string within the cap. The
 * `normalized` attestation carries the canonical stored form: a "sha256:"-
 * prefixed lowercase digest and the NEUTRALIZED statement (never the raw hostile
 * bytes). On any error, `ok:false` and `normalized:null` — a malformed
 * attestation is never repaired into a passing one.
 *
 * @param {unknown} att
 * @returns {{ ok: boolean, normalized: object|null, errors: string[],
 *             statement_report: object|null }}
 */
export declare function validateInitiatorAttestation(att: unknown): {
    ok: boolean;
    normalized: Record<string, unknown> | null;
    errors: string[];
    statement_report: ReturnType<typeof neutralizeStatement> | null;
};
/**
 * bindInto(action, att) — bind a validated initiator attestation into the ACTION
 * digest domain so model_id/model_version/tool_chain_digest are covered by the
 * human's signature.
 *
 * COMPOSITION WITH THE FROZEN action hash (does NOT change actionHash()):
 *   The frozen EP action hash is actionHash(action) = "sha256:" +
 *   sha256(canonicalize(action)) over the WHOLE action object, with
 *   canonicalize() sorting keys. This helper returns a NEW action object with
 *   the normalized attestation placed under the reserved member
 *   INITIATOR_ATTESTATION_FIELD ("initiator_software"). Because canonicalize()
 *   includes every member and sorts keys, feeding the returned object to the
 *   UNCHANGED actionHash() yields a hash that now covers the attestation:
 *   the initiator's WHICH-software identity is signed by the human alongside the
 *   action. Callers hash and sign via the existing path; this module supplies
 *   only the field placement, never a second hasher.
 *
 * The bound attestation uses the NEUTRALIZED statement (from
 * validateInitiatorAttestation.normalized), so the very bytes the human's
 * signature covers are the safe ones, not the raw hostile input.
 *
 * FAIL CLOSED: throws if `action` is not a plain object, if the attestation does
 * not validate, or if the action already carries a DIFFERENT value under the
 * reserved member (silently overwriting a caller's field would be a footgun).
 *
 * @param {object} action - the canonical Action Object (I-D §3), pre-hash.
 * @param {unknown} att - an initiator attestation (validated here).
 * @returns {{ action: object, attestation: object, digest_preview: string }}
 *   `action` = a new action object with the attestation bound; `attestation` =
 *   the normalized attestation actually bound; `digest_preview` = the action
 *   digest recomputed the SAME way actionHash() computes it, for the caller to
 *   compare (advisory; the signing path remains the source of truth).
 */
export declare function bindInto(action: Record<string, unknown> | null | undefined, att: unknown): {
    action: {
        initiator_software: Record<string, unknown> | null;
    };
    attestation: Record<string, unknown> | null;
    digest_preview: string;
};
//# sourceMappingURL=initiator-attestation.d.ts.map