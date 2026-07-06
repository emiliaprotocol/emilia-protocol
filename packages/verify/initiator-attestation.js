// SPDX-License-Identifier: Apache-2.0
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

import crypto from 'node:crypto';
import { canonicalize } from './index.js';

export const INITIATOR_ATTESTATION_VERSION = 'EP-INITIATOR-ATTESTATION-v1';

/** The action-object member under which a bound attestation is placed (bindInto). */
export const INITIATOR_ATTESTATION_FIELD = 'initiator_software';

/** Free-text `statement` hard cap (characters, post-neutralization is measured pre-escape). */
export const INITIATOR_STATEMENT_MAX = 280;

/** The closed set of members a valid attestation may carry. Unknown members => reject. */
const ATTESTATION_MEMBERS = Object.freeze([
  '@version',
  'model_id',
  'model_version',
  'tool_chain_digest',
  'statement',
]);
const ATTESTATION_MEMBER_SET = new Set(ATTESTATION_MEMBERS);

/** Members that MUST be present and non-empty strings. `statement` is optional. */
const REQUIRED_STRING_MEMBERS = Object.freeze(['model_id', 'model_version']);

const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

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
export function normalizeDigest(h) {
  const s = String(h ?? '').replace(/^sha256:/i, '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(s) ? s : '';
}

// ── hostile-text neutralization ──────────────────────────────────────────────
//
// Minimal, self-contained equivalent of the neutralizer the WYSIWYS layer SHOULD
// export. Handles the three presentation-attack classes called out above. Every
// codepoint it acts on is REPLACED with a visible, unambiguous escape rather than
// deleted, so the neutralized form is lossless-enough for a human to see that
// something was there, and an attacker cannot smuggle content by relying on a
// silent drop.

// Bidi controls (Unicode Bidirectional Algorithm formatting + isolate chars):
// LRE LRO RLE RLO PDF (202A–202E), LRI RLI FSI PDI (2066–2069), and the marks
// LRM RLM ALM (200E, 200F, 061C). These reorder the VISIBLE glyph run relative
// to logical order — the canonical "amount: 100 USD" that displays as a refund.
const BIDI_CODEPOINTS = new Set([
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // LRE RLE PDF LRO RLO
  0x2066, 0x2067, 0x2068, 0x2069,         // LRI RLI FSI PDI
  0x200e, 0x200f, 0x061c,                 // LRM RLM ALM
]);

// Zero-width / joiners / BOM that hide or fuse content: ZWSP ZWNJ ZWJ (200B–200D),
// WORD JOINER (2060), and BOM/ZWNBSP (FEFF).
const INVISIBLE_CODEPOINTS = new Set([0x200b, 0x200c, 0x200d, 0x2060, 0xfeff]);

// Homoglyph risk: any codepoint outside Basic Latin + Latin-1 that has a
// confusable Latin lookalike is a spoofing risk (Cyrillic а/е/о, Greek ο/ν, …).
// We do not attempt a full confusables map here (that belongs in the shared
// neutralizer). We FLAG the risk when the statement mixes scripts, i.e. contains
// non-ASCII letters alongside ASCII letters, or contains codepoints in the known
// Latin-confusable ranges. The flag is advisory to the caller; the escaped output
// is always safe to display regardless of the flag.
const CYRILLIC_RE = /[Ѐ-ӿ]/;
const GREEK_RE = /[Ͱ-Ͽ]/;
const ASCII_LETTER_RE = /[A-Za-z]/;

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
export function neutralizeStatement(statement) {
  // Non-string => empty. NEVER coerce an object/number into displayable content.
  const raw = typeof statement === 'string' ? statement : '';

  // Cap length BEFORE escaping so an attacker cannot blow the cap with escape
  // expansion, and measure by codepoints (Array.from) not UTF-16 units.
  const cps = Array.from(raw);
  const truncated = cps.length > INITIATOR_STATEMENT_MAX;
  const bounded = truncated ? cps.slice(0, INITIATOR_STATEMENT_MAX) : cps;

  const escaped = [];
  let changed = false;
  let hasNonAsciiLetter = false;
  let hasAsciiLetter = false;
  let hasConfusableScript = false;

  const out = bounded.map((ch) => {
    const cp = ch.codePointAt(0);

    // Script/confusable tracking for the homoglyph flag.
    if (ASCII_LETTER_RE.test(ch)) hasAsciiLetter = true;
    if (cp > 0x7f && /\p{L}/u.test(ch)) hasNonAsciiLetter = true;
    if (CYRILLIC_RE.test(ch) || GREEK_RE.test(ch)) hasConfusableScript = true;

    const isBidi = BIDI_CODEPOINTS.has(cp);
    const isInvisible = INVISIBLE_CODEPOINTS.has(cp);
    // C0 controls 0x00–0x1F and C1 controls 0x80–0x9F, minus the everyday
    // whitespace we allow to pass (tab, newline, carriage return).
    const isControl =
      ((cp <= 0x1f && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d) ||
        (cp >= 0x7f && cp <= 0x9f));

    if (isBidi || isInvisible || isControl) {
      changed = true;
      escaped.push(cp);
      return `<U+${cp.toString(16).toUpperCase().padStart(4, '0')}>`;
    }
    return ch;
  });

  const homoglyph_risk = hasConfusableScript || (hasNonAsciiLetter && hasAsciiLetter);

  return {
    safe: out.join(''),
    changed,
    homoglyph_risk,
    escaped_codepoints: escaped,
    truncated,
  };
}

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
export function validateInitiatorAttestation(att) {
  const errors = [];
  const fail = () => ({ ok: false, normalized: null, errors, statement_report: null });

  if (!att || typeof att !== 'object' || Array.isArray(att)) {
    errors.push('initiator attestation must be a non-array object');
    return fail();
  }

  // Closed member set — unknown members are rejected, not ignored, so a producer
  // cannot smuggle unbound side-channel content past a permissive verifier.
  for (const key of Object.keys(att)) {
    if (!ATTESTATION_MEMBER_SET.has(key)) {
      errors.push(`unknown member "${key}" (allowed: ${ATTESTATION_MEMBERS.join(', ')})`);
    }
  }

  // Version, when present, must be exactly ours. Absence is tolerated (the
  // normalized form stamps it) but a WRONG version is a hard reject.
  if (att['@version'] !== undefined && att['@version'] !== INITIATOR_ATTESTATION_VERSION) {
    errors.push(`@version must be ${INITIATOR_ATTESTATION_VERSION} when present`);
  }

  // Required identity strings.
  for (const key of REQUIRED_STRING_MEMBERS) {
    const v = att[key];
    if (typeof v !== 'string' || v.length === 0) {
      errors.push(`${key} is required and must be a non-empty string`);
    }
  }

  // tool_chain_digest: required, well-formed SHA-256.
  const digestHex = normalizeDigest(att.tool_chain_digest);
  if (att.tool_chain_digest === undefined || att.tool_chain_digest === null) {
    errors.push('tool_chain_digest is required');
  } else if (digestHex === '') {
    errors.push('tool_chain_digest must be a well-formed SHA-256 (optionally "sha256:"-prefixed 64-hex)');
  }

  // statement: optional; must be a string within the cap when present. It is
  // neutralized below regardless of type, but a wrong TYPE is a rejectable
  // malformation (an object/number statement is a producer bug or an attack).
  let statementReport = null;
  if (att.statement !== undefined) {
    if (typeof att.statement !== 'string') {
      errors.push('statement, when present, must be a string');
    } else if (Array.from(att.statement).length > INITIATOR_STATEMENT_MAX) {
      errors.push(`statement exceeds the ${INITIATOR_STATEMENT_MAX}-character cap`);
    }
  }

  if (errors.length) return fail();

  // Neutralize the (validated) statement for the normalized form. Even a
  // well-formed statement is hostile input; the normalized attestation NEVER
  // carries the raw bytes.
  if (att.statement !== undefined) {
    statementReport = neutralizeStatement(att.statement);
  }

  const normalized = {
    '@version': INITIATOR_ATTESTATION_VERSION,
    model_id: att.model_id,
    model_version: att.model_version,
    tool_chain_digest: `sha256:${digestHex}`,
  };
  if (statementReport) normalized.statement = statementReport.safe;

  return { ok: true, normalized, errors, statement_report: statementReport };
}

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
export function bindInto(action, att) {
  if (!action || typeof action !== 'object' || Array.isArray(action)) {
    throw new TypeError('bindInto requires the canonical Action Object');
  }
  const v = validateInitiatorAttestation(att);
  if (!v.ok) {
    throw new Error(`bindInto: invalid initiator attestation: ${v.errors.join('; ')}`);
  }
  const existing = action[INITIATOR_ATTESTATION_FIELD];
  if (existing !== undefined && canonicalize(existing) !== canonicalize(v.normalized)) {
    throw new Error(
      `bindInto: action already carries a different ${INITIATOR_ATTESTATION_FIELD}; refusing to overwrite`,
    );
  }
  const bound = { ...action, [INITIATOR_ATTESTATION_FIELD]: v.normalized };
  // Recompute exactly as the frozen actionHash() does: "sha256:" + sha256(canonicalize(action)).
  // We do NOT import or alter actionHash(); we mirror its definition so the
  // preview is byte-identical to what the signing path will produce.
  const digest_preview = `sha256:${sha256hex(canonicalize(bound))}`;
  return { action: bound, attestation: v.normalized, digest_preview };
}
