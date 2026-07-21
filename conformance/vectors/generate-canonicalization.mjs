// SPDX-License-Identifier: Apache-2.0
// Generated from generate-canonicalization.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
// Generator for EP-CANONICALIZATION-v1 differential vectors: raw JSON texts that
// probe canonicalization malleability (Unicode normalization, bidi/control
// characters, duplicate member names, surrogate handling, IEEE-754 number
// aliases, nesting depth). Digests are computed with the JS reference
// canonicalize() and pinned; the cross-language runner then requires Python and
// Go to reproduce them byte-for-byte. Run: node generate-canonicalization.mjs
import crypto from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { canonicalize, isCanonicalizable } from '../../packages/verify/index.js';
import { strictParseGate, MAX_DEPTH } from '../runners/strict-json.mjs';
const sha256Hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
// Reference pipeline (must match every runner's canonicalization branch).
function pipeline(raw) {
    let value;
    try {
        value = JSON.parse(raw);
    }
    catch {
        return { ok: false, why: 'parse error' };
    }
    const gate = strictParseGate(raw);
    if (!gate.ok)
        return { ok: false, why: gate.reason };
    if (!isCanonicalizable(value))
        return { ok: false, why: 'outside EP I-JSON profile' };
    return { ok: true, digest: sha256Hex(canonicalize(value)) };
}
const V = [];
const digests = {}; // id -> digest, for alias assertions
function accept(id, note, raw) {
    const r = pipeline(raw);
    if (!r.ok)
        throw new Error(`accept vector ${id} refused by reference pipeline: ${r.why}`);
    digests[id] = r.digest;
    V.push({ id, expect: { valid: true }, canonicalization: { input_json: raw, expected_digest: r.digest, note } });
}
function reject(id, note, raw) {
    const r = pipeline(raw);
    if (r.ok)
        throw new Error(`reject vector ${id} was accepted by reference pipeline (digest ${r.digest})`);
    V.push({ id, expect: { valid: false }, canonicalization: { input_json: raw, note } });
}
const assertSame = (a, b) => { if (digests[a] !== digests[b])
    throw new Error(`expected same digest: ${a} vs ${b}`); };
const assertDiff = (a, b) => { if (digests[a] === digests[b])
    throw new Error(`expected distinct digests: ${a} vs ${b}`); };
// ── 1. Unicode normalization: JCS does NOT normalize. NFC and NFD spellings of
//      the same visible text are DIFFERENT byte sequences and MUST pin
//      DISTINCT digests; a verifier that normalizes diverges here.
accept('accept_nfc_composed', 'NFC "café" spelled with precomposed U+00E9; digest pins the composed bytes', '{"note":"café"}');
accept('accept_nfd_decomposed', 'NFD spelling of the same text (e + combining U+0301); MUST digest differently from NFC', '{"note":"café"}');
accept('accept_escape_alias_of_nfc', 'escaped \\u00e9 decodes to the same code point as literal NFC; MUST digest identically to accept_nfc_composed', '{"note":"caf\\u00e9"}');
accept('accept_angstrom_sign_not_normalized', 'U+212B ANGSTROM SIGN is NOT NFC-normalized to U+00C5 by JCS; raw code point pinned', '{"unit":"Å"}');
accept('accept_latin_a_ring_distinct', 'U+00C5 LATIN CAPITAL A WITH RING; MUST digest differently from U+212B', '{"unit":"Å"}');
assertSame('accept_nfc_composed', 'accept_escape_alias_of_nfc');
assertDiff('accept_nfc_composed', 'accept_nfd_decomposed');
assertDiff('accept_angstrom_sign_not_normalized', 'accept_latin_a_ring_distinct');
// ── 2. Bidi and control characters: pinned behavior. Code points >= U+0020 are
//      emitted RAW (including bidi overrides); code points < U+0020 are escaped
//      (shorthand for the seven classics, lowercase \u00xx otherwise).
accept('accept_bidi_rlo_override_raw', 'U+202E RIGHT-TO-LEFT OVERRIDE and U+202C inside a string are emitted raw, not escaped or stripped', '{"payee":"acme‮reversed‬"}');
accept('accept_control_chars_escaped', 'C0 controls canonicalize to lowercase \\u00xx escapes', '{"s":"\\u0000\\u0007\\u001f"}');
accept('accept_shorthand_escapes', 'backspace/tab/newline/formfeed/carriage-return canonicalize to the shorthand escapes', '{"s":"\\b\\t\\n\\f\\r"}');
accept('accept_long_escape_alias_of_shorthand', 'the same five controls written as \\u00xx decode identically; MUST digest identically to accept_shorthand_escapes', '{"s":"\\u0008\\u0009\\u000a\\u000c\\u000d"}');
accept('accept_format_chars_raw', 'U+2028/U+2029 (ES line separators), U+007F DEL, U+FEFF, U+200B are all >= U+0020 and emitted raw', '{"s":"\\u2028\\u2029\\u007f\\ufeff\\u200b"}');
assertSame('accept_shorthand_escapes', 'accept_long_escape_alias_of_shorthand');
// ── 3. Duplicate member names in the raw text: must reject (RFC 8785 s3.1 /
//      I-JSON). Names compare AFTER escape decoding.
reject('reject_duplicate_key_literal', 'same member name twice in one object', '{"a":1,"a":2}');
reject('reject_duplicate_key_escape_alias', '"\\u0061" decodes to "a": still a duplicate after escape decoding', '{"a":1,"\\u0061":2}');
reject('reject_duplicate_key_nested', 'duplicate detection applies at every nesting level', '{"outer":{"k":1,"k":2}}');
reject('reject_duplicate_key_non_bmp_alias', 'literal U+1F600 and its escaped surrogate pair are the same name', '{"😀":1,"\\ud83d\\ude00":2}');
// ── 4. Surrogates (RFC 8785 requires well-formed Unicode; I-JSON forbids
//      unpaired surrogates) and non-BMP round-tripping.
reject('reject_lone_high_surrogate', 'unpaired \\ud800 escape is not valid Unicode', '{"s":"\\ud800"}');
reject('reject_lone_low_surrogate', 'unpaired \\udc00 escape is not valid Unicode', '{"s":"\\udc00"}');
reject('reject_reversed_surrogate_pair', 'low-then-high escape order does not form a code point', '{"s":"\\udc00\\ud800"}');
reject('reject_high_surrogate_then_bmp_escape', 'a high surrogate escape must be followed by a low surrogate escape, not \\u0041', '{"s":"\\ud800\\u0041"}');
reject('reject_lone_surrogate_in_member_name', 'unpaired surrogate in a member name is equally malformed', '{"\\ud800":1}');
accept('accept_non_bmp_escaped_pair', 'escaped surrogate pair \\ud83d\\ude00 decodes to U+1F600 and canonicalizes to the raw 4-byte UTF-8 sequence', '{"s":"\\ud83d\\ude00"}');
accept('accept_non_bmp_literal_alias', 'literal U+1F600 in the raw text; MUST digest identically to accept_non_bmp_escaped_pair', '{"s":"😀"}');
accept('accept_astral_key_utf16_sort_order', 'member sort is by UTF-16 code units: U+1F600 (D83D DE00) sorts BEFORE U+FF61 (FF61); a code-point sort diverges here', '{"｡":true,"😀":1}');
assertSame('accept_non_bmp_escaped_pair', 'accept_non_bmp_literal_alias');
// ── 5. IEEE-754 / number-token aliases. The EP profile allows ONLY safe
//      integers; integer-valued tokens (1, 1.0, 1e0, -0, -0.0) canonicalize to
//      the single ECMAScript serialization; everything else must reject.
accept('accept_integer_one', 'baseline integer token', '{"n":1}');
accept('accept_number_alias_one_point_zero', 'token 1.0 is integer-valued; canonicalizes to "1"; MUST digest identically to accept_integer_one', '{"n":1.0}');
accept('accept_number_alias_exponent', 'token 1e0 is integer-valued; canonicalizes to "1"', '{"n":1e0}');
accept('accept_negative_zero_integer', 'token -0 canonicalizes to "0" (ECMAScript JSON.stringify semantics)', '{"n":-0}');
accept('accept_negative_zero_real_alias', 'token -0.0 also canonicalizes to "0"; MUST digest identically to accept_negative_zero_integer', '{"n":-0.0}');
accept('accept_max_safe_integer', '2^53-1, the largest magnitude inside the EP profile', '{"n":9007199254740991}');
reject('reject_unsafe_integer_2_53', '2^53 is outside the safe-integer profile (fail-closed)', '{"n":9007199254740992}');
reject('reject_unsafe_large_exponent', '1e21 is integer-valued but far outside the safe-integer profile', '{"n":1e21}');
reject('reject_non_integer_real', 'non-integer reals are outside the EP profile; encode as strings', '{"n":1.5}');
assertSame('accept_integer_one', 'accept_number_alias_one_point_zero');
assertSame('accept_integer_one', 'accept_number_alias_exponent');
assertSame('accept_negative_zero_integer', 'accept_negative_zero_real_alias');
// ── 6. Member order and whitespace are erased by canonicalization.
accept('accept_key_order_whitespace_alias', 'unsorted members plus interior whitespace; MUST digest identically to the compact sorted twin', '{ "b" : 2 ,\n  "a" : 1 }');
accept('accept_key_order_canonical_twin', 'compact sorted form of the same object', '{"a":1,"b":2}');
assertSame('accept_key_order_whitespace_alias', 'accept_key_order_canonical_twin');
// ── 7. Nesting depth: the suite pins a shared bound (MAX_DEPTH) at the parse
//      boundary because native limits differ across languages.
const nest = (d) => '{"d":'.repeat(d - 1) + '{"d":1}' + '}'.repeat(d - 1);
accept('accept_nested_depth_at_limit', `container depth exactly ${MAX_DEPTH} is accepted with a pinned digest`, nest(MAX_DEPTH));
reject('reject_nested_depth_over_limit', `container depth ${MAX_DEPTH + 1} exceeds the suite-pinned bound of ${MAX_DEPTH}`, nest(MAX_DEPTH + 1));
const suite = {
    suite: 'EP-CANONICALIZATION-v1',
    profile: 'Differential canonicalization-malleability vectors over the EP canonicalization profile (RFC 8785 JCS over I-JSON, safe integers only). Each vector carries raw JSON text (canonicalization.input_json). A conformant runner MUST: (1) parse it with the language standard JSON parser, rejecting on error; (2) apply the strict-parse gate at the parse boundary: reject duplicate object member names (compared after escape decoding), reject unpaired UTF-16 surrogate escapes, reject container nesting depth greater than 64 (a suite-pinned bound; native limits differ across languages); (3) require the parsed value to satisfy the EP I-JSON profile predicate (isCanonicalizable: every scalar a string, boolean, null, or integer with magnitude <= 2^53-1); (4) compute the SHA-256 over the UTF-8 bytes of the canonical form and compare it to expected_digest. valid == all four steps pass. The pinned digests enforce byte-exact cross-language agreement: JCS does NOT apply Unicode normalization (NFC and NFD pin DISTINCT digests on purpose), escaped and literal spellings of the same code points pin the SAME digest, member names sort by UTF-16 code units, and integer-valued number tokens (1, 1.0, 1e0, -0) pin one canonical serialization. The strict-parse gate lives in each conformance runner because the verify packages receive already-parsed values; steps 3 and 4 exercise the verify packages themselves.',
    vectors_version: '1.0.0',
    count: V.length,
    vectors: V,
};
writeFileSync(new URL('./canonicalization.v1.json', import.meta.url), JSON.stringify(suite, null, 2) + '\n');
console.log(`wrote canonicalization.v1.json — ${V.length} vectors`);
