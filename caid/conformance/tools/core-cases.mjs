// SPDX-License-Identifier: Apache-2.0
//
// The hand-written cases that corpus version 5 adds to the version 4
// vectors. Each case states its expected outcome in the terms a reader
// checks against the draft: the refusal or reason list, "ok", "valid",
// true/false for decode, or "invalid" for a definition digest. The builder
// (build-core.mjs) fills in the derived members (CAID, digest,
// definition_sha256, verification details) from the spec oracle and fails
// if the oracle disagrees with any stated expectation.
//
// Case shape:
//   {id, kind, description, definitions?, input, expect, relation?,
//    time_budget_ms?, same_definition_sha256_as?, different_definition_sha256_from?}
// input for compute and verify is one of {json}, {json_b64}, {json_repeat}
// or {native}, plus suite (compute), caid and expected_definition_sha256
// (verify). A verify case may give caid_of: {json | native, definitions}
// instead of caid, and the builder computes that object's CAID.

const H64 = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
const D = (h = H64) => `sha256:${h}`;
const j = (v) => JSON.stringify(v);
const b64 = (bytes) => Buffer.from(bytes).toString('base64');
const utf8 = (s) => [...Buffer.from(s, 'utf8')];

// ---------------------------------------------------------------- definitions

const ISO4217 = {
  values_ref: 'ISO 4217 alpha-3',
  values_snapshot: 'SIX ISO 4217 List One published 2026-09-17',
  values_sha256: 'sha256:27f824317e9f271b956123fb77608daece5106e1ee8253a17769390855ade270',
};

const T1 = { action_type: 't.1', required_fields: [{ name: 's', type: 'string' }] };
const OBJ = {
  action_type: 't.obj.1',
  required_fields: [{ name: 's', type: 'string' }],
  optional_fields: [{ name: 'o', type: 'object' }, { name: 'a', type: 'array' }, { name: 'n', type: 'integer' }],
};
// Phases 3 and 4 in one type: three required fields and two optional ones.
const PX = {
  action_type: 'p.1',
  required_fields: [
    { name: 'a', type: 'amount-string' },
    { name: 'b', type: 'string' },
    { name: 'c', type: 'digest' },
  ],
  optional_fields: [
    { name: 'd', type: 'integer' },
    { name: 'e', type: 'code', code_system: 'http://hl7.org/fhir/sid/icd-10-cm', format: 'icd-10-cm' },
  ],
};
const PX_OK = { action_type: 'p.1', a: '1.00', b: 'x', c: D() };
const DOC = {
  action_type: 'doc.sign.1',
  required_fields: [
    { name: 'document', type: 'digest' },
    { name: 'signer_hint', type: 'string' },
    { name: 'signed_at', type: 'timestamp' },
  ],
  optional_fields: [{ name: 'page_count', type: 'integer' }],
};
const DOC_OK = { action_type: 'doc.sign.1', document: D(), signer_hint: 's.okafor', signed_at: '2026-07-08T09:30:00Z' };
const CUR = { action_type: 'test.currency.1', required_fields: [{ name: 'currency', type: 'enum', ...ISO4217 }] };

const CODE_SYSTEMS = {
  'icd-10-cm': 'http://hl7.org/fhir/sid/icd-10-cm',
  'ndc-11': 'http://hl7.org/fhir/sid/ndc',
  'ndc-10-hyphenated': 'http://hl7.org/fhir/sid/ndc',
  cpt: 'http://www.ama-assn.org/go/cpt',
  'hcpcs-level-ii': 'https://www.cms.gov/Medicare/Coding/HCPCSReleaseCodeSets',
  hcpcs: 'https://www.cms.gov/Medicare/Coding/HCPCSReleaseCodeSets',
  'iso-3166-1-alpha-2': 'urn:iso:std:iso:3166',
  'iso-3166-2': 'urn:iso:std:iso:3166:-2',
  'iso20022-external-code': 'https://www.iso20022.org/catalogue-messages/additional-content-messages/external-code-sets',
  'nacha-sec': 'https://www.nacha.org/rules/standard-entry-class-codes',
};
const codeDef = (format) => ({
  action_type: `test.code.${format}.1`,
  required_fields: [{ name: 'f', type: 'code', code_system: CODE_SYSTEMS[format], format }],
});

// ---------------------------------------------------------------- helpers

const compute = (id, description, definitions, input, expect, extra = {}) => ({
  id, kind: 'compute', description, definitions, input: { ...input, suite: input.suite === undefined ? 'jcs-sha256' : input.suite }, expect, ...extra,
});
const computeNoSuite = (id, description, definitions, input, expect) => ({ id, kind: 'compute', description, definitions, input, expect });
const verify = (id, description, definitions, input, expect, extra = {}) => ({ id, kind: 'verify', description, definitions, input, expect, ...extra });
const decode = (id, description, input, ok) => ({ id, kind: 'decode', description, input, expect: ok });
const parse = (id, description, caid, expect) => ({ id, kind: 'parse', description, input: { caid }, expect });
const defn = (id, description, definition, expect, extra = {}) => ({ id, kind: 'definition', description, input: { definition }, expect, ...extra });
const text = (s) => ({ json: s });
const bytes = (arr) => ({ json_b64: b64(arr) });
const native = (v) => ({ native: v });
const units = (s) => ({ $units: [...s].flatMap((ch) => { const c = ch.codePointAt(0); return c > 0xffff ? [0xd800 + ((c - 0x10000) >> 10), 0xdc00 + ((c - 0x10000) & 0x3ff)] : [c]; }) });
const nest = (depth, leaf, container = 'array') => ({ $nest: { depth, container, leaf } });
const deepArrays = (depth, leaf = '0') => '['.repeat(depth) + leaf + ']'.repeat(depth);

const VALID_DIGEST = 'liLG9pKgkLt3silrjf1wa0xIHz5YFrBB9HI-arxrO1Y';
const PAYMENT_CAID = `caid:1:payment.release.1:jcs-sha256:${VALID_DIGEST}`;

export function coreCases({ limits }) {
  const cases = [];
  const add = (...cs) => cases.push(...cs);

  // ------------------------------------------------------------ decode
  add(
    decode('decode-object', 'a plain object decodes', text('{"a":1,"b":[true,false,null],"c":"x"}'), true),
    decode('decode-surrounding-whitespace', 'the four JSON white space characters may surround the text', text(' \t\r\n{}\n\t '), true),
    decode('decode-top-level-string', 'a JSON text need not be an object to decode; computation then refuses it as invalid_action_type', text('"x"'), true),
    decode('decode-escapes', 'every RFC 8259 escape, including an escaped solidus and a surrogate pair', text('{"a":"\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041\\ud83d\\ude00"}'), true),
    decode('decode-raw-astral', 'an astral character written as raw UTF-8', text('{"a":"\u{1F600}\u{10000}\u{10FFFD}"}'), true),
    decode('decode-noncharacter-neighbours', 'U+FFFD, U+FDCF, U+FDF0, U+FFFC and U+10FFFD are not noncharacters', text('{"a":"\\ufffd\\ufdcf\\ufdf0\\ufffc\\udbff\\udffd"}'), true),
    decode('decode-raw-del', 'U+007F is not a control character under RFC 8259 and may appear unescaped', text('{"a":"\u007f"}'), true),
    decode('decode-not-duplicate-case', 'member names that differ only in case are different names', text('{"a":1,"A":2}'), true),
    decode('decode-not-duplicate-normalization', 'NFC and NFD spellings are different code point sequences, so they are not duplicates', text('{"\\u00e9":1,"e\\u0301":2}'), true),
    decode('decode-number-5000-digits', 'the decoder never refuses a number token; the data-model number rule decides it later', text(`[${'1'.repeat(5000)}]`), true),
    decode('decode-number-overflow', 'a literal that overflows binary64 decodes; the number rule refuses it', text('[1e400,-1e400,1e-400]'), true),
    decode('decode-depth-64', 'nesting of exactly 64 is accepted', text(deepArrays(64)), true),
    decode('decode-depth-64-objects', 'nesting of exactly 64 objects is accepted', text('{"a":'.repeat(63) + '{}' + '}'.repeat(63)), true),
    decode('refuse-decode-depth-65', 'nesting of 65 arrays is refused', text(deepArrays(65)), false),
    decode('refuse-decode-depth-65-objects', 'nesting of 65 objects is refused', text('{"a":'.repeat(64) + '{}' + '}'.repeat(64)), false),
    decode('refuse-decode-depth-65-empty', 'an empty array at depth 65 still counts', text('['.repeat(64) + '[]' + ']'.repeat(64)), false),
    decode('refuse-decode-duplicate-names', 'duplicate member names are refused', text('{"a":1,"a":1}'), false),
    decode('refuse-decode-duplicate-escaped-spelling', '"a" and "\\u0061" are the same name after unescaping', text('{"a":1,"\\u0061":2}'), false),
    decode('refuse-decode-duplicate-surrogate-pair-spelling', 'a raw astral name and its surrogate-pair escape are the same name', text('{"\u{1F600}":1,"\\ud83d\\ude00":2}'), false),
    decode('refuse-decode-duplicate-nested', 'duplicates are refused at any depth', text('{"x":[{"b":1,"b":2}]}'), false),
    decode('refuse-decode-bom', 'a leading UTF-8 byte order mark is refused', bytes([0xef, 0xbb, 0xbf, ...utf8('{}')]), false),
    decode('refuse-decode-utf16le', 'UTF-16LE text is not UTF-8', bytes([0x7b, 0x00, 0x7d, 0x00]), false),
    decode('refuse-decode-utf16be-bom', 'UTF-16BE text with a byte order mark', bytes([0xfe, 0xff, 0x00, 0x7b, 0x00, 0x7d]), false),
    decode('refuse-decode-utf32le', 'UTF-32LE text', bytes([0x7b, 0, 0, 0, 0x7d, 0, 0, 0]), false),
    decode('refuse-decode-invalid-utf8-byte', 'the byte 0xFF never occurs in UTF-8', bytes([...utf8('{"a":"'), 0xff, ...utf8('"}')]), false),
    decode('refuse-decode-latin1-byte', 'a Latin-1 e-acute (0xE9) is not UTF-8; it is never read as U+FFFD', bytes([...utf8('{"a":"'), 0xe9, ...utf8('"}')]), false),
    decode('refuse-decode-overlong-utf8', 'an overlong two-byte encoding of "/"', bytes([...utf8('{"a":"'), 0xc0, 0xaf, ...utf8('"}')]), false),
    decode('refuse-decode-utf8-encoded-surrogate', 'the generalized UTF-8 (WTF-8) bytes of U+D800', bytes([...utf8('{"a":"'), 0xed, 0xa0, 0x80, ...utf8('"}')]), false),
    decode('refuse-decode-truncated-utf8', 'a three-byte sequence cut after two bytes', bytes([...utf8('{"a":"'), 0xe2, 0x82, ...utf8('"}')]), false),
    decode('refuse-decode-utf8-above-10ffff', 'a four-byte sequence above U+10FFFF', bytes([...utf8('{"a":"'), 0xf4, 0x90, 0x80, 0x80, ...utf8('"}')]), false),
    decode('refuse-decode-lone-high-surrogate-escape', 'an escaped high surrogate followed by a quote', text('{"a":"\\ud800"}'), false),
    decode('refuse-decode-lone-low-surrogate-escape', 'an escaped low surrogate with no high surrogate', text('{"a":"\\udc00"}'), false),
    decode('refuse-decode-high-surrogate-then-bmp-escape', 'an escaped high surrogate followed by an escaped non-surrogate', text('{"a":"\\ud800\\u0041"}'), false),
    decode('refuse-decode-two-high-surrogate-escapes', 'two escaped high surrogates', text('{"a":"\\ud800\\ud800"}'), false),
    decode('refuse-decode-reversed-surrogate-escapes', 'a low surrogate escape before a high surrogate escape', text('{"a":"\\udc00\\ud800"}'), false),
    decode('refuse-decode-lone-surrogate-member-name', 'an unpaired surrogate escape in a member name', text('{"\\ud800":1}'), false),
    decode('refuse-decode-noncharacter-escape-ffff', 'I-JSON excludes noncharacters: an escaped U+FFFF', text('{"a":"\\uffff"}'), false),
    decode('refuse-decode-noncharacter-escape-fffe', 'an escaped U+FFFE', text('{"a":"x\\ufffe"}'), false),
    decode('refuse-decode-noncharacter-raw-fdd0', 'a raw U+FDD0', bytes([...utf8('{"a":"'), 0xef, 0xb7, 0x90, ...utf8('"}')]), false),
    decode('refuse-decode-noncharacter-plane-16', 'U+10FFFF written as a surrogate-pair escape', text('{"a":"\\udbff\\udfff"}'), false),
    decode('refuse-decode-noncharacter-member-name', 'a noncharacter in a member name', text('{"\\ufdef":1}'), false),
    decode('refuse-decode-unescaped-tab', 'an unescaped tab inside a string', text('{"a":"\t"}'), false),
    decode('refuse-decode-unescaped-nul', 'an unescaped U+0000 inside a string', bytes([...utf8('{"a":"'), 0x00, ...utf8('"}')]), false),
    decode('refuse-decode-unescaped-line-feed', 'an unescaped line feed inside a string', text('{"a":"x\ny"}'), false),
    decode('refuse-decode-trailing-content', 'content after the JSON value', text('{}x'), false),
    decode('refuse-decode-two-texts', 'two JSON texts', text('{} {}'), false),
    decode('refuse-decode-trailing-comma-object', 'a trailing comma in an object', text('{"a":1,}'), false),
    decode('refuse-decode-trailing-comma-array', 'a trailing comma in an array', text('[1,]'), false),
    decode('refuse-decode-nan', 'NaN is not JSON', text('{"a":NaN}'), false),
    decode('refuse-decode-infinity', 'Infinity is not JSON', text('{"a":-Infinity}'), false),
    decode('refuse-decode-single-quotes', 'single-quoted strings are not JSON', text("{'a':1}"), false),
    decode('refuse-decode-comment', 'comments are not JSON', text('{"a":1/*c*/}'), false),
    decode('refuse-decode-leading-zero', 'a number with a leading zero', text('[01]'), false),
    decode('refuse-decode-plus-sign', 'a number with a plus sign', text('[+1]'), false),
    decode('refuse-decode-bare-fraction', 'a fraction with no integer part', text('[.5]'), false),
    decode('refuse-decode-empty-fraction', 'a decimal point with no digits after it', text('[1.]'), false),
    decode('refuse-decode-hex-number', 'a hexadecimal number', text('[0x10]'), false),
    decode('refuse-decode-bad-escape', 'an undefined escape', text('{"a":"\\x41"}'), false),
    decode('refuse-decode-short-unicode-escape', 'a \\u escape with three hex digits', text('{"a":"\\u041"}'), false),
    decode('refuse-decode-uppercase-u-escape', '\\U is not an escape', text('{"a":"\\U0041"}'), false),
    decode('refuse-decode-bad-literal', 'a truncated literal', text('[tru]'), false),
    decode('refuse-decode-nbsp-whitespace', 'U+00A0 is not JSON white space', text(' {}'), false),
    decode('refuse-decode-form-feed-whitespace', 'form feed is not JSON white space', text('\f{}'), false),
    decode('refuse-decode-vertical-tab-whitespace', 'vertical tab is not JSON white space', text('\u000b{}'), false),
    decode('refuse-decode-empty', 'empty input is not a JSON text', text(''), false),
    decode('refuse-decode-whitespace-only', 'white space alone is not a JSON text', text(' \n'), false),
  );

  // ------------------------------------------------------------ JSON text at compute and verify
  const t1 = (s) => j({ action_type: 't.1', s });
  const sizeFill = limits.json_text_octets - t1('x').length;
  add(
    compute('compute-text-size-at-limit', 'a JSON text of exactly 33554432 octets (a small object plus white space) is accepted', [T1],
      { json_repeat: { prefix: t1('x'), unit: ' ', count: sizeFill, suffix: '' } }, 'ok', { relation: { same_caid_as: 'compute-text-small' } }),
    compute('compute-text-small', 'the same object without the white space', [T1], text(t1('x')), 'ok', { relation: { same_caid_as: 'compute-text-size-at-limit' } }),
    compute('refuse-text-size-over-limit', 'one more octet of white space is over the JSON text limit', [T1],
      { json_repeat: { prefix: t1('x'), unit: ' ', count: sizeFill + 1, suffix: '' } }, { refusals: ['malformed_json'] }),
    verify('verify-refuse-text-size-over-limit', 'the JSON text limit applies to verification too', [T1],
      { json_repeat: { prefix: t1('x'), unit: ' ', count: sizeFill + 1, suffix: '' }, caid_of: { json: t1('x'), definitions: [T1] } }, { reasons: ['malformed_json'] }),
  );
  // Canonical size: {"action_type":"t.1","s":"xxx..."} is its own canonical form.
  const canonFill = limits.canonical_octets - t1('').length;
  add(
    compute('compute-canonical-size-at-limit', 'an object whose RFC 8785 encoding is exactly 16777216 octets computes', [T1],
      { json_repeat: { prefix: '{"action_type":"t.1","s":"', unit: 'x', count: canonFill, suffix: '"}' } }, 'ok'),
    compute('refuse-canonical-size-over-limit', 'one more octet of canonical encoding is unsupported_value', [T1],
      { json_repeat: { prefix: '{"action_type":"t.1","s":"', unit: 'x', count: canonFill + 1, suffix: '"}' } }, { refusals: ['unsupported_value'] }),
    compute('refuse-canonical-size-over-limit-with-phase-3-and-4', 'the canonical-size refusal joins field refusals in phase order', [PX],
      { json_repeat: { prefix: '{"action_type":"p.1","a":"01","c":"' + D() + '","pad":"', unit: 'x', count: limits.canonical_octets, suffix: '"}' } },
      { refusals: ['missing_material_field:b', 'invalid_amount:a', 'unsupported_value'] }),
    compute('refuse-canonical-size-not-measured-with-bad-number', 'a value outside the number rule has no RFC 8785 encoding, so its size is not measured: only unsupported_number', [T1],
      { json_repeat: { prefix: '{"action_type":"t.1","n":1.5,"s":"', unit: 'x', count: canonFill + 1, suffix: '"}' } }, { refusals: ['unsupported_number'] }),
    verify('verify-refuse-canonical-size-over-limit', 'an oversized object is invalid_object and its digest is not compared', [T1],
      { json_repeat: { prefix: '{"action_type":"t.1","s":"', unit: 'x', count: canonFill + 1, suffix: '"}' }, caid: 'caid:1:t.1:jcs-sha256:' + VALID_DIGEST }, { reasons: ['invalid_object'] }),
  );
  add(
    compute('compute-depth-64', 'an action object nested exactly 64 deep computes', [OBJ],
      text('{"action_type":"t.obj.1","s":"x","a":' + deepArrays(63) + '}'), 'ok'),
    compute('refuse-depth-65-text', 'from JSON text, nesting of 65 is malformed_json', [OBJ],
      text('{"action_type":"t.obj.1","s":"x","a":' + deepArrays(64) + '}'), { refusals: ['malformed_json'] }),
    compute('refuse-depth-65-native', 'a host value nested 65 deep is unsupported_value', [OBJ],
      native({ action_type: 't.obj.1', s: 'x', a: nest(64, 0) }), { refusals: ['unsupported_value'] }),
    compute('compute-depth-64-native', 'a host value nested exactly 64 deep computes, with the CAID of the same JSON text', [OBJ],
      native({ action_type: 't.obj.1', s: 'x', a: nest(63, 0) }), 'ok', { relation: { same_caid_as: 'compute-depth-64' } }),
    compute('refuse-duplicate-action-type', 'duplicate member names at compute are malformed_json, never the last value', [T1],
      text('{"action_type":"zz.1","action_type":"t.1","s":"x"}'), { refusals: ['malformed_json'] }),
    compute('refuse-duplicate-escaped-member', 'an escaped spelling does not hide a duplicate; the refusal is not laundered by the later value', [T1],
      text('{"action_type":"t.1","s":"\\ud800","\\u0073":"x"}'), { refusals: ['malformed_json'] }),
    compute('refuse-bom-at-compute', 'a byte order mark at compute', [T1], bytes([0xef, 0xbb, 0xbf, ...utf8(t1('x'))]), { refusals: ['malformed_json'] }),
    compute('refuse-invalid-utf8-at-compute', 'the byte 0xE9 is never read as U+FFFD, so this never gets the CAID of compute-replacement-character', [{ action_type: 'test.text.1', required_fields: [{ name: 'c', type: 'string' }], optional_fields: [] }],
      bytes([...utf8('{"action_type":"test.text.1","c":"'), 0xe9, ...utf8('"}')]), { refusals: ['malformed_json'] }),
    compute('refuse-noncharacter-text', 'a noncharacter in JSON text is malformed_json', [T1], text('{"action_type":"t.1","s":"\\uffff"}'), { refusals: ['malformed_json'] }),
    compute('refuse-noncharacter-native', 'a noncharacter in a host string is outside the data model: RFC 8785 input must be I-JSON', [T1],
      native({ action_type: 't.1', s: { $units: [0xffff] } }), { refusals: ['unsupported_value'] }),
    compute('refuse-top-level-array', 'a JSON array is not an action object', [T1], text('[]'), { refusals: ['invalid_action_type'] }),
    compute('refuse-top-level-string', 'a JSON string is not an action object', [T1], text('"t.1"'), { refusals: ['invalid_action_type'] }),
    compute('refuse-top-level-null', 'null is not an action object', [T1], text('null'), { refusals: ['invalid_action_type'] }),
    compute('refuse-top-level-number', 'a number is not an action object', [T1], text('1'), { refusals: ['invalid_action_type'] }),
    compute('compute-whitespace-insignificant', 'white space between tokens does not change the CAID', [T1], text(' {\n\t"action_type" : "t.1" ,\r\n "s" : "x" } '), 'ok', { relation: { same_caid_as: 'compute-text-small' } }),
    compute('compute-escapes-insignificant', 'escaped and raw spellings of the same string give the same CAID', [T1], text('{"\\u0061ction_type":"\\u0074.1","s":"\\u0078"}'), 'ok', { relation: { same_caid_as: 'compute-text-small' } }),
    compute('compute-member-named-proto', 'a member named __proto__ is an ordinary own member of the action object', [T1], text('{"action_type":"t.1","s":"x","__proto__":{"polluted":true}}'), 'ok'),
    compute('compute-empty-string-present', 'the empty string is a present string value', [T1], text('{"action_type":"t.1","s":""}'), 'ok'),
    compute('refuse-null-is-present', 'a member holding null is present, so a string field holding null is mistyped', [T1], text('{"action_type":"t.1","s":null}'), { refusals: ['mistyped_field:s'] }),
  );

  // ------------------------------------------------------------ numbers
  const num = (lit) => text(`{"action_type":"t.obj.1","s":"x","v":${lit}}`);
  const numInt = (lit) => text(`{"action_type":"t.obj.1","s":"x","n":${lit}}`);
  add(
    compute('compute-number-zero', 'the integer 0', [OBJ], num('0'), 'ok'),
    compute('compute-number-negative-zero', '-0 is the integer 0', [OBJ], num('-0'), 'ok', { relation: { same_caid_as: 'compute-number-zero' } }),
    compute('compute-number-negative-zero-fraction', '-0.0 is the integer 0', [OBJ], num('-0.0'), 'ok', { relation: { same_caid_as: 'compute-number-zero' } }),
    compute('compute-number-underflow-is-zero', '1e-400 rounds to 0, which is the integer 0', [OBJ], num('1e-400'), 'ok', { relation: { same_caid_as: 'compute-number-zero' } }),
    compute('compute-number-negative-underflow-is-zero', '-1e-400 rounds to -0, which is the integer 0', [OBJ], num('-1e-400'), 'ok', { relation: { same_caid_as: 'compute-number-zero' } }),
    compute('compute-number-one', 'the integer 1', [OBJ], num('1'), 'ok'),
    compute('compute-number-near-integer-literal', '0.99999999999999999999 rounds to 1 and is accepted as the integer 1', [OBJ], num('0.99999999999999999999'), 'ok', { relation: { same_caid_as: 'compute-number-one' } }),
    compute('compute-number-midpoint-ties-to-even', 'the exact midpoint between 1 and the next binary64 value rounds to even, which is 1', [OBJ], num('1.00000000000000011102230246251565404236316680908203125'), 'ok', { relation: { same_caid_as: 'compute-number-one' } }),
    compute('compute-number-below-midpoint', 'just below that midpoint rounds to 1', [OBJ], num('1.00000000000000011102230246251565404236316680908203124'), 'ok', { relation: { same_caid_as: 'compute-number-one' } }),
    compute('refuse-number-above-midpoint', 'just above that midpoint rounds up to 1.0000000000000002, which is not an integer', [OBJ], num('1.000000000000000111022302462515654042363166809082031250001'), { refusals: ['unsupported_number'] }),
    compute('refuse-number-next-after-one', '1.0000000000000002 is not an integer', [OBJ], num('1.0000000000000002'), { refusals: ['unsupported_number'] }),
    compute('compute-number-uppercase-exponent', '1E2 is the integer 100', [OBJ], num('1E2'), 'ok', { relation: { same_caid_as: 'compute-number-hundred' } }),
    compute('compute-number-plus-exponent', '1e+2 is the integer 100', [OBJ], num('1e+2'), 'ok', { relation: { same_caid_as: 'compute-number-hundred' } }),
    compute('compute-number-hundred', 'the integer 100', [OBJ], num('100'), 'ok'),
    compute('compute-number-max-safe-positive', '2^53-1', [OBJ], num('9007199254740991'), 'ok'),
    compute('compute-number-max-safe-negative', '-(2^53-1)', [OBJ], num('-9007199254740991'), 'ok'),
    compute('compute-number-rounds-into-range', '9007199254740991.4 rounds to 2^53-1', [OBJ], num('9007199254740991.4'), 'ok', { relation: { same_caid_as: 'compute-number-max-safe-positive' } }),
    compute('refuse-number-two-to-53', '2^53 is outside the range', [OBJ], num('9007199254740992'), { refusals: ['unsupported_number'] }),
    compute('refuse-number-negative-two-to-53', '-(2^53) is outside the range', [OBJ], num('-9007199254740992'), { refusals: ['unsupported_number'] }),
    compute('refuse-number-rounds-out-of-range', '9007199254740993 rounds to 2^53, which is outside the range', [OBJ], num('9007199254740993'), { refusals: ['unsupported_number'] }),
    compute('refuse-number-400-digits', 'a 400-digit integer literal overflows binary64', [OBJ], num('1' + '0'.repeat(399)), { refusals: ['unsupported_number'] }),
    compute('refuse-number-5000-digits', 'a 5000-digit literal overflows binary64 and is unsupported_number, never a parser error', [OBJ], num('9'.repeat(5000)), { refusals: ['unsupported_number'] }),
    compute('refuse-number-overflow-exponent', '1e400 overflows to infinity', [OBJ], num('1e400'), { refusals: ['unsupported_number'] }),
    compute('refuse-number-overflow-in-integer-field', '1e400 in an integer field is both mistyped_field and unsupported_number', [OBJ], numInt('1e400'), { refusals: ['mistyped_field:n', 'unsupported_number'] }),
    compute('compute-number-integer-field-underflow', '1e-400 in an integer field is the integer 0', [OBJ], numInt('1e-400'), 'ok'),
    compute('refuse-number-fraction-in-integer-field', '0.5 in an integer field is mistyped and unsupported_number', [OBJ], numInt('0.5'), { refusals: ['mistyped_field:n', 'unsupported_number'] }),
    compute('refuse-number-duplicate-reason-once', 'two non-integers give one unsupported_number', [OBJ], text('{"action_type":"t.obj.1","s":"x","v":1.5,"w":[2.5]}'), { refusals: ['unsupported_number'] }),
  );

  // ------------------------------------------------------------ native lane
  const text1 = { action_type: 'test.text.1', required_fields: [{ name: 'c', type: 'string' }], optional_fields: [] };
  add(
    compute('native-lone-surrogate-string-value', 'native lane: a host string holding a lone surrogate is unsupported_value (from JSON text it is malformed_json)', [text1],
      native({ action_type: 'test.text.1', c: { $units: [0xd800] } }), { refusals: ['unsupported_value'] }),
    compute('native-lone-surrogate-member-name', 'native lane: a member name holding a lone surrogate is unsupported_value', [text1],
      native({ $object: [['action_type', 'test.text.1'], ['c', 'x'], [{ $units: [0xdc00] }, 'y']] }), { refusals: ['unsupported_value'] }),
    verify('native-verify-lone-surrogate-against-replacement-caid', 'native lane: a lone surrogate never verifies against the CAID of the same object with U+FFFD', [text1],
      { native: { action_type: 'test.text.1', c: { $units: [0xd800] } }, caid: 'caid:1:test.text.1:jcs-sha256:agG0nPtxAPmIVabJzWul9xH1rE2ayq67AYPCMNqgdqU' }, { reasons: ['invalid_object'] }),
    compute('native-order-number-then-surrogate-key', 'native lane (review D1): a lone-surrogate member name that sorts before a member holding 1.5; the reason order is fixed by phase, not traversal', [T1],
      native({ $object: [['action_type', 't.1'], ['s', 'x'], [{ $units: [0xd800] }, 'y'], ['', 1.5]] }), { refusals: ['unsupported_number', 'unsupported_value'] }),
    compute('native-order-surrogate-key-after-number', 'native lane: the same pair with the number member sorting first gives the same order', [T1],
      native({ $object: [['action_type', 't.1'], ['s', 'x'], ['\u0001', 1.5], [{ $units: [0xdbff] }, 'y']] }), { refusals: ['unsupported_number', 'unsupported_value'] }),
    compute('native-order-surrogate-value-and-number', 'native lane: a lone-surrogate string value and a non-integer', [T1],
      native({ action_type: 't.1', s: 'x', a: { $units: [0xdfff] }, b: 2.5 }), { refusals: ['unsupported_number', 'unsupported_value'] }),
    compute('native-dedupe-surrogates', 'native lane: two lone surrogates give one unsupported_value', [T1],
      native({ action_type: 't.1', s: 'x', a: { $units: [0xd800] }, b: { $units: [0xdc00] } }), { refusals: ['unsupported_value'] }),
    compute('native-nan', 'native lane: NaN is unsupported_number', [T1], native({ action_type: 't.1', s: 'x', v: { $host: 'nan' } }), { refusals: ['unsupported_number'] }),
    compute('native-infinity', 'native lane: +infinity is unsupported_number', [T1], native({ action_type: 't.1', s: 'x', v: { $host: 'infinity' } }), { refusals: ['unsupported_number'] }),
    compute('native-negative-infinity', 'native lane: -infinity is unsupported_number', [T1], native({ action_type: 't.1', s: 'x', v: [{ $host: '-infinity' }] }), { refusals: ['unsupported_number'] }),
    compute('native-nan-in-integer-field', 'native lane: NaN in an integer field is mistyped_field and unsupported_number', [OBJ], native({ action_type: 't.obj.1', s: 'x', n: { $host: 'nan' } }), { refusals: ['mistyped_field:n', 'unsupported_number'] }),
    compute('native-negative-zero', 'native lane: the binary64 -0.0 is the integer 0', [OBJ], native({ action_type: 't.obj.1', s: 'x', v: { $host: 'negative_zero' } }), 'ok', { relation: { same_caid_as: 'compute-number-zero' } }),
    compute('native-cyclic-object', 'native lane: a cyclic object is refused, never followed forever and never thrown', [T1],
      native({ action_type: 't.1', s: 'x', self: { $host: 'cyclic' } }), { refusals: ['unsupported_value'] }),
    compute('native-cyclic-array', 'native lane: a cyclic array', [OBJ], native({ action_type: 't.obj.1', s: 'x', a: [1, { $host: 'cyclic' }] }), { refusals: ['unsupported_value'] }),
    compute('native-cyclic-in-object-field', 'native lane: a cyclic value in a declared object field has the right type but no canonical form', [OBJ],
      native({ action_type: 't.obj.1', s: 'x', o: { k: { $host: 'cyclic' } } }), { refusals: ['unsupported_value'] }),
    compute('native-opaque-member', 'native lane: a host value with no data-model counterpart is refused, never serialized as {}', [T1],
      native({ action_type: 't.1', s: 'x', m: { $host: 'opaque' } }), { refusals: ['unsupported_value'] }),
    compute('native-opaque-in-object-field', 'native lane: such a value in a declared object field is mistyped_field and unsupported_value', [OBJ],
      native({ action_type: 't.obj.1', s: 'x', o: { $host: 'opaque' } }), { refusals: ['mistyped_field:o', 'unsupported_value'] }),
    compute('native-opaque-top-level', 'native lane: an opaque host value is not an action object', [T1], native({ $host: 'opaque' }), { refusals: ['invalid_action_type'] }),
    compute('native-noncharacter-member-name', 'native lane: a noncharacter in a member name', [T1],
      native({ $object: [['action_type', 't.1'], ['s', 'x'], [{ $units: [0xfdd0] }, 'y']] }), { refusals: ['unsupported_value'] }),
    verify('native-verify-cyclic', 'native lane: verifying a cyclic object never throws', [T1],
      { native: { action_type: 't.1', s: 'x', self: { $host: 'cyclic' } }, caid_of: { json: t1('x'), definitions: [T1] } }, { reasons: ['invalid_object'] }),
    verify('native-verify-opaque-top-level', 'native lane: an opaque value is not an object', [T1],
      { native: { $host: 'opaque' }, caid_of: { json: t1('x'), definitions: [T1] } }, { reasons: ['invalid_object'] }),
  );

  // ------------------------------------------------------------ reason order: gates and phases
  const px = (o) => text(j({ ...PX_OK, ...o }));
  add(
    compute('order-gate-malformed-json-first', 'malformed_json is a gate: nothing else is reported', [PX],
      text('{"action_type":"P.1","action_type":"P.1"}'), { refusals: ['malformed_json'] }),
    compute('order-gate-invalid-action-type', 'invalid_action_type is a gate: a missing field, a bad amount and an unknown suite are not reported', [PX],
      { ...text(j({ action_type: 'P.1', a: '01', v: 1.5 })), suite: 'jcs-sha512' }, { refusals: ['invalid_action_type'] }),
    compute('order-gate-unknown-action-type', 'unknown_action_type is a gate', [PX], { ...text(j({ action_type: 'q.1', a: '01', v: 1.5 })), suite: 'nope' }, { refusals: ['unknown_action_type'] }),
    compute('order-gate-invalid-definition', 'invalid_definition is a gate', [{ ...PX, required_fields: 'a' }], { ...text(j({ action_type: 'p.1', v: 1.5 })), suite: 'nope' }, { refusals: ['invalid_definition'] }),
    compute('order-phase-3-by-required-index', 'missing fields are reported in required_fields order', [PX], text(j({ action_type: 'p.1', b: 'x' })), { refusals: ['missing_material_field:a', 'missing_material_field:c'] }),
    compute('order-phase-3-before-4', 'a missing field (phase 3) precedes a bad amount (phase 4) even though the amount field comes first', [PX],
      text(j({ action_type: 'p.1', a: '01', c: D() })), { refusals: ['missing_material_field:b', 'invalid_amount:a'] }),
    compute('order-phase-4-by-field-index', 'phase 4 reasons follow required then optional field order, not object member order', [PX],
      text('{"action_type":"p.1","e":"a00","d":"1","c":"sha256:X","b":"x","a":"1e3"}'),
      { refusals: ['invalid_amount:a', 'mistyped_field:c', 'mistyped_field:d', 'invalid_code:e'] }),
    compute('order-phase-3-and-5', 'phase 3 then the suite', [PX], { ...text(j({ action_type: 'p.1', a: '1', b: 'x' })), suite: 'jcs-sha512' }, { refusals: ['missing_material_field:c', 'unknown_suite'] }),
    compute('order-phase-3-and-6', 'phase 3 then unsupported_number', [PX], text(j({ action_type: 'p.1', a: '1', b: 'x', v: 0.5 })), { refusals: ['missing_material_field:c', 'unsupported_number'] }),
    compute('order-phase-3-and-7', 'native lane: phase 3 then unsupported_value', [PX], native({ action_type: 'p.1', a: '1', b: 'x', v: { $units: [0xd800] } }), { refusals: ['missing_material_field:c', 'unsupported_value'] }),
    compute('order-phase-4-and-5', 'phase 4 then the suite', [PX], { ...px({ a: '+1' }), suite: 'cbor-sha256' }, { refusals: ['invalid_amount:a', 'unknown_suite'] }),
    compute('order-phase-4-and-6', 'phase 4 then unsupported_number', [PX], px({ b: 2, v: 0.5 }), { refusals: ['mistyped_field:b', 'unsupported_number'] }),
    compute('order-phase-4-and-7', 'native lane: phase 4 then unsupported_value', [PX], native({ ...PX_OK, b: false, v: { $host: 'opaque' } }), { refusals: ['mistyped_field:b', 'unsupported_value'] }),
    compute('order-phase-5-and-6', 'the suite then unsupported_number', [PX], { ...px({ v: 0.5 }), suite: 'jcs-sha512' }, { refusals: ['unknown_suite', 'unsupported_number'] }),
    compute('order-phase-5-and-7', 'native lane: the suite then unsupported_value', [PX], { ...native({ ...PX_OK, v: { $units: [0xd800] } }), suite: 'jcs-sha512' }, { refusals: ['unknown_suite', 'unsupported_value'] }),
    compute('order-phase-6-and-7', 'native lane: unsupported_number then unsupported_value', [PX], native({ ...PX_OK, v: { $units: [0xd800] }, w: 0.5 }), { refusals: ['unsupported_number', 'unsupported_value'] }),
    compute('order-all-phases', 'native lane: phases 3 to 7 in one result', [PX],
      { ...native({ action_type: 'p.1', a: 'x', c: 7, d: 1.5, v: { $units: [0xd800] } }), suite: 'none' },
      { refusals: ['missing_material_field:b', 'invalid_amount:a', 'mistyped_field:c', 'mistyped_field:d', 'unknown_suite', 'unsupported_number', 'unsupported_value'] }),
    compute('order-one-reason-per-field', 'a field gets at most one phase-4 reason', [PX], px({ e: 5 }), { refusals: ['mistyped_field:e'] }),
    compute('option-suite-not-a-string', 'a suite option of the wrong type counts as absent: unknown_suite, never an exception', [PX], { ...px({}), suite: ['jcs-sha256'] }, { refusals: ['unknown_suite'] }),
    computeNoSuite('option-suite-absent', 'with no suite option there is no default suite', [PX], px({}), { refusals: ['unknown_suite'] }),
    compute('option-definitions-not-an-array', 'a definitions option of the wrong type counts as absent', { 'p.1': PX }, px({}), { refusals: ['unknown_action_type'] }),
    compute('option-definitions-with-non-objects', 'entries of the definitions array that are not objects are ignored', [null, 5, 'p.1', PX], px({}), 'ok', { relation: { same_caid_as: 'compute-px-ok' } }),
    compute('compute-px-ok', 'the reference object of the phase vectors computes', [PX], px({}), 'ok'),
  );

  // ------------------------------------------------------------ verification
  const pxCaid = { json: j(PX_OK), definitions: [PX] };
  add(
    verify('verify-px-valid', 'a valid verification carries definition_sha256 and empty details', [PX], { json: j(PX_OK), caid_of: pxCaid }, 'valid'),
    verify('verify-gate-parse-first', 'a malformed CAID is a gate even when the object is also malformed JSON', [PX], { json: '{"a":1,"a":2}', caid: 'CAID:1:p.1:jcs-sha256:' + VALID_DIGEST }, { reasons: ['malformed_caid'] }),
    verify('verify-gate-unknown-suite-at-parse', 'a grammatical but unregistered suite stops verification at parse with unknown_suite', [PX],
      { json: j({ action_type: 'q.1' }), caid: 'caid:1:p.1:jcs-sha512:' + VALID_DIGEST }, { reasons: ['unknown_suite'] }),
    verify('verify-gate-malformed-json', 'malformed JSON text is the gate after parse', [PX], { json: '{"action_type":"p.1","action_type":"p.1"}', caid_of: pxCaid }, { reasons: ['malformed_json'] }),
    verify('verify-not-an-object-array', 'a JSON array is invalid_object; its detail observes an array', [PX], { json: '[1]', caid_of: pxCaid }, { reasons: ['invalid_object'] }),
    verify('verify-not-an-object-null', 'null is invalid_object; its detail observes null', [PX], { json: 'null', caid_of: pxCaid }, { reasons: ['invalid_object'] }),
    verify('verify-object-lacking-action-type', 'an object with no action_type: action_type_mismatch, digest_mismatch and invalid_object, with invalid_action_type as the detail', [PX],
      { json: j({ a: '1.00', b: 'x', c: D() }), caid_of: pxCaid }, { reasons: ['action_type_mismatch', 'digest_mismatch', 'invalid_object'] }),
    verify('verify-object-not-canonicalizable', 'an object outside the number rule is invalid_object only; its digest is not compared', [PX],
      { json: j({ ...PX_OK, v: 1.5 }), caid_of: pxCaid }, { reasons: ['invalid_object'] }),
    verify('verify-details-observed-kinds', 'each detail names the field, the rule and the JSON kind it observed', [PX],
      { json: j({ action_type: 'p.1', a: 1, b: [], c: {}, d: 'x', e: null }), caid_of: pxCaid }, { reasons: ['digest_mismatch', 'invalid_object'] }),
    verify('verify-details-missing-field-absent', 'a missing field is observed as absent', [PX], { json: j({ action_type: 'p.1', a: '1.00', c: D(), e: true }), caid_of: pxCaid }, { reasons: ['digest_mismatch', 'invalid_object'] }),
    verify('verify-registered-suite-not-implemented', 'a registered suite this implementation does not implement is unknown_suite after parse', [PX],
      { json: j(PX_OK), caid: 'caid:1:p.1:cbor-sha256:' + VALID_DIGEST }, { reasons: ['unknown_suite'] }),
    verify('verify-registered-suite-not-implemented-invalid-object', 'unknown_suite (rank 6) precedes invalid_object (rank 7)', [PX],
      { json: j({ ...PX_OK, a: '1.0.0' }), caid: 'caid:1:p.1:cbor-sha256:' + VALID_DIGEST }, { reasons: ['unknown_suite', 'invalid_object'] }),
    verify('verify-expected-definition-match', 'a matching expected_definition_sha256 verifies', [PX], { json: j(PX_OK), caid_of: pxCaid, expected_definition_sha256: { of: PX } }, 'valid'),
    verify('verify-definition-mismatch', 'a different expected_definition_sha256 is definition_mismatch even when the digest matches', [PX],
      { json: j(PX_OK), caid_of: pxCaid, expected_definition_sha256: { of: { ...PX, optional_fields: [] } } }, { reasons: ['definition_mismatch'] }),
    verify('verify-definition-mismatch-and-digest', 'definition_mismatch (rank 5) precedes digest_mismatch (rank 6)', [PX],
      { json: j({ ...PX_OK, b: 'y' }), caid_of: pxCaid, expected_definition_sha256: 'sha256:' + '0'.repeat(64) }, { reasons: ['definition_mismatch', 'digest_mismatch'] }),
    verify('verify-action-type-and-definition-mismatch', 'action_type_mismatch (rank 4) precedes definition_mismatch', [PX, T1],
      { json: t1('x'), caid_of: pxCaid, expected_definition_sha256: { of: PX } }, { reasons: ['action_type_mismatch', 'definition_mismatch', 'digest_mismatch'] }),
    verify('verify-expected-definition-unresolved', 'with no resolvable definition there is nothing to compare: no definition_mismatch', [T1],
      { json: j(PX_OK), caid_of: pxCaid, expected_definition_sha256: { of: PX } }, { reasons: ['invalid_object'] }),
    verify('verify-expected-definition-not-a-string', 'an expected_definition_sha256 option that is not a string counts as absent', [PX],
      { json: j(PX_OK), caid_of: pxCaid, expected_definition_sha256: 7 }, 'valid'),
    verify('verify-expected-definition-malformed-string', 'any other string is compared as given and differs', [PX],
      { json: j(PX_OK), caid_of: pxCaid, expected_definition_sha256: 'SHA256:' + '0'.repeat(64) }, { reasons: ['definition_mismatch'] }),
    verify('verify-definition-notes-do-not-matter', 'the definition used to verify may differ in notes and status; definition_sha256 is the same', [{ ...PX, status: 'deprecated', summary: 'x', required_fields: PX.required_fields.map((f) => ({ ...f, notes: 'n' })) }],
      { json: j(PX_OK), caid_of: pxCaid, expected_definition_sha256: { of: PX } }, 'valid'),
  );

  // ------------------------------------------------------------ definitions
  const bad = (id, description, definition, extra = []) => compute(id, description, [definition, ...extra], text(j({ action_type: 'd.1', f: 'x' })), { refusals: ['invalid_definition'] });
  const f = (o) => ({ name: 'f', type: 'string', ...o });
  add(
    bad('definition-required-fields-absent', 'a definition without required_fields', { action_type: 'd.1' }),
    bad('definition-required-fields-string', 'required_fields is a string', { action_type: 'd.1', required_fields: 'f' }),
    bad('definition-required-fields-strings', 'required_fields holds strings, not field entries', { action_type: 'd.1', required_fields: ['f'] }),
    bad('definition-name-typo', 'a field entry spelled nmae has no name', { action_type: 'd.1', required_fields: [{ nmae: 'f', type: 'string' }] }),
    bad('definition-numeric-name', 'a numeric field name', { action_type: 'd.1', required_fields: [{ name: 1, type: 'string' }] }),
    bad('definition-required-fields-empty', 'an empty required_fields binds nothing and is refused', { action_type: 'd.1', required_fields: [] }),
    bad('definition-optional-fields-object', 'optional_fields that is not an array', { action_type: 'd.1', required_fields: [f()], optional_fields: {} }),
    bad('definition-optional-fields-null', 'optional_fields present as null', { action_type: 'd.1', required_fields: [f()], optional_fields: null }),
    bad('definition-entry-null', 'a field entry that is not an object', { action_type: 'd.1', required_fields: [f()], optional_fields: [null] }),
    bad('definition-duplicate-name', 'a field name repeated in required_fields', { action_type: 'd.1', required_fields: [f(), f()] }),
    bad('definition-duplicate-name-across-lists', 'a field name repeated across required_fields and optional_fields', { action_type: 'd.1', required_fields: [f()], optional_fields: [f({ type: 'integer' })] }),
    bad('definition-name-action-type', 'a field may not be named action_type', { action_type: 'd.1', required_fields: [f(), { name: 'action_type', type: 'string' }] }),
    bad('definition-name-with-colon', 'a field name may not contain ":", which would make reason strings ambiguous', { action_type: 'd.1', required_fields: [f(), { name: 'a:b', type: 'string' }] }),
    bad('definition-name-empty', 'a field name may not be empty', { action_type: 'd.1', required_fields: [f(), { name: '', type: 'string' }] }),
    bad('definition-type-not-string', 'a field type that is not a string', { action_type: 'd.1', required_fields: [f({ type: 1 })] }),
    bad('definition-type-absent', 'a field entry with no type', { action_type: 'd.1', required_fields: [{ name: 'f' }] }),
    bad('definition-member-not-of-type', 'a string field may not carry enum members', { action_type: 'd.1', required_fields: [f({ values: ['x'] })] }),
    bad('definition-member-not-of-amount-type', 'an amount-string field may not carry code members', { action_type: 'd.1', required_fields: [f({ type: 'amount-string', format: 'cpt' })] }),
    bad('definition-code-without-system', 'a code field needs code_system', { action_type: 'd.1', required_fields: [{ name: 'f', type: 'code', format: 'cpt' }] }),
    bad('definition-code-without-format', 'a code field needs format', { action_type: 'd.1', required_fields: [{ name: 'f', type: 'code', code_system: CODE_SYSTEMS.cpt }] }),
    bad('definition-code-system-not-uri', 'code_system must be an absolute URI', { action_type: 'd.1', required_fields: [{ name: 'f', type: 'code', code_system: 'icd-10-cm', format: 'icd-10-cm' }] }),
    bad('definition-code-system-fragment', 'code_system carries no fragment', { action_type: 'd.1', required_fields: [{ name: 'f', type: 'code', code_system: 'http://hl7.org/fhir/sid/icd-10-cm#x', format: 'icd-10-cm' }] }),
    bad('definition-code-format-uppercase', 'format must match the format-name rule', { action_type: 'd.1', required_fields: [{ name: 'f', type: 'code', code_system: CODE_SYSTEMS['icd-10-cm'], format: 'ICD-10-CM' }] }),
    bad('definition-code-with-values', 'a code field never carries a value set', { action_type: 'd.1', required_fields: [{ name: 'f', type: 'code', code_system: CODE_SYSTEMS.cpt, format: 'cpt', values: ['99213'] }] }),
    bad('definition-conflicting-duplicates', 'two definitions of one type with different validation semantics', { action_type: 'd.1', required_fields: [f()] }, [{ action_type: 'd.1', required_fields: [f({ type: 'digest' })] }]),
    bad('definition-conflicting-duplicates-reversed', 'the same pair in the other order: the result never depends on definition order', { action_type: 'd.1', required_fields: [f({ type: 'digest' })] }, [{ action_type: 'd.1', required_fields: [f()] }]),
    bad('definition-duplicate-one-nonconforming', 'a conforming definition beside a nonconforming one of the same type', { action_type: 'd.1', required_fields: [f()] }, [{ action_type: 'd.1', required_fields: [] }]),
    compute('definition-equal-duplicates', 'duplicates that differ only in notes, status and summary count once', [
      { action_type: 'd.1', required_fields: [f()] },
      { action_type: 'd.1', status: 'deprecated', summary: 'x', required_fields: [f({ notes: 'n' })], optional_fields: [] },
    ], text(j({ action_type: 'd.1', f: 'x' })), 'ok', { relation: { same_caid_as: 'definition-plain' } }),
    compute('definition-plain', 'the plain definition', [{ action_type: 'd.1', required_fields: [f()] }], text(j({ action_type: 'd.1', f: 'x' })), 'ok'),
    compute('definition-deprecated-status-computes', 'status never gates computation: a deprecated definition with a successor computes the same CAID', [{ action_type: 'd.1', status: 'deprecated', superseded_by: 'd.2', required_fields: [f()] }],
      text(j({ action_type: 'd.1', f: 'x' })), 'ok', { relation: { same_caid_as: 'definition-plain' } }),
    compute('definition-other-types-ignored', 'a nonconforming definition of another type does not matter', [{ action_type: 'd.1', required_fields: [f()] }, { action_type: 'e.1', required_fields: [] }],
      text(j({ action_type: 'd.1', f: 'x' })), 'ok', { relation: { same_caid_as: 'definition-plain' } }),
    compute('definition-entry-members-open', 'entry-level members other than the field lists are allowed and outside validation', [{ action_type: 'd.1', required_fields: [f()], status: 'active', risk_class: 'x', 'x-local': { any: 1 } }],
      text(j({ action_type: 'd.1', f: 'x' })), 'ok', { relation: { same_caid_as: 'definition-plain' } }),
    compute('definition-unknown-field-type-absent', 'a field of an unregistered type keeps the definition conforming; absent, it does not matter', [{ action_type: 'd.1', required_fields: [f()], optional_fields: [{ name: 'g', type: 'color', palette: 'x' }] }],
      text(j({ action_type: 'd.1', f: 'x' })), 'ok'),
    compute('definition-unknown-field-type-present', 'present, a field of an unregistered type is mistyped_field', [{ action_type: 'd.1', required_fields: [f()], optional_fields: [{ name: 'g', type: 'color' }] }],
      text(j({ action_type: 'd.1', f: 'x', g: 'red' })), { refusals: ['mistyped_field:g'] }),
    compute('definition-unregistered-format-absent', 'a code field with a grammatical but unregistered format keeps the definition conforming', [{ action_type: 'd.1', required_fields: [f()], optional_fields: [{ name: 'g', type: 'code', code_system: 'http://loinc.org', format: 'loinc' }] }],
      text(j({ action_type: 'd.1', f: 'x' })), 'ok'),
    compute('definition-unregistered-format-present', 'present, it is mistyped_field', [{ action_type: 'd.1', required_fields: [f()], optional_fields: [{ name: 'g', type: 'code', code_system: 'http://loinc.org', format: 'loinc' }] }],
      text(j({ action_type: 'd.1', f: 'x', g: '1234-5' })), { refusals: ['mistyped_field:g'] }),
    compute('definition-field-names-beyond-snake-case', 'any non-empty name without ":" other than action_type is a field name', [{ action_type: 'd.1', required_fields: [{ name: '@version', type: 'string' }, { name: 'Café \u{1F600}', type: 'string' }, { name: 'toString', type: 'string' }, { name: '__proto__', type: 'string' }] }],
      text('{"action_type":"d.1","@version":"1","Café \u{1F600}":"x","toString":"y","__proto__":"z"}'), 'ok'),
    compute('definition-field-name-missing-reason', 'the reason parameter is the field name as written', [{ action_type: 'd.1', required_fields: [{ name: 'Café \u{1F600}', type: 'string' }] }],
      text('{"action_type":"d.1"}'), { refusals: ['missing_material_field:Café \u{1F600}'] }),
  );

  // ------------------------------------------------------------ definition_sha256
  const PAY = {
    action_type: 'payment.release.1', status: 'active', risk_class: 'irreversible-financial', summary: 'Release of a payment instruction to settlement.',
    required_fields: [
      { name: 'amount', type: 'amount-string', notes: "decimal string, no exponent, no leading '+', no thousands separators" },
      { name: 'currency', type: 'enum', ...ISO4217 },
      { name: 'beneficiary_account', type: 'digest', notes: 'sha256:<lowercase hex> of the normalized account identifier' },
      { name: 'payment_instruction_id', type: 'string' },
    ],
    optional_fields: [{ name: 'memo', type: 'string' }],
    digest_notes: 'amounts never renormalized after signing', references: [],
  };
  const strip = (d) => ({
    action_type: d.action_type,
    required_fields: d.required_fields.map(({ notes, ...rest }) => rest),
    optional_fields: (d.optional_fields ?? []).map(({ notes, ...rest }) => rest),
  });
  add(
    defn('definition-sha256-payment-release', 'the validation projection of payment.release.1', PAY, 'ok'),
    defn('definition-sha256-projection-only', 'the projection itself has the same digest: notes, status, risk_class, summary, digest_notes and references are outside it', strip(PAY), 'ok', { same_definition_sha256_as: 'definition-sha256-payment-release' }),
    defn('definition-sha256-optional-absent-is-empty', 'an absent optional_fields is the empty list', { action_type: 't.1', required_fields: [{ name: 's', type: 'string' }] }, 'ok', { same_definition_sha256_as: 'definition-sha256-optional-empty' }),
    defn('definition-sha256-optional-empty', 'optional_fields: []', { action_type: 't.1', required_fields: [{ name: 's', type: 'string' }], optional_fields: [] }, 'ok'),
    defn('definition-sha256-field-order-matters', 'field order drives reason order, so it is in the digest', { ...PAY, required_fields: [PAY.required_fields[1], PAY.required_fields[0], ...PAY.required_fields.slice(2)] }, 'ok', { different_definition_sha256_from: 'definition-sha256-payment-release' }),
    defn('definition-sha256-enum-pin-matters', 'a different enum pin is a different definition', { ...PAY, required_fields: [PAY.required_fields[0], { name: 'currency', type: 'enum', values: ['EUR', 'USD'] }, ...PAY.required_fields.slice(2)] }, 'ok', { different_definition_sha256_from: 'definition-sha256-payment-release' }),
    defn('definition-sha256-unknown-type-members-kept', 'a field of an unregistered type keeps all its members except notes in the projection', { action_type: 't.1', required_fields: [{ name: 's', type: 'color', palette: 'rgb', notes: 'n' }] }, 'ok'),
    defn('definition-sha256-code-field', 'a code field projects code_system and format', codeDef('icd-10-cm'), 'ok'),
    defn('definition-sha256-refuses-nonconforming', 'a nonconforming definition has no definition_sha256', { action_type: 't.1', required_fields: [] }, 'invalid'),
    defn('definition-sha256-refuses-non-object', 'a definition must be an object', ['t.1'], 'invalid'),
    defn('definition-sha256-refuses-bad-action-type', 'a definition whose action_type is not an action type', { action_type: 'T.1', required_fields: [{ name: 's', type: 'string' }] }, 'invalid'),
  );

  // ------------------------------------------------------------ code fields
  const codeCase = (format, value, ok, note) => compute(
    `code-${format}-${ok ? 'accepts' : 'refuses'}-${value === '' ? 'empty' : String(value).replace(/[^A-Za-z0-9]/g, '_')}`,
    `${format}: ${JSON.stringify(value)} ${ok ? 'matches' : 'does not match'} the named format${note ? ` (${note})` : ''}`,
    [codeDef(format)], text(j({ action_type: `test.code.${format}.1`, f: value })),
    ok ? 'ok' : { refusals: [typeof value === 'string' ? 'invalid_code:f' : 'mistyped_field:f'] },
  );
  const codeTable = {
    'icd-10-cm': [['A00', true], ['A00.0', true], ['S72.001A', true], ['U07.1', true], ['Z99.89', true], ['C4A.0', true, 'letters are allowed in positions 2 and 3'],
      ['a00', false, 'never case-folded'], ['A0', false], ['A00.', false], ['A00.12345', false], ['A00-1', false], [' A00', false], ['1A0', false]],
    'ndc-11': [['00002322730', true], ['12345678901', true], ['0002-3227-30', false, 'the hyphenated form is ndc-10-hyphenated'], ['0000232273', false], ['000023227301', false], ['0000232273A', false]],
    'ndc-10-hyphenated': [['0002-3227-30', true, '4-4-2'], ['12345-678-90', true, '5-3-2'], ['12345-6789-0', true, '5-4-1'], ['00002322730', false], ['123456-78-90', false], ['1234-5678-901', false], ['12345-6789-01', false]],
    cpt: [['99213', true], ['0001F', true, 'Category II'], ['0042T', true, 'Category III'], ['9921', false], ['992134', false], ['A9921', false], ['99213 ', false]],
    'hcpcs-level-ii': [['J1234', true], ['E0114', true], ['99213', false, 'CPT is not Level II'], ['j1234', false], ['J123', false]],
    hcpcs: [['99213', true], ['J1234', true], ['0001F', true], ['J12345', false], ['12345A', false]],
    'iso-3166-1-alpha-2': [['US', true], ['DE', true], ['ZZ', true, 'syntax only; membership is a value-set question'], ['us', false], ['USA', false], ['U1', false], ['', false]],
    'iso-3166-2': [['US-CA', true], ['GB-ENG', true], ['FR-75C', true], ['US-', false], ['US-ABCD', false], ['us-ca', false], ['US_CA', false]],
    'iso20022-external-code': [['AC01', true], ['MS03', true], ['A', true], ['ac01', false], ['ABCDE', false], ['', false]],
    'nacha-sec': [['PPD', true], ['CCD', true], ['WEB', true], ['ppd', false], ['PP', false], ['PPDX', false]],
  };
  for (const [format, rows] of Object.entries(codeTable)) for (const [value, ok, note] of rows) add(codeCase(format, value, ok, note));
  add(
    compute('code-refuses-number', 'a code value must be a JSON string', [codeDef('cpt')], text(j({ action_type: 'test.code.cpt.1', f: 99213 })), { refusals: ['mistyped_field:f'] }),
    compute('code-refuses-null', 'null is not a code', [codeDef('cpt')], text(j({ action_type: 'test.code.cpt.1', f: null })), { refusals: ['mistyped_field:f'] }),
  );
  // Adversarial inputs for backtracking matchers: a mebibyte of a
  // character the format accepts, then one it does not. A linear-time
  // matcher refuses in microseconds.
  const redos = { 'icd-10-cm': 'A', 'ndc-11': '0', 'ndc-10-hyphenated': '0', cpt: '0', 'hcpcs-level-ii': 'J', hcpcs: '9', 'iso-3166-1-alpha-2': 'U', 'iso-3166-2': 'A', 'iso20022-external-code': 'A', 'nacha-sec': 'P' };
  for (const [format, unit] of Object.entries(redos)) {
    add(compute(`code-${format}-adversarial-1mib`, `${format}: 1 MiB of "${unit}" then "!" is refused inside the time budget (a backtracking matcher would not finish)`, [codeDef(format)],
      { json_repeat: { prefix: `{"action_type":"test.code.${format}.1","f":"`, unit, count: 1 << 20, suffix: '!"}' } }, { refusals: ['invalid_code:f'] }, { time_budget_ms: 2000 }));
  }
  add(compute('code-hyphen-adversarial-1mib', 'ndc-10-hyphenated: 1 MiB of "0-" pairs is refused inside the time budget', [codeDef('ndc-10-hyphenated')],
    { json_repeat: { prefix: '{"action_type":"test.code.ndc-10-hyphenated.1","f":"', unit: '0-', count: 1 << 19, suffix: '"}' } }, { refusals: ['invalid_code:f'] }, { time_budget_ms: 2000 }));

  // ------------------------------------------------------------ timestamps
  const ts = (id, value, ok, description, extra) => compute(id, description, [DOC], text(j({ ...DOC_OK, signed_at: value })), ok ? 'ok' : { refusals: ['mistyped_field:signed_at'] }, extra);
  add(
    ts('timestamp-plain', '2026-07-08T09:30:00Z', true, 'a UTC timestamp with no fraction'),
    ts('timestamp-fraction-distinct', '2026-07-08T09:30:00.000Z', true, 'the fraction is lexical: ".000Z" is different content from "Z"', { relation: { different_caid_from: 'timestamp-plain' } }),
    ts('timestamp-long-fraction', '2026-07-08T09:30:00.123456789012Z', true, 'a fraction of any length'),
    ts('timestamp-year-zero', '0000-01-01T00:00:00Z', true, 'year 0000 is accepted'),
    ts('timestamp-leap-day-2024', '2024-02-29T00:00:00Z', true, '29 February in a leap year'),
    ts('timestamp-leap-day-2000', '2000-02-29T00:00:00Z', true, '2000 is a leap year'),
    ts('timestamp-refuses-leap-day-2023', '2023-02-29T00:00:00Z', false, '29 February in a common year'),
    ts('timestamp-refuses-leap-day-1900', '1900-02-29T00:00:00Z', false, '1900 is not a leap year'),
    ts('timestamp-refuses-april-31', '2026-04-31T00:00:00Z', false, 'April has 30 days'),
    ts('timestamp-refuses-month-13', '2026-13-01T00:00:00Z', false, 'month 13'),
    ts('timestamp-refuses-month-00', '2026-00-10T00:00:00Z', false, 'month 00'),
    ts('timestamp-refuses-day-00', '2026-01-00T00:00:00Z', false, 'day 00'),
    ts('timestamp-refuses-hour-24', '2026-07-08T24:00:00Z', false, 'hour 24'),
    ts('timestamp-refuses-second-60', '2026-12-31T23:59:60Z', false, 'second 60 is not accepted'),
    ts('timestamp-refuses-lowercase-t', '2026-07-08t09:30:00Z', false, 'lowercase t'),
    ts('timestamp-refuses-lowercase-z', '2026-07-08T09:30:00z', false, 'lowercase z'),
    ts('timestamp-refuses-offset', '2026-07-08T09:30:00+00:00', false, 'an offset instead of Z'),
    ts('timestamp-refuses-no-seconds', '2026-07-08T09:30Z', false, 'seconds are required'),
    ts('timestamp-refuses-empty-fraction', '2026-07-08T09:30:00.Z', false, 'a decimal point with no digits'),
    ts('timestamp-refuses-fullwidth-digit', '2026-07-08T09:30:0０Z', false, 'a fullwidth digit'),
    ts('timestamp-refuses-leading-space', ' 2026-07-08T09:30:00Z', false, 'a leading space'),
  );

  // ------------------------------------------------------------ parse
  const d42 = VALID_DIGEST.slice(0, 42);
  add(
    parse('parse-refuses-uppercase-prefix', 'the prefix is case-sensitive (%s"caid")', `CAID:1:payment.release.1:jcs-sha256:${VALID_DIGEST}`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-leading-space', 'no trimming', ` ${PAYMENT_CAID}`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-trailing-cr', 'a trailing carriage return', `${PAYMENT_CAID}\r`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-empty-segment', 'an empty name segment', `caid:1:payment..release.1:jcs-sha256:${VALID_DIGEST}`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-uppercase-type', 'an uppercase letter in the action type', `caid:1:Payment.release.1:jcs-sha256:${VALID_DIGEST}`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-version-01', 'the CAID version is exactly "1"', `caid:01:payment.release.1:jcs-sha256:${VALID_DIGEST}`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-version-2', 'an unknown CAID version', `caid:2:payment.release.1:jcs-sha256:${VALID_DIGEST}`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-fullwidth-version', 'a fullwidth digit version', `caid:１:payment.release.1:jcs-sha256:${VALID_DIGEST}`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-type-version-leading-zero', 'a type version with a leading zero', `caid:1:payment.release.01:jcs-sha256:${VALID_DIGEST}`, { refusals: ['malformed_caid'] }),
    parse('parse-accepts-huge-type-version', 'a type version of any length', `caid:1:payment.release.${'9'.repeat(40)}:jcs-sha256:${VALID_DIGEST}`, 'ok'),
    parse('parse-accepts-segment-trailing-hyphen', 'the grammar allows a trailing hyphen in a segment', `caid:1:payment-.release.1:jcs-sha256:${VALID_DIGEST}`, 'ok'),
    parse('parse-accepts-segment-double-hyphen', 'the grammar allows two hyphens in a row', `caid:1:pay--ment.release.1:jcs-sha256:${VALID_DIGEST}`, 'ok'),
    parse('parse-refuses-segment-leading-digit', 'a segment starts with a lowercase letter', `caid:1:1payment.release.1:jcs-sha256:${VALID_DIGEST}`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-segment-leading-hyphen', 'a segment does not start with a hyphen', `caid:1:-payment.release.1:jcs-sha256:${VALID_DIGEST}`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-cyrillic-a', 'U+0430 looks like "a" and is refused', `caid:1:pаyment.release.1:jcs-sha256:${VALID_DIGEST}`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-type-without-segment', 'an action type needs a name segment', `caid:1:1:jcs-sha256:${VALID_DIGEST}`, { refusals: ['malformed_caid'] }),
    parse('parse-accepts-two-part-type', 'one name segment and a version', `caid:1:payment.1:jcs-sha256:${VALID_DIGEST}`, 'ok'),
    parse('parse-refuses-standard-base64', '"+" and "/" are not base64url', `caid:1:payment.release.1:jcs-sha256:${VALID_DIGEST.slice(0, 20)}+/${VALID_DIGEST.slice(22)}`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-empty-digest', 'an empty digest', 'caid:1:payment.release.1:jcs-sha256:', { refusals: ['malformed_caid'] }),
    parse('parse-refuses-nul-in-digest', 'U+0000 in the digest', `caid:1:payment.release.1:jcs-sha256:${d42}\u0000`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-digest-42', 'a 42-character digest for a 32-octet suite', `caid:1:payment.release.1:jcs-sha256:${d42}`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-empty-version', 'an empty version', `caid::payment.release.1:jcs-sha256:${VALID_DIGEST}`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-empty-suite', 'an empty suite', `caid:1:payment.release.1::${VALID_DIGEST}`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-sixth-part', 'a sixth colon-separated part', `${PAYMENT_CAID}:x`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-digest-outside-alphabet', 'a digest character outside base64url is malformed_caid before any suite lookup', 'caid:1:payment.release.1:foo:!', { refusals: ['malformed_caid'] }),
    parse('parse-unknown-suite-registry-before-digest', 'the registry check precedes the digest check: an unregistered suite with a malformed-for-any-suite digest', 'caid:1:payment.release.1:sha3-jcs:AAAA', { refusals: ['unknown_suite'] }),
    parse('parse-unknown-suite-long-digest', 'an unregistered suite with a 64-character digest', `caid:1:payment.release.1:jcs-sha512:${'A'.repeat(64)}`, { refusals: ['unknown_suite'] }),
    parse('parse-refuses-suite-leading-digit', 'a suite that does not match the suite rule is malformed_caid, not unknown_suite', `caid:1:payment.release.1:1x:${VALID_DIGEST}`, { refusals: ['malformed_caid'] }),
    parse('parse-refuses-suite-uppercase', 'an uppercase suite does not match the suite rule', `caid:1:payment.release.1:JCS-SHA256:${VALID_DIGEST}`, { refusals: ['malformed_caid'] }),
  );
  return cases;
}

export const REFERENCE_DEFINITIONS = { T1, OBJ, PX, DOC, CUR, ISO4217, CODE_SYSTEMS, codeDef };
