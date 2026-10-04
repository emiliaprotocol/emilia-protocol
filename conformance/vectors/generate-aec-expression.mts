// SPDX-License-Identifier: Apache-2.0
//
// Writes aec-expression.v1.json, the frozen requirement-expression corpus for
// the AEC -08 expression contract (evaluator EP-AEC-EVALUATOR-08-v1), and its
// checksum file aec-expression.v1.SHA256SUMS.
//
// Every expectation here is stated by hand from the grammar: syntax validity,
// the refusal class of an invalid expression, the Boolean value of a valid
// one, and its canonical parse. Nothing is computed by an implementation under
// test. The only derived field is the parse identity, which is SHA-256 over
// the domain string, one 0x00 octet and the hand-written canonical parse.
//
// The corpus is frozen. `--check` proves the checked-in bytes are exactly what
// this file states and that the checksum file matches; changing a vector means
// a new corpus version, never an edit of v1.
//
//   node conformance/vectors/generate-aec-expression.mjs           # write
//   node conformance/vectors/generate-aec-expression.mjs --check   # verify
import crypto from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const CORPUS = 'aec-expression.v1.json';
const SUMS = 'aec-expression.v1.SHA256SUMS';
const DOMAIN = 'EP-AEC-EXPRESSION-PARSE-v1';

type Invalid = { invalid: 'syntax' | 'limit' };
type Vector = {
  id: string;
  group: string;
  aec_expression: { expression: string; eligible_types: string[] };
  expect: {
    syntax: 'VALID' | 'INVALID';
    invalid_class: 'syntax' | 'limit' | null;
    value: boolean | null;
    result: 'SATISFIED' | 'UNSATISFIED';
    canonical_parse: string | null;
    parse_identity: string | null;
  };
};

const identity = (canonical: string) => {
  if (!/^[\x21-\x7e ]+$/.test(canonical)) throw new Error(`canonical parse must be printable ASCII: ${canonical}`);
  return `sha256:${crypto.createHash('sha256')
    .update(Buffer.concat([Buffer.from(DOMAIN, 'ascii'), Buffer.from([0]), Buffer.from(canonical, 'ascii')]))
    .digest('hex')}`;
};

const vectors: Vector[] = [];
function v(id: string, group: string, expression: string, eligible: string[], outcome: Invalid | { canonical: string; value: boolean }) {
  if (vectors.some(x => x.id === id)) throw new Error(`duplicate id ${id}`);
  const invalid = 'invalid' in outcome;
  vectors.push({
    id, group,
    aec_expression: { expression, eligible_types: eligible },
    expect: invalid
      ? { syntax: 'INVALID', invalid_class: outcome.invalid, value: null, result: 'UNSATISFIED', canonical_parse: null, parse_identity: null }
      : { syntax: 'VALID', invalid_class: null, value: outcome.value, result: outcome.value ? 'SATISFIED' : 'UNSATISFIED',
        canonical_parse: outcome.canonical, parse_identity: identity(outcome.canonical) },
  });
}
const ok = (canonical: string, value: boolean) => ({ canonical, value });
const SYNTAX: Invalid = { invalid: 'syntax' };
const LIMIT: Invalid = { invalid: 'limit' };

// 1. The -08 acceptance table, row for row.
v('table-01-aORb-eligible-a', 'review-table', 'aORb', ['a'], ok('aORb', false));
v('table-02-aORb-eligible-aORb', 'review-table', 'aORb', ['aORb'], ok('aORb', true));
v('table-03-a-OR-b', 'review-table', 'a OR b', ['a'], ok('(a OR b)', true));
v('table-04-a-OR-paren-b', 'review-table', 'a OR(b)', ['a'], ok('(a OR b)', true));
v('table-05-paren-a-OR-paren-b', 'review-table', '(a)OR(b)', ['a'], ok('(a OR b)', true));
v('table-06-aOR-paren-b', 'review-table', 'aOR(b)', ['aOR'], SYNTAX);
v('table-07-paren-a-ORb', 'review-table', '(a)ORb', ['a', 'ORb'], SYNTAX);
v('table-08-a-ANDb', 'review-table', 'a ANDb', ['a', 'ANDb'], SYNTAX);
v('table-09-lowercase-and-identifier', 'review-table', 'and', ['and'], ok('and', true));
v('table-10-And-case-sensitive', 'review-table', 'And', ['and'], ok('And', false));
v('table-11-bare-AND', 'review-table', 'AND', ['AND'], SYNTAX);
v('table-12-lowercase-or-not-operator', 'review-table', 'a or b', ['a', 'b'], SYNTAX);
v('table-13-left-to-right', 'review-table', 'a OR b AND c', ['a'], ok('((a OR b) AND c)', false));
v('table-14-explicit-group', 'review-table', 'a OR (b AND c)', ['a'], ok('(a OR (b AND c))', true));
v('table-15-malformed-branch-behind-true-or', 'review-table', 'a OR (b AND)', ['a'], SYNTAX);
v('table-16-malformed-branch-behind-false-and', 'review-table', 'missing AND (b OR)', [], SYNTAX);
v('table-17-trailing-identifier', 'review-table', 'a OR b trailing', ['a'], SYNTAX);

// 2. Whitespace: only SP, HTAB, CR and LF separate tokens; nothing is trimmed.
v('ws-ascii-four', 'whitespace', ' \ta\r\nOR\tb \n', ['b'], ok('(a OR b)', true));
v('ws-ascii-only-is-empty', 'whitespace', ' \t\r\n', [], SYNTAX);
v('ws-empty-string', 'whitespace', '', [], SYNTAX);
v('ws-nbsp-separator', 'whitespace', 'a\u00a0OR b', ['a'], SYNTAX);
v('ws-nbsp-trailing-not-trimmed', 'whitespace', 'a\u00a0', ['a'], SYNTAX);
v('ws-em-space', 'whitespace', 'a\u2003OR b', ['a'], SYNTAX);
v('ws-line-separator', 'whitespace', 'a\u2028OR b', ['a'], SYNTAX);
v('ws-paragraph-separator', 'whitespace', 'a OR\u2029b', ['a'], SYNTAX);
v('ws-next-line', 'whitespace', 'a\u0085OR b', ['a'], SYNTAX);
v('ws-bom-leading', 'whitespace', '\ufeffa', ['a'], SYNTAX);
v('ws-zero-width-space', 'whitespace', 'a\u200bOR b', ['a'], SYNTAX);
v('ws-vertical-tab', 'whitespace', 'a\u000bOR b', ['a'], SYNTAX);
v('ws-form-feed', 'whitespace', 'a\u000cOR b', ['a'], SYNTAX);
v('ws-form-feed-trailing-not-trimmed', 'whitespace', 'a\u000c', ['a'], SYNTAX);

// 3. Maximal identifier runs: operator-looking substrings stay inside one identifier.
v('ident-dotted-OR', 'identifier', 'a.OR.b', ['a.OR.b'], ok('a.OR.b', true));
v('ident-dotted-OR-not-split', 'identifier', 'a.OR.b', ['a', 'b'], ok('a.OR.b', false));
v('ident-colon-AND', 'identifier', 'x:AND:y', ['x:AND:y'], ok('x:AND:y', true));
v('ident-hyphen-OR-not-split', 'identifier', 'p-OR-q', ['p', 'q'], ok('p-OR-q', false));
v('ident-underscore-AND-operand', 'identifier', 'r_AND_s OR t', ['r_AND_s'], ok('(r_AND_s OR t)', true));
v('ident-urn-mixed', 'identifier', 'urn:ep.ORx-1_AND', ['urn:ep.ORx-1_AND'], ok('urn:ep.ORx-1_AND', true));
v('ident-AND-prefix-run', 'identifier', 'AND.x', ['AND.x'], ok('AND.x', true));
v('ident-ORb-alone', 'identifier', 'ORb', ['ORb'], ok('ORb', true));
v('ident-ORb-operand', 'identifier', 'a OR ORb', ['ORb'], ok('(a OR ORb)', true));
v('ident-ANDOR', 'identifier', 'ANDOR', ['ANDOR'], ok('ANDOR', true));
v('ident-mixed-case-Or', 'identifier', 'Or', ['Or'], ok('Or', true));
v('ident-mixed-case-oR-not-operator', 'identifier', 'a oR b', ['a', 'b'], SYNTAX);
v('ident-case-sensitive-lookup', 'identifier', 'A OR b', ['a'], ok('(A OR b)', false));
v('ident-digits', 'identifier', '123 AND x.9', ['123', 'x.9'], ok('(123 AND x.9)', true));
v('ident-single-hyphen', 'identifier', '-', ['-'], ok('-', true));
v('ident-bare-OR', 'identifier', 'OR', ['OR'], SYNTAX);
v('ident-leading-operator', 'identifier', 'AND a', ['a'], SYNTAX);
v('ident-trailing-operator', 'identifier', 'a AND', ['a'], SYNTAX);
v('ident-double-operator', 'identifier', 'a OR OR b', ['a', 'b'], SYNTAX);
v('ident-adjacent-identifiers', 'identifier', 'a b', ['a', 'b'], SYNTAX);
v('ident-invalid-character', 'identifier', 'a!', ['a'], SYNTAX);
v('ident-slash-not-identifier', 'identifier', 'a/b', ['a/b'], SYNTAX);

// 4. Operator aliases normalize to AND and OR in the canonical parse.
v('alias-and', 'alias', 'a && b', ['a', 'b'], ok('(a AND b)', true));
v('alias-or-unspaced', 'alias', 'a||b', ['b'], ok('(a OR b)', true));
v('alias-mixed-left-to-right', 'alias', 'a&&b||c', ['c'], ok('((a AND b) OR c)', true));
v('alias-single-ampersand', 'alias', 'a & b', ['a', 'b'], SYNTAX);
v('alias-single-bar', 'alias', 'a | b', ['a', 'b'], SYNTAX);
v('alias-triple-ampersand', 'alias', 'a &&& b', ['a', 'b'], SYNTAX);
v('alias-triple-bar', 'alias', 'a ||| b', ['a', 'b'], SYNTAX);
v('alias-operator-pair', 'alias', 'a AND && b', ['a', 'b'], SYNTAX);

// 5. Grouping: redundant parentheses vanish; evaluation order never changes.
v('group-redundant', 'grouping', '(a)', ['a'], ok('a', true));
v('group-double-redundant', 'grouping', '((a))', [], ok('a', false));
v('group-empty', 'grouping', '()', [], SYNTAX);
v('group-whole', 'grouping', '(a OR b)', ['b'], ok('(a OR b)', true));
v('group-left-chain', 'grouping', 'a OR b OR c', ['c'], ok('((a OR b) OR c)', true));
v('group-right-explicit', 'grouping', 'a OR (b OR c)', ['c'], ok('(a OR (b OR c))', true));
v('group-and-then-or', 'grouping', 'a AND b OR c', ['c'], ok('((a AND b) OR c)', true));
v('group-four-operands', 'grouping', 'a OR b AND c OR d', ['d'], ok('(((a OR b) AND c) OR d)', true));
v('group-explicit-same-tree-as-table-13', 'grouping', '(a OR b) AND c', ['a'], ok('((a OR b) AND c)', false));
v('group-nested-alias', 'grouping', 'a && (b || c)', ['a', 'c'], ok('(a AND (b OR c))', true));
v('group-unclosed', 'grouping', '(a', ['a'], SYNTAX);
v('group-unopened', 'grouping', 'a)', ['a'], SYNTAX);
v('group-leading-close', 'grouping', ')a', ['a'], SYNTAX);
v('group-extra-close', 'grouping', '(a))', ['a'], SYNTAX);
v('group-missing-close', 'grouping', '((a)', ['a'], SYNTAX);
v('group-trailing-input-after-true', 'grouping', 'a OR b c', ['a'], SYNTAX);
v('group-unclosed-behind-false-and', 'grouping', 'missing AND (b', [], SYNTAX);

// 6. Limits. Length is 4096 UTF-8 octets of the whole string, whitespace
// included. A valid expression always has an odd token count (n identifiers,
// n-1 operators, paired parentheses), so 255 tokens is the longest valid one,
// any 256-token expression is malformed, and the 257th token is refused by
// the lexer's limit before the parser runs.
const leftChain = (ids: string[], op: string) => ids.slice(1).reduce((acc, id) => `(${acc} ${op} ${id})`, ids[0]);
const ids = (prefix: string, n: number) => Array.from({ length: n }, (_, i) => `${prefix}${i}`);
const r128 = ids('r', 128);
const r129 = ids('r', 129);
v('limit-length-4095-identifier', 'limit', 'b'.repeat(4095), ['b'.repeat(4095)], ok('b'.repeat(4095), true));
v('limit-length-4096-identifier', 'limit', 'a'.repeat(4096), [], ok('a'.repeat(4096), false));
v('limit-length-4096-identifier-eligible', 'limit', 'a'.repeat(4096), ['a'.repeat(4096)], ok('a'.repeat(4096), true));
v('limit-length-4097-identifier', 'limit', 'a'.repeat(4097), ['a'], LIMIT);
v('limit-length-4096-with-whitespace', 'limit', `${' '.repeat(4095)}a`, ['a'], ok('a', true));
v('limit-length-4097-with-whitespace', 'limit', `${' '.repeat(4096)}a`, ['a'], LIMIT);
v('limit-length-octets-4096-nbsp-is-syntax', 'limit', `${'a'.repeat(4094)}\u00a0`, [], SYNTAX);
v('limit-length-octets-4097-nbsp-is-limit', 'limit', `${'a'.repeat(4095)}\u00a0`, [], LIMIT);
v('limit-tokens-253', 'limit', ids('r', 127).join(' OR '), ['r126'], ok(leftChain(ids('r', 127), 'OR'), true));
v('limit-tokens-255-true', 'limit', r128.join(' OR '), ['r127'], ok(leftChain(r128, 'OR'), true));
v('limit-tokens-255-false', 'limit', r128.join(' OR '), [], ok(leftChain(r128, 'OR'), false));
v('limit-tokens-255-and', 'limit', r128.join(' AND '), r128, ok(leftChain(r128, 'AND'), true));
v('limit-tokens-256-ends-in-operator', 'limit', `${r128.join(' OR ')} OR`, r128, SYNTAX);
v('limit-tokens-257', 'limit', r129.join(' OR '), r129, LIMIT);
v('limit-tokens-257-behind-true-or', 'limit', `a OR ${r128.join(' OR ')}`, ['a'], LIMIT);
v('limit-tokens-257-behind-false-and', 'limit', `missing AND ${r128.join(' OR ')}`, [], LIMIT);
v('limit-tokens-257-before-invalid-character', 'limit', `${r129.join(' OR ')} !`, [], LIMIT);
v('limit-tokens-invalid-character-before-257', 'limit', `! ${r129.join(' OR ')}`, [], SYNTAX);
const nest = (n: number, inner: string) => `${'('.repeat(n)}${inner}${')'.repeat(n)}`;
v('limit-depth-31', 'limit', nest(31, 'a'), ['a'], ok('a', true));
v('limit-depth-32', 'limit', nest(32, 'a'), ['a'], ok('a', true));
v('limit-depth-33', 'limit', nest(33, 'a'), ['a'], LIMIT);
v('limit-depth-32-operator-inside', 'limit', nest(32, 'a AND b'), ['a', 'b'], ok('(a AND b)', true));
v('limit-depth-33-behind-true-or', 'limit', `a OR ${nest(33, 'b')}`, ['a'], LIMIT);
v('limit-depth-33-behind-false-and', 'limit', `missing AND ${nest(33, 'b')}`, [], LIMIT);
v('limit-depth-33-unclosed-is-limit', 'limit', `${'('.repeat(33)}a`, ['a'], LIMIT);
v('limit-depth-32-unclosed-is-syntax', 'limit', `${'('.repeat(32)}a${')'.repeat(31)}`, ['a'], SYNTAX);

const corpus = {
  '@version': 'EP-AEC-EXPRESSION-VECTORS-v1',
  suite: 'EP-AEC-EXPRESSION-v1',
  frozen: true,
  description: 'Requirement-expression corpus for the AEC -08 expression contract (evaluator EP-AEC-EVALUATOR-08-v1). Each vector states syntax validity, the refusal class of an invalid expression, the Boolean value of a valid expression over the given eligible component types, the canonical parse, and the parse identity as separate assertions.',
  claim_scope: 'Passing this finite corpus is necessary for the -08 expression profile, not proof of correctness for every input. A matching parse identity is an interpretation diagnostic; it does not prove a matching verdict. The JavaScript, Python and Go implementations that run it are one team\'s ports in one repository; their agreement is a consistency check, not independent implementation. Python and Go agreement covers requirement-expression evaluation only, not the structured -07/-08 requirement and replay contract.',
  evaluator_revision: 'EP-AEC-EVALUATOR-08-v1',
  grammar: {
    whitespace: ['U+0020', 'U+0009', 'U+000D', 'U+000A'],
    identifier_characters: 'A-Z a-z 0-9 _ . : -',
    operators: { AND: ['AND', '&&'], OR: ['OR', '||'] },
    token_boundary: 'longest identifier run first; a complete run equal to AND or OR is an operator, any other run is an identifier',
    grouping: 'equal precedence, left to right',
  },
  limits: { max_octets: 4096, max_tokens: 256, max_depth: 32, counted_tokens: 'identifiers, operators and parentheses' },
  refusal_order: 'length cap, then lexer left to right (invalid character: syntax; 257th token: limit), then parser left to right (depth beyond 32: limit; otherwise syntax)',
  parse_identity: {
    domain: DOMAIN,
    construction: 'sha256: followed by lowercase hex SHA-256 of ASCII(domain) || 0x00 || ASCII(canonical_parse)',
    canonical_parse: 'identifier as written; operator node as ( left SP AND|OR SP right ); && and || render as AND and OR; source parentheses that do not change grouping are dropped; no commutation or reassociation',
  },
  vectors,
};

// ASCII-only bytes: every non-ASCII code point is written as a JSON escape.
const text = `${JSON.stringify(corpus, null, 2).replace(/[\u007f-\uffff]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`)}\n`;
const sha = crypto.createHash('sha256').update(text, 'utf8').digest('hex');
const sums = `${sha}  ${CORPUS}\n`;

if (process.argv.includes('--check')) {
  const current = readFileSync(resolve(here, CORPUS), 'utf8');
  if (current !== text) throw new Error(`${CORPUS} differs from the frozen corpus this generator states`);
  if (readFileSync(resolve(here, SUMS), 'utf8') !== sums) throw new Error(`${SUMS} does not match ${CORPUS}`);
  console.log(`${CORPUS}: frozen corpus and ${SUMS} match (${vectors.length} vectors, sha256:${sha})`);
} else {
  writeFileSync(resolve(here, CORPUS), text);
  writeFileSync(resolve(here, SUMS), sums);
  console.log(`wrote ${CORPUS} (${vectors.length} vectors, sha256:${sha})`);
}
