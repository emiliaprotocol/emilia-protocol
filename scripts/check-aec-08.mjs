#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Guards the staged draft-schrock-ep-authorization-evidence-chain-08 packet:
// the packet holds one source and its two renders, the checksums match, the
// renders carry the source's name, date and examples, the -08 requirement
// expression text is present and the -07 grammar and evaluator value are
// gone, the draft does not promise that a parse identity proves a verdict,
// the posted -07 source is unchanged, and the examples, limits, digests and
// corpus that Section 8 cites are the ones on this tree: the frozen corpus
// bytes match the SHA-256 in the draft and its locator, and the reference
// evaluator on this tree reproduces every corpus vector and every inline
// example. It also replays the genuine -07 record that the released 6.0.0
// evaluator made and requires UNSUPPORTED_REVISION with the record unmodified.
//
// `--render` additionally re-renders the source with xml2rfc 3.34.0 (network
// needed for the bibxml includes) and requires byte-identical TXT and HTML.

import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = new URL('../', import.meta.url);
const root = new URL('standards/staged/NEXT-AEC-08/', repo);
const basename = 'draft-schrock-ep-authorization-evidence-chain-08';
const posted07 = new URL('standards/staged/NEXT-AEC-07/UPLOAD-THIS/draft-schrock-ep-authorization-evidence-chain-07.xml', repo);
// SHA-256 of the -07 source as archived by the IETF (posted 2026-09-28).
const posted07Sha256 = 'bfcf111687d6b48cd6b32b829144673c6b70cb340209316dc5a1945a1a62d1e6';
const corpusPath = new URL('conformance/vectors/aec-expression.v1.json', repo);
const corpusUrl = 'https://raw.githubusercontent.com/emiliaprotocol/emilia-protocol/'
  + '2ebba2d8439b8e268ba6c3bc2fbbfdd42d2fb318/conformance/vectors/aec-expression.v1.json';
const corpusCommit = '2ebba2d8439b8e268ba6c3bc2fbbfdd42d2fb318';

/** @param {unknown} condition @param {string} message @returns {asserts condition} */
function invariant(condition, message) {
  if (!condition) throw new Error(`AEC -08 packet: ${message}`);
}
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const sameSet = (a, b) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());

// ---- Packet structure and checksums ---------------------------------------
invariant(sameSet(readdirSync(new URL('UPLOAD-THIS/', root)), [`${basename}.xml`]),
  'UPLOAD-THIS must contain exactly the -08 XML source');
invariant(sameSet(readdirSync(new URL('RENDERS/', root)), [`${basename}.html`, `${basename}.txt`]),
  'RENDERS must contain exactly the -08 HTML and TXT files');

const xmlBytes = readFileSync(new URL(`UPLOAD-THIS/${basename}.xml`, root));
const txtBytes = readFileSync(new URL(`RENDERS/${basename}.txt`, root));
const htmlBytes = readFileSync(new URL(`RENDERS/${basename}.html`, root));
const xml = xmlBytes.toString('utf8');
const txt = txtBytes.toString('utf8');
const html = htmlBytes.toString('utf8');

const manifest = readFileSync(new URL('SHA256SUMS.txt', root), 'utf8').trim().split('\n');
const expectedPaths = [`UPLOAD-THIS/${basename}.xml`, `RENDERS/${basename}.html`, `RENDERS/${basename}.txt`];
invariant(manifest.length === expectedPaths.length, 'checksum manifest must contain exactly three rows');
for (const [index, relative] of expectedPaths.entries()) {
  const match = /^([a-f0-9]{64}) {2}(.+)$/.exec(manifest[index]);
  invariant(match !== null && match[2] === relative, `malformed checksum row for ${relative}`);
  invariant(sha256(readFileSync(new URL(relative, root))) === match[1], `checksum mismatch for ${relative}`);
}

// ---- Encoding and layout ---------------------------------------------------
invariant(/^[\x09\x0a\x0d\x20-\x7e]*$/.test(xml), 'XML source must be printable ASCII');
invariant(/^[\x09\x0a\x0c\x0d\x20-\x7e]*$/.test(txt), 'TXT render must be printable ASCII');
invariant(txt.split('\n').every((line) => line.length <= 72), 'TXT render has a line over 72 columns');
invariant(!/[\u2013\u2014]/.test(xml + txt + html), 'no en or em dash may appear');

// xml2rfc breaks lines only at spaces and after existing hyphens, so joining
// a line-final hyphen to the next line restores the text as written.
const flatXml = xml.replace(/\s+/g, ' ');
const flatTxt = txt
  .split('\n')
  .filter((line) => !/\[Page \d+\]$/.test(line) && !/^Internet-Draft {2,}.* \d{4}$/.test(line))
  .join('\n')
  .replace(/\f/g, '')
  .replace(/-\n\s*/g, '-')
  .replace(/\s+/g, ' ');

// The source's own words, for the checks below that must hold in the XML as
// well as in the TXT render (the render is pinned only by checksum unless
// --render is passed).
const xmlText = xml
  .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
  .replace(/<[^>]+>/g, '')
  .replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&')
  .replace(/\s+/g, ' ');

// ---- The renders belong to this source -------------------------------------
invariant(txt.includes(basename) && html.includes(basename), 'renders do not name the -08 draft');
invariant(/^Internet-Draft .* October 2026$/m.test(txt) && txt.includes('4 October 2026'),
  'TXT render does not carry the source date 4 October 2026');

// ---- Required -08 text -----------------------------------------------------
for (const required of [
  `docName="${basename}"`,
  `value="${basename}"`,
  '<date year="2026" month="October" day="4"/>',
  '<name>Changes in -08</name>',
  '<name>Changes in -07</name>',
  'operator = %s"AND" / %s"OR" / "&&" / "||"',
  'ows = *( SP / HTAB / CR / LF )',
  'reference.RFC.7405.xml',
  'reference.RFC.5234.xml',
  'draft-schrock-canonical-action-identifier-05',
  'draft-schrock-ep-authorization-receipts-13',
  'draft-schrock-ep-quorum-04',
  'draft-schrock-action-evidence-boundary-07',
  `target="${corpusUrl}"`,
]) invariant(flatXml.includes(required), `XML is missing required -08 text: ${required}`);

for (const required of [
  // Section 4: the stored expression is digested as stored, under the named digest.
  'which is the evidence digest (Section 2) of the complete requirement object',
  'a verifier MUST NOT trim it, change its case, apply Unicode normalization to it, or otherwise rewrite it before computing the digest',
  // Section 8.1 and 8.2: grammar, whitespace and token boundaries.
  'with the case-sensitive string syntax of [RFC7405]',
  'SP, HTAB, CR, and LF are its only whitespace characters',
  'part of an "&&" or "||" operator makes the expression invalid, so a single "&" or "|" does',
  'NO-BREAK SPACE (U+00A0), EM SPACE (U+2003), LINE SEPARATOR (U+2028), BYTE ORDER MARK (U+FEFF), ZERO WIDTH SPACE (U+200B), VERTICAL TAB (U+000B), FORM FEED (U+000C)',
  'the tokenizer MUST take the longest run of identifier characters before classifying it, and MUST then classify the complete run',
  'a run that is exactly "AND" or exactly "OR" is that operator, and every other run is an identifier',
  'AND and OR are reserved only as expression tokens',
  'this revision defines no quoting mechanism',
  // Section 8.3: validity separate from truth, the review's normative text.
  'An evaluator MUST validate the entire expression, including every operand and parenthesized branch, and consume all input before reporting SATISFIED.',
  'Boolean short-circuiting MUST NOT bypass syntax or configured resource-limit validation.',
  'A syntactically valid unknown identifier evaluates to false; malformed syntax or an exceeded limit makes the evaluation UNSATISFIED.',
  'with no case folding and no Unicode normalization',
  'group strictly from left to right: "a OR b AND c" is "((a OR b) AND c)"',
  'Such a refusal is not an evaluation and produces no replay record.',
  // Section 8.4: limits as they are.
  'At most 4096 octets in the UTF-8 encoding of the expression\'s string value after JSON decoding',
  'A lone surrogate, which some host languages can hold in a string although it is not Unicode text, counts as three octets and is an invalid character.',
  'At most 256 tokens. Identifiers, operators (including "&&" and "||"), and parentheses each count as one token',
  'The limit counts tokens, not names',
  'At most 32 levels of parentheses',
  'An evaluator MUST apply exactly these limits, neither raising nor lowering them.',
  'it MUST therefore be part of the evaluator profile that a replay record identifies by its evaluator_profile_digest',
  // Section 8.4 refusal order: a token counts once complete; a lone & or | is a syntax refusal.
  'an invalid character, including a single "&" or "|", is a syntax refusal where it is met, and a token counts only once it is complete, so that completing a 257th token is a limit refusal',
  // Section 8.6: the parse identity is a diagnostic only.
  'An evaluator MUST evaluate the same tree from which it computes the canonical parse and parse identity.',
  'A matching parse identity does not guarantee matching verdicts.',
  'this document does not claim that every disagreement between evaluators is detected',
  'The parse identity is not a member of EP-AEC-REQUIREMENT-v1 or EP-AEC-REPLAY-v1, and an evaluator MUST NOT add it to either object',
  '"EP-AEC-EXPRESSION-PARSE-v1" || 0x00 ||',
  // Section 8.7: the corpus.
  'An evaluator MUST NOT need it, or fetch it, at run time.',
  // Section 9: whole-expression validation in the fail-closed order.
  'Validate the entire requirement expression under Section 8 and produce its one tree',
  'evaluate the tree produced in step 4 over it',
  // Section 10: revision and migration.
  'sets it to the string EP-AEC-EVALUATOR-08-v1',
  'Records move between revisions by re-evaluation, never by relabeling',
  'A stored record MUST NOT be modified.',
  'with an evaluator of the record\'s own revision, and MUST compare the complete record by its replay digest',
  // Section 10: the evaluator profile digest the -07 template omitted, and its scope.
  'The evaluator_profile_digest identifies the evaluator profile that produced the record.',
  'This document defines neither a portable serialization of that description nor a closed list of the further normalized fact members',
  'expected action inputs, requirement profile, evaluator profile, explicit verification time',
  'Re-evaluating the evidence under a different revision produces a new, separately identified record.',
  'MUST report the comparison as unsupported or refuse it',
  // Section 14.
  'Parser differentials.',
  'A finite corpus can show that an implementation is wrong on its vectors, not that it is right on every input.',
  // Changes and Implementation Status.
  'already agree with every vector of the corpus in Section 8.7 on syntax validity and Boolean value',
  'already agree with every vector of the new corpus on syntax validity and Boolean value',
  'or the strict JSON error when the requirement is not I-JSON',
  'No wire-format change.',
  '@emilia-protocol/verify 6.0.0, implements EP-AEC-EVALUATOR-07-v1',
  'is not yet in a published release',
  'aec_requirement_invalid',
  'their agreement with the JavaScript implementation on the corpus is agreement on expression evaluation only',
  'their agreement is a consistency check, not independent implementation',
  'reports authorization_decision as false',
]) {
  invariant(flatTxt.includes(required), `TXT rendering is stale or missing: ${required}`);
  // Cross-references render as "Section N" or "[NAME]"; the rest must also be
  // in the source as written.
  if (!/Section \d|\[/.test(required)) invariant(xmlText.includes(required), `XML source is missing: ${required}`);
}

for (const forbidden of [
  // -07 grammar and evaluator value.
  'operator = "AND" / "OR"',
  'WS = *(SP / HTAB / CR / LF)',
  'sets it to the string EP-AEC-EVALUATOR-07-v1',
  `docName="draft-schrock-ep-authorization-evidence-chain-07"`,
  'draft-schrock-canonical-action-identifier-04',
  // Promises the review rejected.
  'cannot happen silently',
  'every disagreement is caught',
  'every disagreement is detected.',
  'guarantees matching',
  'proves the verdict',
  'backward compatible',
  // Superseded -08 drafting the clean-room review found ambiguous or too broad.
  'reference parsers of -07 already read every vector',
  'An evaluator MUST NOT raise these limits.',
  'tighter expression limit',
  'or part of an operator makes',
  'expression size, and verifier execution',
]) {
  invariant(!flatXml.includes(forbidden), `XML contains rejected text: ${forbidden}`);
  invariant(!flatTxt.includes(forbidden), `TXT contains rejected text: ${forbidden}`);
  invariant(!xmlText.includes(forbidden), `XML source contains rejected text: ${forbidden}`);
}

invariant(sha256(readFileSync(posted07)) === posted07Sha256, 'immutable posted -07 XML changed');

// ---- Corpus identity -------------------------------------------------------
const corpusBytes = readFileSync(corpusPath);
const corpusSha = sha256(corpusBytes);
const corpus = JSON.parse(corpusBytes.toString('utf8'));
const vectorsSection = xml.slice(xml.indexOf('<section anchor="expr-vectors">'));
const draftCorpusSha = /<!\[CDATA\[\s*([a-f0-9]{64})\s*\]\]>/.exec(vectorsSection)?.[1];
invariant(draftCorpusSha === corpusSha, `Section 8.7 SHA-256 ${draftCorpusSha} is not the corpus SHA-256 ${corpusSha}`);
const sums = readFileSync(new URL('conformance/vectors/aec-expression.v1.SHA256SUMS', repo), 'utf8');
invariant(sums.trim() === `${corpusSha}  aec-expression.v1.json`, 'corpus SHA256SUMS does not match the corpus');
const locator = readFileSync(new URL('conformance/vectors/README.md', repo), 'utf8');
invariant(locator.includes(corpusUrl) && locator.includes(corpusSha), 'conformance/vectors/README.md locator differs from the draft');
let pinnedNote = 'commit not in this clone; locator consistency checked';
try {
  const pinned = execFileSync('git', ['show', `${corpusCommit}:conformance/vectors/aec-expression.v1.json`],
    { cwd: fileURLToPath(repo), stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 16 * 1024 * 1024 });
  invariant(sha256(pinned) === corpusSha, `corpus bytes at ${corpusCommit} differ from the draft SHA-256`);
  pinnedNote = `bytes at ${corpusCommit.slice(0, 9)} match`;
} catch (error) {
  if (error instanceof Error && error.message.startsWith('AEC -08 packet:')) throw error;
}

const vectors = corpus.vectors;
const valid = vectors.filter((v) => v.expect.syntax === 'VALID').length;
const countSentence = `Each of its ${vectors.length} vectors, ${valid} valid and ${vectors.length - valid} invalid`;
invariant(flatTxt.includes(countSentence) && xmlText.includes(countSentence),
  `Section 8.7 counts differ from the corpus (${vectors.length} vectors, ${valid} valid)`);
invariant(corpus.limits.max_octets === 4096 && corpus.limits.max_tokens === 256 && corpus.limits.max_depth === 32,
  'corpus limits differ from Section 8.4');
invariant(corpus.parse_identity.domain === 'EP-AEC-EXPRESSION-PARSE-v1', 'corpus parse identity domain differs from Section 8.6');
invariant(corpus.evaluator_revision === 'EP-AEC-EVALUATOR-08-v1', 'corpus evaluator revision differs from Section 10');

// ---- The implementation on this tree ---------------------------------------
const src = readFileSync(new URL('packages/verify/src/evidence-chain.ts', repo), 'utf8');
invariant(/export const AEC_EVALUATOR_REVISION = 'EP-AEC-EVALUATOR-08-v1';/.test(src),
  'packages/verify/src/evidence-chain.ts does not emit EP-AEC-EVALUATOR-08-v1');
const aec = await import(new URL('packages/verify/evidence-chain.js', repo).href);
invariant(aec.AEC_EVALUATOR_REVISION === 'EP-AEC-EVALUATOR-08-v1', 'the built evaluator does not emit EP-AEC-EVALUATOR-08-v1');
invariant(aec.AEC_EXPRESSION_PARSE_DOMAIN === 'EP-AEC-EXPRESSION-PARSE-v1', 'built parse identity domain differs from Section 8.6');
invariant(aec.AEC_EXPRESSION_LIMITS.maxOctets === 4096 && aec.AEC_EXPRESSION_LIMITS.maxTokens === 256
  && aec.AEC_EXPRESSION_LIMITS.maxDepth === 32, 'built expression limits differ from Section 8.4');

const run = (expression, eligible) => aec.evaluateAecRequirementExpression(expression, eligible);
const fields = ['syntax', 'invalid_class', 'value', 'result', 'canonical_parse', 'parse_identity'];
for (const vector of vectors) {
  const got = run(vector.aec_expression.expression, vector.aec_expression.eligible_types);
  for (const field of fields) {
    invariant(got[field] === vector.expect[field],
      `implementation differs from corpus vector ${vector.id} on ${field}: ${JSON.stringify(got[field])}`);
  }
}

// ---- Inline examples (Table 1) ---------------------------------------------
const table = xml.slice(xml.indexOf('<table anchor="expr-example-table">'), xml.indexOf('</table>'));
const decode = (s) => s.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
const rows = [...table.matchAll(/<tr><td>(.*?)<\/td><td>(.*?)<\/td><td>(.*?)<\/td><td>(.*?)<\/td><td>(.*?)<\/td><\/tr>/g)]
  .map((m) => m.slice(1).map(decode));
const reviewRows = vectors.filter((v) => v.group === 'review-table');
invariant(rows.length === 17 && reviewRows.length === 17, `Table 1 must hold the 17 review rows (found ${rows.length})`);
for (const [expression, eligibleText, validText, valueText, canonical] of rows) {
  const eligible = eligibleText === 'none' ? [] : eligibleText.split(', ');
  const vector = reviewRows.find((v) => v.aec_expression.expression === expression
    && sameSet(v.aec_expression.eligible_types, eligible));
  invariant(vector !== undefined, `Table 1 row ${expression} / ${eligibleText} is not a review-table corpus vector`);
  const want = {
    syntax: validText === 'yes' ? 'VALID' : 'INVALID',
    value: valueText === 'n/a' ? null : valueText === 'true',
    canonical_parse: canonical === 'n/a' ? null : canonical,
  };
  const got = run(expression, eligible);
  for (const field of Object.keys(want)) {
    invariant(vector.expect[field] === want[field], `Table 1 row ${expression}: ${field} differs from corpus ${vector.id}`);
    invariant(got[field] === want[field], `Table 1 row ${expression}: ${field} differs from the implementation`);
  }
  // The rendered table must show the same row the source holds.
  const cells = [expression, eligibleText, validText, valueText, canonical];
  invariant(new RegExp(`\\|\\s*${cells.map((c) => c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('\\s*\\|\\s*')}\\s*\\|`).test(txt),
    `TXT Table 1 is missing the row for ${expression} / ${eligibleText}`);
}

// ---- Inline parse identity and limit examples ------------------------------
const pid = /<!\[CDATA\[\s*(sha256:[a-f0-9]{32})\s+([a-f0-9]{32})\s*\]\]>/.exec(xml);
invariant(pid !== null, 'Section 8.5 parse identity example not found');
const inlineIdentity = pid[1] + pid[2];
const table13 = run('a OR b AND c', ['a']);
invariant(table13.canonical_parse === '((a OR b) AND c)' && table13.parse_identity === inlineIdentity,
  'Section 8.5 parse identity differs from the implementation');
invariant(vectors.find((v) => v.id === 'table-13-left-to-right')?.expect.parse_identity === inlineIdentity,
  'Section 8.5 parse identity differs from the corpus');

const chain = (n, op = 'OR') => Array.from({ length: n }, (_, i) => `r${i}`).join(` ${op} `);
const nest = (n, inner) => `${'('.repeat(n)}${inner}${')'.repeat(n)}`;
/** @type {Array<[string, string[], string, string | null, number | null]>} */
const limitExamples = [
  [chain(128), ['r127'], 'VALID', null, 255],
  [`${chain(128)} OR`, [], 'INVALID', 'syntax', 256],
  [chain(129), [], 'INVALID', 'limit', 257],
  [`a OR ${chain(128)}`, ['a'], 'INVALID', 'limit', 257],
  [`missing AND ${chain(128)}`, [], 'INVALID', 'limit', 257],
  [nest(32, 'a'), ['a'], 'VALID', null, null],
  [nest(33, 'a'), ['a'], 'INVALID', 'limit', null],
  [`a OR ${nest(33, 'b')}`, ['a'], 'INVALID', 'limit', null],
  [`missing AND ${nest(33, 'b')}`, [], 'INVALID', 'limit', null],
];
for (const [expression, eligible, syntax, invalidClass, tokens] of limitExamples) {
  const got = run(expression, eligible);
  invariant(got.syntax === syntax && got.invalid_class === invalidClass,
    `Section 8.5 limit example (${expression.length} chars) is ${got.syntax}/${got.invalid_class}, not ${syntax}/${invalidClass}`);
  if (tokens !== null && syntax === 'VALID') {
    invariant(aec.compileAecRequirementExpression(expression).token_count === tokens, 'token count example differs');
  }
  const vector = vectors.find((v) => v.aec_expression.expression === expression);
  invariant(vector === undefined || (vector.expect.syntax === syntax && vector.expect.invalid_class === invalidClass),
    `Section 8.5 limit example disagrees with corpus ${vector?.id}`);
}
invariant(vectors.filter((v) => v.group === 'limit').length > 0, 'corpus has no limit vectors');

// ---- Implementation Status: replay of a genuine -07 record ------------------
// The draft says replay reports a record of another revision, including -07,
// as unsupported without modifying it, and returns a new -08 record. Check
// that against the record the released 6.0.0 evaluator made
// (conformance/vectors/aec-replay-07.v1.*), not an edited -08 record.
execFileSync(process.execPath, [fileURLToPath(new URL('conformance/vectors/generate-aec-replay-07.mjs', repo)), '--check'],
  { stdio: ['ignore', 'pipe', 'pipe'] });
const replay07 = JSON.parse(readFileSync(new URL('conformance/vectors/aec-replay-07.v1.json', repo), 'utf8'));
const record07Bytes = readFileSync(new URL('conformance/vectors/aec-replay-07.v1.record.json', repo), 'utf8');
invariant(replay07.producer.version === '6.0.0' && replay07.record.algorithm_revision === 'EP-AEC-EVALUATOR-07-v1',
  'the -07 replay fixture is not a 6.0.0 EP-AEC-EVALUATOR-07-v1 record');
const evaluator07 = aec.createAuthorizationChainEvaluator({ requirement: replay07.inputs.requirement, nativeVerifiers: replay07.inputs.native_verifiers });
const stored07 = JSON.parse(record07Bytes);
const migrated = await evaluator07.replay(replay07.inputs.chain, stored07,
  { expectedAction: replay07.inputs.expected_action, verificationTime: replay07.inputs.verification_time });
invariant(migrated.comparison === 'UNSUPPORTED_REVISION' && migrated.matches === false
  && migrated.recorded_revision === 'EP-AEC-EVALUATOR-07-v1', `genuine -07 record replayed as ${migrated.comparison}`);
invariant(JSON.stringify(stored07) === JSON.stringify(JSON.parse(record07Bytes)), 'replay modified the stored -07 record');
invariant(migrated.result.satisfied === true && migrated.result.replay.algorithm_revision === 'EP-AEC-EVALUATOR-08-v1'
  && migrated.result.replay_digest !== replay07.record.replay_digest, 're-evaluation under -08 is not a new SATISFIED -08 record');

// ---- Optional: re-render ---------------------------------------------------
let renderNote = 'renders checked by checksum (pass --render to re-render)';
if (process.argv.includes('--render')) {
  const version = execFileSync('xml2rfc', ['--version'], { encoding: 'utf8' }).trim();
  invariant(version === 'xml2rfc 3.34.0', `--render needs xml2rfc 3.34.0, found ${version}`);
  const dir = mkdtempSync(join(tmpdir(), 'aec08-'));
  try {
    copyFileSync(new URL(`UPLOAD-THIS/${basename}.xml`, root), join(dir, `${basename}.xml`));
    execFileSync('xml2rfc', ['--text', '--html', `${basename}.xml`], { cwd: dir, stdio: 'ignore' });
    const rendered = readFileSync(join(dir, `${basename}.html`), 'utf8').replace(/[ \t]+$/gm, '');
    invariant(readFileSync(join(dir, `${basename}.txt`)).equals(txtBytes), 'TXT does not reproduce from the source');
    invariant(rendered === html, 'HTML does not reproduce from the source');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  renderNote = 'TXT and HTML reproduce byte for byte with xml2rfc 3.34.0';
}

console.log(`AEC -08: packet, checksums, ASCII and 72 columns, required -08 text, posted -07 integrity PASS; `
  + `corpus SHA-256 ${corpusSha.slice(0, 12)} (${pinnedNote}); the evaluator on this tree reproduces all `
  + `${vectors.length} corpus vectors, the ${rows.length} Table 1 rows, the parse identity example and the limit examples; the genuine 6.0.0 -07 replay record is UNSUPPORTED_REVISION and unmodified; ${renderNote}.`);
