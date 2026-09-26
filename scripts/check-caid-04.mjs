#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize, computeCaid, parseCaid } from '../caid/impl/js/caid.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packet = path.join(root, 'standards/staged/NEXT-CAID-04');
const sourceRel = 'UPLOAD-THIS/draft-schrock-canonical-action-identifier-04.xml';
const textRel = 'RENDERS/draft-schrock-canonical-action-identifier-04.txt';
const htmlRel = 'RENDERS/draft-schrock-canonical-action-identifier-04.html';
const source = readFileSync(path.join(packet, sourceRel), 'utf8');
const text = readFileSync(path.join(packet, textRel), 'utf8');
const html = readFileSync(path.join(packet, htmlRel), 'utf8');
const registry = JSON.parse(readFileSync(path.join(root, 'caid/registry/action-types.json'), 'utf8'));
const enumSnapshot = JSON.parse(readFileSync(
  path.join(root, 'caid/registry/value-sets/iso-4217-alpha-3.2026-09-17.json'),
  'utf8',
));

const assert = (condition, message) => {
  if (!condition) throw new Error(`CAID-04 packet: ${message}`);
};

assert(source.includes('docName="draft-schrock-canonical-action-identifier-04"'), 'wrong source revision');
assert(source.includes('category="std"'), 'candidate is not Standards Track');
assert(!source.includes('submissionType='), 'individual draft must not claim an adopted stream');
for (const retainedReference of [
  'draft-schrock-ep-authorization-receipts-09',
  'draft-schrock-action-evidence-boundary-03',
  'draft-schrock-ep-authorization-evidence-chain-05',
  'draft-thallapelly-oasnt-caid-01',
]) assert(source.includes(retainedReference), `missing retained reference ${retainedReference}`);

assert(registry.meta.registry_version === 4, 'reference registry is not version 4');
assert(registry.meta.updated === '2026-09-24', 'reference registry has wrong update date');
assert(source.includes('<name>Enum Value-Set Resolution</name>'), 'enum resolution text missing');
assert(source.includes('<name>Changes since -03</name>'), 'revision history does not name -03');
assert(source.includes('<name>Changes since -02</name>'), 'revision history lost the -02 entry');
assert(source.includes('Historical v3'), 'v3-to-v4 migration consequence missing');
// Review revision: the enum forms, trimming set, presence rule, unpaired
// surrogate refusal, and the corrective pin exception are normative text.
for (const [needle, what] of [
  ['trimmed of leading and trailing U+0020 SPACE characters only', 'inline trimming rule'],
  ['is present and malformed, not absent', 'null-member presence rule'],
  ['A supplied snapshot never replaces an embedded', 'embedded external values rule'],
  ['member of the action object itself', 'own-member presence rule'],
  ['else unsupported_value', 'unpaired surrogate refusal'],
  ['MUST NOT replace an unpaired surrogate escape', 'raw parser surrogate rule'],
  ['One narrow correction is permitted.', 'corrective pin exception'],
  ['Eleven active types in the reference registry', 'blocked-type migration consequence'],
]) assert(source.includes(needle), `missing ${what}`);
assert(
  Array.isArray(registry.unresolved_external_enums)
    && new Set(registry.unresolved_external_enums.filter((item) => item.required).map((item) => item.action_type)).size === 11,
  'registry does not list the eleven blocked types',
);

// Revision -04: amount-string is ABNF, not prose. The draft, its TXT render,
// and DESIGN.md carry the same three rules, and the JavaScript reference
// accepts exactly the strings they describe. The shared corpus holds the
// Python and Go ports to the same refusals.
const flat = (value) => value.replace(/\s+/g, ' ');
const amountAbnf = [
  'amount-string = [ "-" ] int-part [ "." frac-part ]',
  'int-part      = "0" / ( %x31-39 *DIGIT )  ; no leading zero',
  'frac-part     = 1*DIGIT',
];
const design = readFileSync(path.join(root, 'caid/DESIGN.md'), 'utf8');
assert(source.includes(amountAbnf.join('\n')), 'amount-string ABNF missing from source');
assert(text.includes(amountAbnf.map((line) => `      ${line}`).join('\n')), 'amount-string ABNF missing from TXT render');
assert(design.includes(amountAbnf.map((line) => `    ${line}`).join('\n')), 'DESIGN.md amount-string ABNF differs from the draft');
assert(!flat(source).includes('one or more digits, and an optional "."'), 'loose -03 amount-string prose still present');
assert(!flat(source).includes('MAY be refined to invalid_amount'), 'amount refusal reason is still optional');
for (const [needle, what] of [
  ['reported as invalid_amount:&lt;name&gt;; a non-string value there remains mistyped_field:&lt;name&gt;', 'amount refusal reason rule'],
  ['Notes guide issuers and never change how a field is validated.', 'notes-are-not-validation rule'],
  ['The -03 prose admitted "01.5"', 'leading-zero change record'],
]) assert(flat(source).includes(needle), `missing ${what}`);

// Written from the three rules above, independently of any port's regex.
const matchesAmountAbnf = (value) => {
  const at = (index) => value[index] ?? '';
  const isDigit = (char) => char >= '0' && char <= '9';
  let index = at(0) === '-' ? 1 : 0;
  if (at(index) === '0') index += 1;
  else if (at(index) >= '1' && at(index) <= '9') {
    index += 1;
    while (isDigit(at(index))) index += 1;
  } else return false;
  if (at(index) === '.') {
    const fraction = index + 1;
    index = fraction;
    while (isDigit(at(index))) index += 1;
    if (index === fraction) return false;
  }
  return index === value.length;
};
const amountDefinition = {
  action_type: 'test.amount.1',
  status: 'active',
  required_fields: [{ name: 'amount', type: 'amount-string' }],
};
const amountVerdict = (amount) => computeCaid(
  { action_type: 'test.amount.1', amount },
  { suite: 'jcs-sha256', definitions: [amountDefinition] },
);
const draftMatches = ['0', '0.50', '-0', '-0.50'];
const draftRefusals = ['01.5', '00', '+1', '1e3', '.5', '1.', '1,000'];
for (const example of [...draftMatches, ...draftRefusals]) {
  assert(flat(source).includes(`"${example}"`), `draft does not cite amount example ${example}`);
}
const alphabet = ['0', '1', '9', '-', '.', '+', 'e', ' ', '\n'];
let candidates = [''];
const amountStrings = [...draftMatches, ...draftRefusals, ''];
for (let length = 1; length <= 4; length += 1) {
  candidates = candidates.flatMap((prefix) => alphabet.map((char) => prefix + char));
  amountStrings.push(...candidates);
}
for (const amount of amountStrings) {
  const expected = matchesAmountAbnf(amount);
  const actual = amountVerdict(amount);
  const ok = expected
    ? typeof actual.caid === 'string'
    : JSON.stringify(actual.refusals) === JSON.stringify(['invalid_amount:amount']);
  assert(ok, `JavaScript amount-string verdict for ${JSON.stringify(amount)} differs from the ABNF`);
}
for (const example of draftMatches) assert(matchesAmountAbnf(example), `draft example ${example} does not match the ABNF`);
for (const example of draftRefusals) assert(!matchesAmountAbnf(example), `draft counterexample ${example} matches the ABNF`);
assert(
  JSON.stringify(amountVerdict(250).refusals) === JSON.stringify(['mistyped_field:amount']),
  'a non-string amount is not mistyped_field',
);

// Revision -04: identifier parsing. The suite ABNF and the parsing rules are
// unchanged since -00; -04 defines an unknown suite as one outside the suite
// registry and lists the digest's permitted final characters. A parser model
// written from those rules, independently of any port, must agree with the
// JavaScript reference. The shared corpus holds Python and Go to the same
// refusals.
const suiteRegistry = JSON.parse(readFileSync(path.join(root, 'caid/registry/suites.json'), 'utf8'));
const suiteAbnf = 'suite         = lower-char *( lower-char / DIGIT / "-" )';
assert(source.includes(suiteAbnf), 'suite ABNF missing from source');
assert(text.includes(`   ${suiteAbnf}\n`), 'suite ABNF missing from TXT render');
assert(design.includes('`suite = lower-char *( lower-char / DIGIT / "-" )`'), 'DESIGN.md suite grammar differs from the draft');
const isLowerChar = (char) => char >= 'a' && char <= 'z';
const matchesSuiteAbnf = (value) => value.length > 0
  && isLowerChar(value[0])
  && [...value.slice(1)].every((char) => isLowerChar(char) || (char >= '0' && char <= '9') || char === '-');
const registeredSuites = new Map(suiteRegistry.suites.map((entry) => {
  assert(matchesSuiteAbnf(entry.suite), `registered suite ${entry.suite} does not match the suite ABNF`);
  assert(entry.digest?.name === 'SHA-256', `registered suite ${entry.suite} does not use SHA-256`);
  return [entry.suite, 32];
}));
assert(registeredSuites.size === 2 && registeredSuites.has('jcs-sha256') && registeredSuites.has('cbor-sha256'),
  'suite registry is not jcs-sha256 and cbor-sha256');
for (const [needle, what] of [
  ['MUST treat an unknown suite, one that is not in the suite registry', 'unknown-suite definition'],
  ['is not unknown to its parser', 'registered-but-unimplemented rule'],
  ['else unknown_suite if the verifier does not implement that registered suite', 'verification unknown_suite reason'],
  ['a registered suite that the implementation implements, else unknown_suite', 'computation unknown_suite rule'],
  ['An unknown suite is now defined as one not in the suite registry.', 'unknown-suite change record'],
  ['or whose final character encodes nonzero unused bits', 'unused-bit parsing rule'],
]) assert(flat(source).includes(needle), `missing ${what}`);
const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const encodedLength = (octets) => Math.ceil((octets * 8) / 6);
const finalMask = (octets) => (1 << (encodedLength(octets) * 6 - octets * 8)) - 1;
const permittedFinals = [...B64URL].filter((char) => (B64URL.indexOf(char) & finalMask(32)) === 0);
const quotedFinals = permittedFinals.map((char) => `"${char}"`);
const finalsProse = `${quotedFinals.slice(0, -1).join(', ')}, or ${quotedFinals.at(-1)}`;
assert(permittedFinals.length === 16, 'a 32-octet digest does not leave two unused bits');
assert(flat(source).includes(finalsProse), 'draft does not list the permitted final digest characters');
assert(flat(text).includes(finalsProse), 'TXT render does not list the permitted final digest characters');
assert(design.includes(`\`${permittedFinals.join(' ')}\``), 'DESIGN.md final digest characters differ from the draft');
// Written from the ABNF, the registry, and the digest rules above.
const modelParse = (suite, digest) => {
  if (!matchesSuiteAbnf(suite) || !registeredSuites.has(suite)) return false;
  const octets = registeredSuites.get(suite);
  if (digest.length !== encodedLength(octets) || ![...digest].every((char) => B64URL.includes(char))) return false;
  return (B64URL.indexOf(digest.at(-1)) & finalMask(octets)) === 0;
};
const validDigest = createHash('sha256').update('CAID-04 parse check', 'utf8').digest('base64url');
const suiteAlphabet = ['a', 'z', '0', '9', '-', 'A', '_'];
const suiteNames = [...registeredSuites.keys(), 'jcs-sha512', 'JCS-SHA256', 'jcs-sha256-', 'jcs--sha256', 'x--y', 'x-', '1x', ''];
let suiteCandidates = [''];
for (let length = 1; length <= 4; length += 1) {
  suiteCandidates = suiteCandidates.flatMap((prefix) => suiteAlphabet.map((char) => prefix + char));
  suiteNames.push(...suiteCandidates);
}
const digestNames = [validDigest, validDigest.slice(0, -1), `${validDigest}A`, `${validDigest.slice(0, -1)}=`,
  ...[...B64URL, '=', '.', '+', '/', ' ', '\n'].map((char) => validDigest.slice(0, -1) + char)];
const parseVerdict = (suite, digest) => parseCaid(`caid:1:payment.release.1:${suite}:${digest}`).ok;
let parseCases = 0;
for (const suite of suiteNames) {
  const digests = registeredSuites.has(suite) || suite === 'jcs-sha512' ? digestNames : [validDigest];
  for (const digest of digests) {
    parseCases += 1;
    assert(parseVerdict(suite, digest) === modelParse(suite, digest),
      `JavaScript parse verdict for suite ${JSON.stringify(suite)} and digest ${JSON.stringify(digest)} differs from the draft`);
  }
}
assert(parseCases > 2_900, 'parse comparison covered too few identifiers');

const canonicalValues = canonicalize(enumSnapshot.values);
assert(canonicalValues.ok, 'ISO 4217 snapshot values are not JCS-compatible');
const snapshotHash = 'sha256:' + createHash('sha256')
  .update(/** @type {{ok: true, canonical: string}} */ (canonicalValues).canonical, 'utf8')
  .digest('hex');
assert(snapshotHash === enumSnapshot.values_sha256, 'ISO 4217 values digest mismatch');
assert(new Set(enumSnapshot.values).size === 178, 'ISO 4217 snapshot does not contain 178 unique codes');
assert(enumSnapshot.values.includes('USD') && enumSnapshot.values.includes('XAD'), 'expected valid currency codes absent');

const toolCall = registry.types.find((entry) => entry.action_type === 'tool.call.1');
assert(toolCall?.required_fields?.[0]?.name === 'target', 'tool.call.1 does not require target');
assert(toolCall?.required_fields?.[1]?.name === 'tool', 'tool.call.1 does not require tool');
assert(toolCall?.required_fields?.[2]?.name === 'args', 'tool.call.1 does not require args');
assert(!toolCall.required_fields.some((field) => field.name === 'arguments'), 'tool.call.1 admits divergent arguments member');

const paymentRelease = registry.types.find((entry) => entry.action_type === 'payment.release.1');
const currencyField = paymentRelease?.required_fields?.find((field) => field.name === 'currency');
assert(currencyField?.values_ref === enumSnapshot.values_ref, 'currency values_ref is not pinned snapshot reference');
assert(currencyField?.values_snapshot === enumSnapshot.values_snapshot, 'currency snapshot label mismatch');
assert(currencyField?.values_sha256 === enumSnapshot.values_sha256, 'currency snapshot digest mismatch');
const payment = {
  action_type: 'payment.release.1',
  amount: '250.00',
  currency: 'USD',
  beneficiary_account: 'sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
  payment_instruction_id: 'pi-2026-000117',
};
const validCurrency = computeCaid(payment, {
  suite: 'jcs-sha256',
  definitions: registry.types,
  enumSnapshots: [enumSnapshot],
});
assert(typeof validCurrency.caid === 'string', 'valid pinned currency did not compute');
const invalidCurrency = computeCaid({ ...payment, currency: 'NOT-A-CURRENCY' }, {
  suite: 'jcs-sha256',
  definitions: registry.types,
  enumSnapshots: [enumSnapshot],
});
assert(
  JSON.stringify(invalidCurrency.refusals) === JSON.stringify(['mistyped_field:currency']),
  'NOT-A-CURRENCY did not fail closed',
);

const example = {
  action_type: 'tool.call.1',
  target: 'https://payments.example',
  tool: 'payment.release',
  args: { amount_usd: 4000, beneficiary: 'vendor@example.com', memo: 'invoice 7781' },
};
const computed = computeCaid(example, { suite: 'jcs-sha256', definitions: registry.types });
const expected = 'caid:1:tool.call.1:jcs-sha256:FdawgFwgN5tAtiZa-SCkVDrV3dS9w1yeXVQaDaZLQQQ';
assert(computed.caid === expected, 'tool.call.1 example does not reproduce the draft CAID');
const shadowed = computeCaid(
  { ...example, target: 'https://shadow.example' },
  { suite: 'jcs-sha256', definitions: registry.types },
);
assert(shadowed.caid !== expected, 'tool.call.1 target does not discriminate a shadow provider');
const withoutWhitespace = (value) => value.replace(/\s+/g, '');
assert(withoutWhitespace(source).includes(expected), 'example CAID missing from source');
assert(withoutWhitespace(text).includes(expected), 'example CAID missing from TXT render');
assert(html.includes('FdawgFwgN5tAtiZa-SCkVDrV3dS9w1ye') && html.includes('XVQaDaZLQQQ'), 'example CAID missing from HTML render');
assert(text.includes('Intended status: Standards Track'), 'TXT render has the wrong intended status');

const sums = readFileSync(path.join(packet, 'SHA256SUMS.txt'), 'utf8').trim().split('\n');
const expectedPaths = new Set([sourceRel, textRel, htmlRel]);
for (const line of sums) {
  const match = line.match(/^([0-9a-f]{64})  (.+)$/);
  assert(match, `malformed checksum line ${line}`);
  if (!match) continue;
  const [, expectedHash, relative] = match;
  assert(expectedPaths.delete(relative), `unexpected or duplicate checksum path ${relative}`);
  const actual = createHash('sha256').update(readFileSync(path.join(packet, relative))).digest('hex');
  assert(actual === expectedHash, `checksum mismatch for ${relative}`);
}
assert(expectedPaths.size === 0, `missing checksum path ${[...expectedPaths].join(', ')}`);

console.log(`CAID-04: amount-string ABNF, identifier parsing (${parseCases} identifiers), enum snapshot, registry v4, draft source, example, renders, and checksums PASS.`);
