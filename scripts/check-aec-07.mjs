#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Guards the staged draft-schrock-ep-authorization-evidence-chain-07 packet:
// VERIFIED (cryptographic and structural checks) and ACCEPTED (the relying
// party's pinned trust inputs) stay separate results everywhere the draft
// states or uses them, the -06 definitions that merged them are gone, the
// renders and checksums match the source, the posted -06 is unchanged, and the
// evaluator that Sections 10 and 21 describe is the one on the same tree.

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/NEXT-AEC-07/', import.meta.url);
const basename = 'draft-schrock-ep-authorization-evidence-chain-07';
const posted06 = new URL('../standards/posted/draft-schrock-ep-authorization-evidence-chain-06.xml', import.meta.url);
const posted06Sha256 = '69fef7053014c053e274f6396afdc9ea77943b6538876c8e49707d51796c1585';

function invariant(condition, message) {
  if (!condition) throw new Error(`AEC -07 packet: ${message}`);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

invariant(
  JSON.stringify(readdirSync(new URL('UPLOAD-THIS/', root)).sort())
    === JSON.stringify([`${basename}.xml`]),
  'UPLOAD-THIS must contain exactly the -07 XML source',
);
invariant(
  JSON.stringify(readdirSync(new URL('RENDERS/', root)).sort())
    === JSON.stringify([`${basename}.html`, `${basename}.txt`]),
  'RENDERS must contain exactly the -07 HTML and TXT files',
);

const xmlBytes = readFileSync(new URL(`UPLOAD-THIS/${basename}.xml`, root));
const txtBytes = readFileSync(new URL(`RENDERS/${basename}.txt`, root));
const xml = xmlBytes.toString('utf8');
const txt = txtBytes.toString('utf8');
const flatXml = xml.replace(/\s+/g, ' ');
// Page footers and running headers can fall inside a sentence; drop them
// before flattening so required text is matched as a reader sees it.
const flatTxt = txt
  .split('\n')
  .filter((line) => !/\[Page \d+\]$/.test(line) && !/^Internet-Draft {2,}.* \d{4}$/.test(line))
  .join('\n')
  .replace(/\f/g, '')
  .replace(/\s+/g, ' ');

invariant(/^[\x09\x0a\x0d\x20-\x7e]*$/.test(xml), 'XML source must be printable ASCII');
invariant(/^[\x09\x0a\x0c\x0d\x20-\x7e]*$/.test(txt), 'TXT render must be printable ASCII');
invariant(txt.split('\n').every((line) => line.length <= 72), 'TXT render has a line over 72 columns');

for (const required of [
  `docName="${basename}"`,
  `value="${basename}"`,
  '<date year="2026" month="September" day="27"/>',
  '<dt>ACCEPTED</dt>',
  '<dt>UNSATISFIED</dt>',
  '<name>Changes in -07</name>',
  'draft-schrock-canonical-action-identifier-03',
  'draft-schrock-ep-authorization-receipts-13',
  'draft-schrock-ep-quorum-04',
  'draft-schrock-action-evidence-boundary-07',
]) invariant(flatXml.includes(required), `XML is missing required -07 text: ${required}`);

// Rendered text is what readers see; check the separation there.
for (const required of [
  'VERIFIED The native verifier\'s cryptographic and structural checks passed',
  'VERIFIED says nothing about whether the relying party trusts that key, issuer, or policy',
  'ACCEPTED A VERIFIED artifact also meets the relying party\'s pinned trust inputs',
  'that holds or resolves the same verification key can reproduce VERIFIED for the same bytes',
  'Resolution uses only the mapping from a key reference to key bytes',
  'never as FAILED, and the component is ineligible',
  'can reach different VERIFIED results for the same bytes',
  'An ACCEPTED artifact bound to a different action is ineligible because it is not MATCH',
  'with the same verification keys under different trust inputs can reproduce the VERIFIED results',
  'evidence and the same verification keys re-derive VERIFIED',
  'FAILED does not distinguish a forgery from an intact artifact',
  'Whether the bundle\'s action is the exact expected action is established by MATCH',
  'it is FAILED only when the checks ran and did not pass',
  '"algorithm_revision"',
  'MATCH A VERIFIED and ACCEPTED artifact\'s',
  'The pinned trust inputs decide ACCEPTED.',
  'The native verifier MUST report the two results separately.',
  'MUST NOT report ACCEPTED for an artifact that is not VERIFIED',
  'MUST NOT report VERIFIED for an artifact whose integrity it did not check',
  'the verifier reports the artifact as not VERIFIED',
  'Resolving a key does not make the artifact ACCEPTED',
  'Only after VERIFIED and ACCEPTED, establish material-action MATCH',
  'Each normalized fact MUST carry the VERIFIED and ACCEPTED results as separate fields',
  'native_verification is VERIFIED, FAILED, or NOT_EVALUATED',
  'acceptance is NOT_EVALUATED whenever native_verification is not VERIFIED',
  'native VERIFIED -> relying-party ACCEPTED -> material-action MATCH',
  'AEC MUST NOT collapse ACCEPTED into VERIFIED',
  'Verification and acceptance.',
  'Changes in -07',
  'Native verification is not sufficient for composition.',
  'Except where a native procedure checks trust inputs and cryptography together and cannot attribute a failure',
  'With the same exception, a party with different trust inputs',
  'sets it to the string EP-AEC-EVALUATOR-07-v1',
  // Section 11 keeps the -06 requirement level, now stated per result.
  'Its native verifier MUST report VERIFIED only when the bundle\'s closed structure',
  'and MUST report ACCEPTED only when the relying-party-selected policy',
  'The ep-receipt built-in MUST report VERIFIED only when',
  'its log checkpoint signature verifies under the relying party\'s pinned log key',
  'without a pinned log key VERIFIED cannot be evaluated',
  'The built-in MUST report ACCEPTED only for a VERIFIED Trust Receipt',
  'The ep-quorum built-in MUST report VERIFIED only when the quorum structure is intact',
  'every member signoff verifies under the public key that member carries',
  'The built-in MUST report ACCEPTED only when the presented quorum policy equals',
  // Section 12 assigns the referenced capability and its issuance
  // authorization to both results instead of one combined validation.
  'issuance authorization are each VERIFIED and ACCEPTED under the relying party\'s pins for their own roles',
  'not ACCEPTED unless all three are ACCEPTED',
  // Remaining -06 vocabulary replaced: mapping input, lifecycle outcome
  // names, and the acknowledgment.
  'projects the VERIFIED and ACCEPTED native payload',
  'FAILED and INDETERMINATE in the last line are execution outcomes',
  'separation among native verification, relying-party acceptance',
]) invariant(flatTxt.includes(required), `TXT rendering is stale or missing: ${required}`);

// The -06 wording that folded pinned trust inputs into VERIFIED, and the
// earlier -07 wording that let VERIFIED travel without the same key or put the
// exact action inside ACCEPTED.
for (const forbidden of [
  'A party with different trust inputs can reproduce VERIFIED',
  'If no key can be resolved, the artifact is not VERIFIED.',
  'reports ACCEPTED only when the exact expected action',
  'lets a later reader who holds the evidence re-derive VERIFIED',
  'The native verifier accepted an artifact under the selected native profile',
  'format-specific semantics under pinned trust inputs',
  'A component reaches VERIFIED only when its native verifier succeeds.',
  'native validity and a machine-readable failure reason',
  'Only after native VERIFIED, establish',
  'In both arrangements, VERIFIED precedes MATCH, and both precede SATISFIED',
  'docName="draft-schrock-ep-authorization-evidence-chain-06"',
  // Earlier -07 wording: Section 11 without BCP 14 keywords, the log key as
  // an ACCEPTED pin, and the undefined "validity" terms in Section 1.
  'Its native verifier reports VERIFIED when',
  'built-in reports ACCEPTED only',
  'policy hash, log key, maximum evidence age',
  'Native validity is not sufficient for composition',
  // -06 wording that survived into earlier -07 text: Section 12's combined
  // validation, the mapping input, the splicing example and the
  // acknowledgment.
  'the native verifier validates the referenced capability',
  'projects the verified native payload',
  'individually valid artifacts',
  'separation among native validity',
]) {
  invariant(!flatXml.includes(forbidden), `-06 text survived in the XML: ${forbidden}`);
  invariant(!flatTxt.includes(forbidden), `-06 text survived in the TXT render: ${forbidden}`);
}
invariant(!/[–—]/.test(xml) && !/[–—]/.test(txt), 'no en or em dash may appear');

invariant(sha256(readFileSync(posted06)) === posted06Sha256, 'immutable posted -06 XML changed');

const manifest = readFileSync(new URL('SHA256SUMS.txt', root), 'utf8').trim().split('\n');
const expectedPaths = [
  `UPLOAD-THIS/${basename}.xml`,
  `RENDERS/${basename}.html`,
  `RENDERS/${basename}.txt`,
];
invariant(manifest.length === expectedPaths.length, 'checksum manifest must contain exactly three rows');
for (const [index, relative] of expectedPaths.entries()) {
  const match = /^([a-f0-9]{64}) {2}(.+)$/.exec(manifest[index]);
  invariant(match !== null && match[2] === relative, `malformed checksum row for ${relative}`);
  if (match !== null) {
    invariant(sha256(readFileSync(new URL(relative, root))) === match[1], `checksum mismatch for ${relative}`);
  }
}

// Sections 10 and 21 describe the evaluator revision that accompanies -07.
// Those sentences must be true of the code on this tree, so the packet cannot
// land on main ahead of that evaluator (README, Hold 1). This runs last so a
// text or checksum failure is reported first.
const evaluatorSource = readFileSync(new URL('../packages/verify/src/evidence-chain.ts', import.meta.url), 'utf8');
const evaluatorRevision = /export const AEC_EVALUATOR_REVISION = '([^']+)';/.exec(evaluatorSource)?.[1] ?? 'no revision';
const absent = [
  // Trust Receipt integrity checked under the relying party's log key.
  'function receiptIntegrity(',
  'approverKeys: resolved, logPublicKey: profile.log_public_key',
  // An unresolvable key reference is NOT_EVALUATED, never FAILED.
  "reason: 'key_unresolved'",
  "'native_key_unresolved'",
  // Separate per-fact results.
  "fact.native_verification = 'VERIFIED'",
  "native_verification: 'NOT_EVALUATED', acceptance: 'NOT_EVALUATED'",
].filter((marker) => !evaluatorSource.includes(marker));
invariant(
  evaluatorRevision === 'EP-AEC-EVALUATOR-07-v1' && absent.length === 0,
  'text, renders, checksums and posted -06 integrity pass, but Sections 10 and 21 describe the '
    + 'EP-AEC-EVALUATOR-07-v1 evaluator and packages/verify/src/evidence-chain.ts on this tree emits '
    + `${evaluatorRevision}${absent.length ? ` and lacks ${absent.join(', ')}` : ''}. `
    + 'Merge feat/verify-aec-07-evaluator first, or revise Sections 10 and 21 (README, Hold 1).',
);

console.log('AEC -07: VERIFIED and ACCEPTED separated in definitions, algorithm, replay, built-ins and lifecycle; -06 wording removed; renders, checksums, posted -06 integrity and the Section 21 evaluator on this tree PASS.');
