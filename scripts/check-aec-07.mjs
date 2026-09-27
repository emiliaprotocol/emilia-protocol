#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Guards the staged draft-schrock-ep-authorization-evidence-chain-07 packet:
// VERIFIED (cryptographic and structural checks) and ACCEPTED (the relying
// party's pinned trust inputs) stay separate results everywhere the draft
// states or uses them, the -06 definitions that merged them are gone, the
// renders and checksums match the source, and the posted -06 is unchanged.

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
const flatTxt = txt.replace(/\s+/g, ' ');

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

console.log('AEC -07: VERIFIED and ACCEPTED separated in definitions, algorithm, replay and lifecycle; -06 wording removed; renders, checksums and posted -06 integrity PASS.');
