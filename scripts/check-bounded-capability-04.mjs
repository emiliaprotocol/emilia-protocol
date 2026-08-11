#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/NEXT-BOUNDED-CAPABILITY-04/', import.meta.url);
const basename = 'draft-schrock-ep-bounded-capability-receipts-04';

function invariant(condition, message) {
  if (!condition) throw new Error(`Bounded Capability -04 packet: ${message}`);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

invariant(
  JSON.stringify(readdirSync(new URL('UPLOAD-THIS/', root)).sort())
    === JSON.stringify([`${basename}.xml`]),
  'UPLOAD-THIS must contain exactly the -04 XML source',
);
invariant(
  JSON.stringify(readdirSync(new URL('RENDERS/', root)).sort())
    === JSON.stringify([`${basename}.html`, `${basename}.txt`]),
  'RENDERS must contain exactly the -04 HTML and TXT files',
);

const xml = readFileSync(new URL(`UPLOAD-THIS/${basename}.xml`, root), 'utf8');
const txt = readFileSync(new URL(`RENDERS/${basename}.txt`, root), 'utf8');
const html = readFileSync(new URL(`RENDERS/${basename}.html`, root), 'utf8');
const xmlText = xml.replace(/\s+/g, ' ');
const txtText = txt.replace(/\s+/g, ' ');

invariant(xml.includes(`docName="${basename}"`), 'docName must identify -04');
invariant(xml.includes(`value="${basename}"`), 'seriesInfo must identify -04');
invariant(xml.includes('category="exp"'), 'the candidate must remain Experimental');
invariant(xml.includes('submissionType="IETF"'), 'the inherited submission type changed');
invariant(xml.includes('<date year="2026" month="August" day="10"/>'), 'date must be 10 August 2026');
invariant(txt.includes(basename) && html.includes(basename), 'renderings must identify -04');

for (const required of [
  '<tt>revocation_mode</tt>',
  'Exactly <tt>direct</tt> or <tt>cascade</tt>',
  'complete authority-bearing ancestor lineage',
  'revocation transition and a descendant reservation',
  '<tt>capability_ancestor_status_unavailable</tt>',
  'quarantines legacy rows without an explicit mode',
  'reservation that commits first remains owned and reconcilable',
  'separate -03 revocation-inheritance model',
  'This non-strict subset relation is reflexive and transitive',
  '<tt>definition-derived</tt>',
  '<tt>mechanically-checkable</tt>',
  '<tt>asserted</tt>',
  'performed the complete enumeration itself or relied on a prior conformance run',
  'makes the record stale for this evaluation',
  'assigns no automatic trust rank',
  'solely to avoid reporting the relied-on mode',
  'every such mismatch yields a local-only result',
  'without repeating the enumeration',
  'mechanical-establishment provenance',
  'Sumit P. Ahuja',
  'local-only or chain-composable',
  'An asserted-transitive profile',
  '<name>Implementation Status</name>',
]) {
  invariant(xmlText.includes(required), `XML is missing required -04 text: ${required}`);
}
for (const required of [
  'revocation_mode',
  'direct or cascade',
  'complete authority-bearing ancestor lineage',
  'capability_ancestor_status_unavailable',
  'quarantines legacy rows without an explicit mode',
  'remains owned and reconcilable',
  'revocation-inheritance model',
  'non-strict subset relation is reflexive and transitive',
  'definition-derived',
  'mechanically-checkable',
  'performed the complete enumeration itself or relied on a prior conformance run',
  'makes the record stale for this evaluation',
  'assigns no automatic trust rank',
  'solely to avoid reporting the relied-on mode',
  'every such mismatch yields a local-only result',
  'without repeating the enumeration',
  'mechanical-establishment provenance',
  'Sumit P. Ahuja',
  'local-only or chain-composable',
  'asserted-transitive profile',
  'not yet emit per-component decidability records',
  'Implementation Status',
]) {
  invariant(txtText.includes(required), `TXT rendering is stale or missing: ${required}`);
}
for (const forbidden of [
  'does not yet implement the mandatory revocation_mode field',
  'atomic cascade-ancestor traversal, or the direct-versus-cascade',
  'No runtime conformance claim is made',
]) {
  invariant(!xmlText.includes(forbidden), `forbidden stale claim survived: ${forbidden}`);
  invariant(!txtText.includes(forbidden), `forbidden rendered claim survived: ${forbidden}`);
}

const manifest = readFileSync(new URL('SHA256SUMS.txt', root), 'utf8').trim().split('\n');
const expectedPaths = [
  `UPLOAD-THIS/${basename}.xml`,
  `RENDERS/${basename}.html`,
  `RENDERS/${basename}.txt`,
];
invariant(manifest.length === expectedPaths.length, 'checksum manifest must contain exactly three rows');
for (const [index, relative] of expectedPaths.entries()) {
  const match = /^([a-f0-9]{64})  (.+)$/.exec(manifest[index]);
  invariant(match !== null && match[2] === relative, `malformed checksum row for ${relative}`);
  if (match === null) continue;
  invariant(sha256(readFileSync(new URL(relative, root))) === match[1], `checksum mismatch for ${relative}`);
}

console.log('Bounded Capability -04: source, renders, profile-relation proof basis, metadata, and checksums PASS.');
