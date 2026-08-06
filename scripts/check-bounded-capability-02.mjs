#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/NEXT-BOUNDED-CAPABILITY-02/', import.meta.url);
const basename = 'draft-schrock-ep-bounded-capability-receipts-02';

function invariant(condition, message) {
  if (!condition) throw new Error(`Bounded Capability -02 packet: ${message}`);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

invariant(
  JSON.stringify(readdirSync(new URL('UPLOAD-THIS/', root)).sort())
    === JSON.stringify([`${basename}.xml`]),
  'UPLOAD-THIS must contain exactly the -02 XML source',
);
invariant(
  JSON.stringify(readdirSync(new URL('RENDERS/', root)).sort())
    === JSON.stringify([`${basename}.html`, `${basename}.txt`]),
  'RENDERS must contain exactly the -02 HTML and TXT files',
);

const xml = readFileSync(new URL(`UPLOAD-THIS/${basename}.xml`, root), 'utf8');
const txt = readFileSync(new URL(`RENDERS/${basename}.txt`, root), 'utf8');
const html = readFileSync(new URL(`RENDERS/${basename}.html`, root), 'utf8');
const xmlText = xml.replace(/\s+/g, ' ');
const txtText = txt.replace(/\s+/g, ' ');

invariant(xml.includes(`docName="${basename}"`), 'docName must identify -02');
invariant(xml.includes(`value="${basename}"`), 'seriesInfo must identify -02');
invariant(xml.includes('category="exp"'), 'the candidate must remain Experimental');
invariant(xml.includes('submissionType="IETF"'), 'the inherited submission type changed');
invariant(xml.includes('<date year="2026" month="August" day="6"/>'), 'date must be 6 August 2026');
invariant(txt.includes(basename) && html.includes(basename), 'renderings must identify -02');
invariant(!txt.includes('draft-schrock-ep-bounded-capability-receipts-01'), 'TXT still identifies -01');

for (const required of [
  'relying-party-pinned atomic state-domain digest',
  'explicitly pinned single executor',
  'exact exercise-action digest',
  'native verifier',
  'local_store_only',
  'do not claim aggregate enforcement',
  'cannot by itself prove that two processes connect to the same physical database',
  '<name>Implementation Status</name>',
]) {
  invariant(xmlText.includes(required), `XML is missing required -02 text: ${required}`);
}
for (const required of [
  'relying-party-pinned atomic state-domain digest',
  'explicitly pinned single executor',
  'exact exercise-action digest',
  'native verifier',
  'local_store_only',
  'do not claim aggregate enforcement',
  'same physical database',
  'Implementation Status',
]) {
  invariant(txtText.includes(required), `TXT rendering is stale or missing: ${required}`);
}
for (const forbidden of [
  'reference implementation does not claim to implement those integrations',
  'proves that two processes connect to the same physical database',
]) {
  invariant(!xmlText.includes(forbidden), `forbidden claim survived: ${forbidden}`);
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

console.log('Bounded Capability -02: source, renders, implementation boundary, metadata, and checksums PASS.');
