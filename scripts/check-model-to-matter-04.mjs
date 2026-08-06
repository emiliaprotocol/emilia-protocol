#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/NEXT-MODEL-TO-MATTER-04/', import.meta.url);
const basename = 'draft-schrock-model-to-matter-04';

function invariant(condition, message) {
  if (!condition) throw new Error(`Model-to-Matter -04 packet: ${message}`);
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
invariant(xml.includes('submissionType="IETF"'), 'the -03 submission type must remain unchanged');
invariant(xml.includes('<date year="2026" month="August" day="6"/>'), 'date must be 6 August 2026');
invariant(txt.includes(basename) && html.includes(basename), 'renderings must identify -04');
invariant(!txt.includes('draft-schrock-model-to-matter-03'), 'TXT still identifies -03');

for (const required of [
  'physical_state_attestation',
  'digest of the required precondition set',
  'maximum measurement age',
  'maximum validity duration',
  'A second key under the executor',
  'control is not independent',
  'a new measurement is required',
  'does not establish physical truth',
  'correct sensor placement',
  'MUST NOT represent a cleared action as evidence',
  'not yet implemented by the Model-to-Matter reference clearance path',
  '<name>Changes since -03</name>',
]) {
  invariant(xmlText.includes(required), `XML is missing required -04 text: ${required}`);
}
for (const required of [
  'physical_state_attestation',
  'maximum measurement age',
  'maximum validity duration',
  'control is not independent',
  'does not establish physical truth',
  'MUST NOT represent a cleared action as evidence',
  'not yet implemented by the Model-to-Matter reference clearance path',
  'Changes since -03',
]) {
  invariant(txtText.includes(required), `TXT rendering is stale or missing: ${required}`);
}
for (const forbidden of [
  'the reactor is clean',
  'physical preconditions are not met',
  'guarantee of safety',
  '<name>Changes since -02</name>',
  'seven signed evidence adapters',
]) {
  invariant(!xmlText.toLowerCase().includes(forbidden.toLowerCase()), `forbidden claim survived: ${forbidden}`);
  invariant(!txtText.toLowerCase().includes(forbidden.toLowerCase()), `forbidden rendered claim survived: ${forbidden}`);
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

console.log('Model-to-Matter -04: source, renders, doctrine boundary, metadata, and checksums PASS.');
