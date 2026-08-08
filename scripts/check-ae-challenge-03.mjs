#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/NEXT-AE-CHALLENGE-03/', import.meta.url);
const basename = 'draft-schrock-ae-challenge-03';

function invariant(condition, message) {
  if (!condition) throw new Error(`AE Challenge -03 packet: ${message}`);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

invariant(
  JSON.stringify(readdirSync(new URL('UPLOAD-THIS/', root)).sort())
    === JSON.stringify([`${basename}.xml`]),
  'UPLOAD-THIS must contain exactly the -03 XML source',
);
invariant(
  JSON.stringify(readdirSync(new URL('RENDERS/', root)).sort())
    === JSON.stringify([`${basename}.html`, `${basename}.txt`]),
  'RENDERS must contain exactly the -03 HTML and TXT files',
);

const xml = readFileSync(new URL(`UPLOAD-THIS/${basename}.xml`, root), 'utf8');
const txt = readFileSync(new URL(`RENDERS/${basename}.txt`, root), 'utf8');
const flatXml = xml.replace(/\s+/g, ' ');
const flatTxt = txt.replace(/\s+/g, ' ');

for (const required of [
  `docName="${basename}"`,
  `value="${basename}"`,
  'Transport-Neutral Core Data Model',
  'HTTP Binding',
  '403 Forbidden',
  'application/problem+json',
  'Informative DMSC Gateway Profile',
  'does not authorize the action or transfer admission ownership',
  'does not prevent Gateway A and Gateway B',
  'https://iana.org/assignments/http-problem-types#ae-required',
  'Deployment Scenarios and Gap Analysis for AI Agent Gateway',
  'The Action Evidence Boundary for Consequential Agent Effects',
  'HTTP Problem Types',
  'Specification Required',
  'withdraws the earlier request',
]) {
  invariant(flatXml.includes(required), `XML is missing required -03 text: ${required}`);
}
for (const required of [
  'Transport-Neutral Core Data Model',
  'HTTP Binding',
  '403 Forbidden',
  'application/problem+json',
  'Informative DMSC Gateway Profile',
  'transfer admission ownership',
  'double-admission',
  'Specification Required',
]) {
  invariant(flatTxt.includes(required), `TXT rendering is stale or missing: ${required}`);
}
for (const forbidden of [
  'application/authorization-evidence-challenge+json in the standards tree',
  'with status 428',
  'EP-APPROVAL-v1',
  '<authorization-evidence-required problem type URI>',
  'AI Agent Gateway Scenarios and Gap Analysis',
  'Action Evidence Boundary for High-Risk Agent Actions',
]) {
  invariant(!flatXml.includes(forbidden), `retired -02 protocol text survived: ${forbidden}`);
  invariant(!flatTxt.includes(forbidden), `retired -02 rendered text survived: ${forbidden}`);
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
  if (match !== null) {
    invariant(sha256(readFileSync(new URL(relative, root))) === match[1], `checksum mismatch for ${relative}`);
  }
}

console.log('AE Challenge -03: transport separation, HTTP and DMSC boundaries, renders, and checksums PASS.');
