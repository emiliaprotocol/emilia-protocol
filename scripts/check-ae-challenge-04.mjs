#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/NEXT-AE-CHALLENGE-04/', import.meta.url);
const basename = 'draft-schrock-ae-challenge-04';
const posted03 = new URL('../standards/posted/draft-schrock-ae-challenge-03.xml', import.meta.url);
const posted03Sha256 = '3e6c1fbefa4c1c87731083b72e185dd9a80528ed9e23a38881116c4b930d3d99';

function invariant(condition, message) {
  if (!condition) throw new Error(`AE Challenge -04 packet: ${message}`);
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
const flatXml = xml.replace(/\s+/g, ' ');
const flatTxt = txt.replace(/\s+/g, ' ');

for (const required of [
  `docName="${basename}"`,
  `value="${basename}"`,
  '<date year="2026" month="August" day="9"/>',
  'Transport-Neutral Core Data Model',
  'HTTP Binding',
  '403 Forbidden',
  'application/problem+json',
  'Informative DMSC Gateway Profile',
  'does not authorize the action or transfer admission ownership',
  'does not prevent Gateway A and Gateway B',
  'retry_timing',
  'not_before',
  'jitter_sec',
  'Retry-After',
  'recipient-specific or challenge-specific retry schedules',
  'MUST NOT be issued solely to signal overload',
  'structured refusal or error payload',
  'does not preserve one action binding across hops',
  'Capability discovery',
  'determine sufficiency using its authenticated local policy',
  'Sumit P. Ahuja',
  'Guigui Wang',
  'Changes since -03',
  'https://iana.org/assignments/http-problem-types#ae-required',
  'Deployment Scenarios and Gap Analysis for AI Agent Gateway',
  'The Action Evidence Boundary for Consequential Agent Effects',
  'HTTP Problem Types',
  'Specification Required',
  'withdraws the earlier request',
]) {
  invariant(flatXml.includes(required), `XML is missing required -04 text: ${required}`);
}
for (const required of [
  'Expires: 10 February 2027',
  'Transport-Neutral Core Data Model',
  'HTTP Binding',
  '403 Forbidden',
  'application/problem+json',
  'Informative DMSC Gateway Profile',
  'transfer admission ownership',
  'double-admission',
  'retry_timing',
  'Retry-After',
  'retry synchronization and load amplification',
  'structured refusal or error payload',
  'does not preserve one action binding across hops',
  'Capability discovery',
  'Sumit P. Ahuja',
  'Guigui Wang',
  'Changes since -03',
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
  'docName="draft-schrock-ae-challenge-03"',
  '<name>Changes since -02</name>',
  '2026-08-08T',
]) {
  invariant(!flatXml.includes(forbidden), `retired protocol or revision text survived: ${forbidden}`);
  invariant(!flatTxt.includes(forbidden), `retired rendered text survived: ${forbidden}`);
}

invariant(
  sha256(readFileSync(posted03)) === posted03Sha256,
  'immutable posted -03 XML changed',
);

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

console.log('AE Challenge -04: retry pacing, per-hop rebinding, discovery separation, carrier semantics, renders, checksums, and immutable -03 PASS.');
