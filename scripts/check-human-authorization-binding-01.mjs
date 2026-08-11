#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/NEXT-HUMAN-AUTHORIZATION-BINDING-01/', import.meta.url);
const basename = 'draft-schrock-human-authorization-binding-01';
const posted00 = new URL('../standards/posted/draft-schrock-human-authorization-binding-00.xml', import.meta.url);
const posted00Sha256 = '28574a050312837c96189561b2f0776da6cfdb1fe2720dab575fcb99a6811a0e';

function invariant(condition, message) {
  if (!condition) throw new Error(`Human Authorization Binding -01: ${message}`);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

invariant(
  JSON.stringify(readdirSync(new URL('UPLOAD-THIS/', root)).sort())
    === JSON.stringify([`${basename}.xml`]),
  'UPLOAD-THIS must contain exactly the -01 XML source',
);
invariant(
  JSON.stringify(readdirSync(new URL('RENDERS/', root)).sort())
    === JSON.stringify([`${basename}.html`, `${basename}.txt`]),
  'RENDERS must contain exactly the -01 HTML and TXT files',
);

const xml = readFileSync(new URL(`UPLOAD-THIS/${basename}.xml`, root), 'utf8');
const txt = readFileSync(new URL(`RENDERS/${basename}.txt`, root), 'utf8');
const flatXml = xml.replace(/\s+/g, ' ');
const flatTxt = txt.replace(/\s+/g, ' ');

for (const required of [
  `docName="${basename}"`,
  `value="${basename}"`,
  '<date year="2026" month="August" day="11"/>',
  'Seven requirements hold for every host',
  'B6: Authoritative approver attribution',
  'B7: Role non-equivalence',
  'A self-asserted name, self-issued key, workload identifier, or OAuth subject claim MUST NOT establish named-human identity by itself',
  'Terminal Accountability Is Not Per-Action Human Authorization',
  'draft-schrock-ep-authorization-receipts-11',
  'draft-schrock-ep-quorum-03',
  'draft-klrc-aiagent-auth-03',
  'draft-schrock-ae-challenge-06',
  'Mid-Execution Acquisition and Resource-Server Challenges',
  'It does not authorize the action',
  'establish trust in a discovered authorization server',
  'Identification, Authentication, and Delegated Authority for Non-Person Actors in AI Systems',
  'does not replace the grant',
  'grant-specific semantics of an OAuth subject',
]) invariant(flatXml.includes(required), `XML is missing required text: ${required}`);

for (const required of [
  'Seven requirements hold for every host',
  'Authoritative approver attribution',
  'Role non-equivalence',
  'Terminal Accountability Is Not Per-Action Human Authorization',
  'Mid-Execution Acquisition and Resource-Server Challenges',
  'AI Agent Authentication and Authorization',
  'Authorization Evidence Challenge Protocol',
  'Murali, T.',
  'Discovery of metadata or keys cannot substitute',
]) invariant(flatTxt.includes(required), `TXT rendering is stale or missing: ${required}`);

for (const forbidden of [
  'B1-B5',
  'five requirements hold',
  'draft-schrock-ep-authorization-receipts-05',
  'draft-schrock-ep-quorum-01',
  'CIBA itself proves named-human authorization',
  'Discovery establishes trust',
]) {
  invariant(!flatXml.includes(forbidden), `retired or unsafe text survived in XML: ${forbidden}`);
  invariant(!flatTxt.includes(forbidden), `retired or unsafe text survived in TXT: ${forbidden}`);
}

invariant(sha256(readFileSync(posted00)) === posted00Sha256, 'immutable posted -00 XML changed');

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

console.log('Human Authorization Binding -01: source, renders, B1-B7, composition boundaries, checksums, and immutable -00 PASS.');
