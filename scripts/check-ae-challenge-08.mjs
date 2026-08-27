#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/NEXT-AE-CHALLENGE-08/', import.meta.url);
const basename = 'draft-schrock-ae-challenge-08';
const published07 = new URL('../standards/posted/draft-schrock-ae-challenge-07.xml', import.meta.url);
const published07Sha256 = '2bfb675ec652487bd90addbb95dda15551e69f4c022fc83a45195fee6d8d8e34';

function invariant(condition, message) {
  if (!condition) throw new Error(`AE Challenge -08 packet: ${message}`);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

invariant(
  JSON.stringify(readdirSync(new URL('UPLOAD-THIS/', root)).sort())
    === JSON.stringify([`${basename}.xml`]),
  'UPLOAD-THIS must contain exactly the -08 XML source',
);
invariant(
  JSON.stringify(readdirSync(new URL('RENDERS/', root)).sort())
    === JSON.stringify([`${basename}.html`, `${basename}.txt`]),
  'RENDERS must contain exactly the -08 HTML and TXT files',
);

const xml = readFileSync(new URL(`UPLOAD-THIS/${basename}.xml`, root), 'utf8');
const txt = readFileSync(new URL(`RENDERS/${basename}.txt`, root), 'utf8');
const flatXml = xml.replace(/\s+/g, ' ');
const flatTxt = txt.replace(/\s+/g, ' ');

for (const required of [
  `docName="${basename}"`,
  `value="${basename}"`,
  '<date year="2026" month="August" day="26"/>',
  'Optional Evaluation Lineage Profile',
  'AE-EVALUATION-LINEAGE-v1',
  'predecessor_challenge_digest',
  'presentation_profile',
  'presentation_digest',
  'evaluation_profile',
  'evaluation_profile_digest',
  'evaluated_at',
  'evidence_sufficient',
  'evidence_insufficient',
  'evaluation_indeterminate',
  'missing_evidence',
  'stale_evidence',
  'unverifiable_evidence',
  'status_unsatisfied',
  'policy_unsatisfied',
  'evaluation_unavailable',
  'evaluation_state_uncertain',
  'successor_challenge_digest',
  'not authorization, admission, execution',
  'MUST NOT rewrite an earlier artifact',
  'authenticated issuer statement',
  'does not prove challenge consumption',
  'data-minimized',
  'MUST NOT contain a credential, bearer token, secret, or sensitive query parameter',
  'not raw evidence, policy documents, credentials, authority objects',
  'Christine Classy',
  '538: Iman Schrock Missing-Evidence Receipt',
  'Changes since -07',
]) invariant(flatXml.includes(required), `XML is missing required -08 text: ${required}`);

for (const required of [
  'Optional Evaluation Lineage Profile',
  'AE-EVALUATION-LINEAGE-v1',
  'predecessor_challenge_digest',
  'evaluation_profile_digest',
  'evidence_sufficient',
  'evidence_insufficient',
  'evaluation_indeterminate',
  'successor_challenge_digest',
  'not authorization, admission, execution',
  'MUST NOT rewrite an earlier artifact',
  'authenticated issuer statement',
  'does not prove challenge consumption',
  'data-minimized',
  'MUST NOT contain a credential, bearer token, secret, or sensitive query parameter',
  'Christine Classy',
  'Changes since -07',
]) invariant(flatTxt.includes(required), `TXT rendering is stale or missing: ${required}`);

for (const forbidden of [
  'docName="draft-schrock-ae-challenge-07"',
  '<name>Changes since -06</name>',
  'Legacy Seal',
  'Master Vault Echo Hash',
  'CIW 1.000',
  'absolute legal',
  'un-fudgeable',
  'exactly-once physical execution',
]) {
  invariant(!flatXml.includes(forbidden), `retired or unsupported text survived: ${forbidden}`);
  invariant(!flatTxt.includes(forbidden), `retired or unsupported rendered text survived: ${forbidden}`);
}

invariant(
  sha256(readFileSync(published07)) === published07Sha256,
  'immutable published -07 XML changed',
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

console.log('AE Challenge -08: authenticated evaluation statement, closed outcomes, bounded successor reference, renders, checksums, and published -07 integrity PASS.');
