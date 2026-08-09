#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/NEXT-AE-CHALLENGE-05/', import.meta.url);
const basename = 'draft-schrock-ae-challenge-05';
const published04 = new URL('../standards/staged/NEXT-AE-CHALLENGE-04/UPLOAD-THIS/draft-schrock-ae-challenge-04.xml', import.meta.url);
const published04Sha256 = 'db58ddde429ca0da23cf50d8a16ece0f973d574d1e27d4cee6d7f6319069fbe3';

function invariant(condition, message) {
  if (!condition) throw new Error(`AE Challenge -05 packet: ${message}`);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

invariant(
  JSON.stringify(readdirSync(new URL('UPLOAD-THIS/', root)).sort())
    === JSON.stringify([`${basename}.xml`]),
  'UPLOAD-THIS must contain exactly the -05 XML source',
);
invariant(
  JSON.stringify(readdirSync(new URL('RENDERS/', root)).sort())
    === JSON.stringify([`${basename}.html`, `${basename}.txt`]),
  'RENDERS must contain exactly the -05 HTML and TXT files',
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
  'MUST NOT appear in <tt>critical</tt>',
  'not a promise of capacity, evidence sufficiency, admission, or execution',
  'Retry-After',
  'recipient-specific or challenge-specific retry schedules',
  'MUST NOT be issued solely to signal overload',
  'MUST be an absolute URI',
  'action agreement; expiry; atomic nonce claim',
  'whether that first evaluation is still in flight or has completed',
  'State Bounds and Exhaustion',
  'finite aggregate upper bound',
  'per-presenter and per-audience bounds',
  'administrative bound per tenant',
  'self-describing issuance',
  'authoritative replay domain',
  'MUST NOT evict a live in-flight or consumed nonce',
  'State Exhaustion Conformance Cases',
  'Two verifier replicas concurrently receiving the same nonce',
  'MUST NOT include <tt>evidence_challenge</tt>',
  'committed capacity is not over-allocated under any interleaving',
  'structured refusal or error payload',
  'does not preserve one action binding across hops',
  'Capability discovery',
  'determine sufficiency using its authenticated local policy',
  'Sumit P. Ahuja',
  'Guigui Wang',
  'Henri Sirkkavaara',
  'Changes since -04',
  'https://iana.org/assignments/http-problem-types#ae-required',
  'Deployment Scenarios and Gap Analysis for AI Agent Gateway',
  'The Action Evidence Boundary for Consequential Agent Effects',
  'HTTP Problem Types',
  'Specification Required',
  'withdraws the earlier request',
]) {
  invariant(flatXml.includes(required), `XML is missing required -05 text: ${required}`);
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
  'Retry synchronization and load amplification',
  'not a promise of capacity, evidence sufficiency, admission, or execution',
  'State Bounds and Exhaustion',
  'finite aggregate upper bound',
  'self-describing issuance',
  'authoritative replay domain',
  'State Exhaustion Conformance Cases',
  'absolute URI',
  'first evaluation is still in flight',
  'committed capacity is not over-allocated',
  'structured refusal or error payload',
  'does not preserve one action binding across hops',
  'Capability discovery',
  'Sumit P. Ahuja',
  'Guigui Wang',
  'Henri Sirkkavaara',
  'Changes since -04',
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
  'docName="draft-schrock-ae-challenge-04"',
  '<name>Changes since -03</name>',
  'MUST include <tt>retry_timing</tt> in <tt>critical</tt>',
  'Durable body-bound nonce registration is required before challenge exposure',
  '2026-08-08T',
]) {
  invariant(!flatXml.includes(forbidden), `retired protocol or revision text survived: ${forbidden}`);
  invariant(!flatTxt.includes(forbidden), `retired rendered text survived: ${forbidden}`);
}

invariant(
  sha256(readFileSync(published04)) === published04Sha256,
  'immutable published -04 XML changed',
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

console.log('AE Challenge -05: non-critical retry pacing, bounded refusal-path state, authoritative replay, conformance cases, renders, checksums, and immutable -04 PASS.');
