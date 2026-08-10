#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/NEXT-AE-CHALLENGE-06/', import.meta.url);
const basename = 'draft-schrock-ae-challenge-06';
const published05 = new URL('../standards/archive/draft-schrock-ae-challenge-05.xml', import.meta.url);
const published05Sha256 = '77fce83124c69fbd1cd5b45fb13aba64d00a2ffdd4f17c4610f6ace895a8106b';

function invariant(condition, message) {
  if (!condition) throw new Error(`AE Challenge -06 packet: ${message}`);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

invariant(
  JSON.stringify(readdirSync(new URL('UPLOAD-THIS/', root)).sort())
    === JSON.stringify([`${basename}.xml`]),
  'UPLOAD-THIS must contain exactly the -06 XML source',
);
invariant(
  JSON.stringify(readdirSync(new URL('RENDERS/', root)).sort())
    === JSON.stringify([`${basename}.html`, `${basename}.txt`]),
  'RENDERS must contain exactly the -06 HTML and TXT files',
);

const xml = readFileSync(new URL(`UPLOAD-THIS/${basename}.xml`, root), 'utf8');
const txt = readFileSync(new URL(`RENDERS/${basename}.txt`, root), 'utf8');
const flatXml = xml.replace(/\s+/g, ' ');
const flatTxt = txt.replace(/\s+/g, ' ');

for (const required of [
  `docName="${basename}"`,
  `value="${basename}"`,
  '<date year="2026" month="August" day="10"/>',
  'Transport-Neutral Core Data Model',
  'HTTP Binding',
  'Boundary with OAuth Transaction Authorization',
  'OAuth Non-Substitution Conformance Case',
  'transaction_authorization_required',
  'Satisfying AE-CHALLENGE never satisfies a native OAuth grant requirement',
  'single-use property in this document applies only to one evidence-presentation attempt',
  'draft-rosomakho-oauth-txn-challenge-00',
  'draft-klrc-aiagent-auth-03',
  'draft-schrock-ep-authorization-receipts-11',
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
  'action agreement; expiry; authoritative routing; binding capacity reservation; atomic nonce claim',
  'whether that first evaluation is still in flight or has completed',
  'State Bounds and Exhaustion',
  'finite aggregate upper bound',
  'per-presenter and per-audience bounds',
  'administrative bound per tenant',
  'self-describing issuance',
  'authoritative replay domain',
  'MUST NOT evict a live in-flight or consumed nonce',
  'State Exhaustion Conformance Cases',
  'read-only capacity check followed by unreserved evaluation does not satisfy this requirement',
  'capacity response wins',
  'stateless list of remaining requirements',
  'route the claim to the owner before classifying the nonce',
  'Only an authoritative owner result that the exact registered body was already claimed is a replay result',
  'temporary unavailability, not replay',
  'owner timeout, partition, or uncertain response',
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
  'Changes since -05',
  'https://iana.org/assignments/http-problem-types#ae-required',
  'Deployment Scenarios and Gap Analysis for AI Agent Gateway',
  'The Action Evidence Boundary for Consequential Agent Effects',
  'HTTP Problem Types',
  'Specification Required',
  'withdraws the earlier request',
]) {
  invariant(flatXml.includes(required), `XML is missing required -06 text: ${required}`);
}
for (const required of [
  'Expires: 11 February 2027',
  'Transport-Neutral Core Data Model',
  'HTTP Binding',
  'Boundary with OAuth Transaction Authorization',
  'OAuth Non-Substitution Conformance Case',
  'transaction_authorization_required',
  'never satisfies a native OAuth grant requirement',
  'one evidence-presentation attempt',
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
  'read-only capacity check followed by unreserved evaluation',
  'capacity response wins',
  'stateless list of remaining requirements',
  'route the claim to the owner before classifying the nonce',
  'temporary unavailability, not replay',
  'owner timeout, partition, or uncertain response',
  'absolute URI',
  'first evaluation is still in flight',
  'committed capacity is not over-allocated',
  'structured refusal or error payload',
  'does not preserve one action binding across hops',
  'Capability discovery',
  'Sumit P. Ahuja',
  'Guigui Wang',
  'Henri Sirkkavaara',
  'Changes since -05',
  'Specification Required',
]) {
  invariant(flatTxt.includes(required), `TXT rendering is stale or missing: ${required}`);
}

const implementation = readFileSync(new URL('../lib/negotiate/evidence-challenge.ts', import.meta.url), 'utf8');
for (const required of [
  'selectAuthorizationChallengeMechanism',
  "primary: 'oauth-transaction-authorization'",
  'substitution_allowed: false',
  'explicit_composition_profile',
]) invariant(implementation.includes(required), `implementation is missing OAuth boundary guard: ${required}`);
for (const forbidden of [
  'application/authorization-evidence-challenge+json in the standards tree',
  'with status 428',
  'EP-APPROVAL-v1',
  '<authorization-evidence-required problem type URI>',
  'AI Agent Gateway Scenarios and Gap Analysis',
  'Action Evidence Boundary for High-Risk Agent Actions',
  'docName="draft-schrock-ae-challenge-05"',
  '<name>Changes since -04</name>',
  'MUST include <tt>retry_timing</tt> in <tt>critical</tt>',
  'Durable body-bound nonce registration is required before challenge exposure',
  '2026-08-08T',
]) {
  invariant(!flatXml.includes(forbidden), `retired protocol or revision text survived: ${forbidden}`);
  invariant(!flatTxt.includes(forbidden), `retired rendered text survived: ${forbidden}`);
}

invariant(
  sha256(readFileSync(published05)) === published05Sha256,
  'immutable published -05 XML changed',
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

console.log('AE Challenge -06: cap-first refusal, no-policy-oracle behavior, authoritative owner replay, renders, checksums, and immutable -05 PASS.');
