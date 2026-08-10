#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/NEXT-AE-CHALLENGE-07/', import.meta.url);
const basename = 'draft-schrock-ae-challenge-07';
const published06 = new URL('../standards/posted/draft-schrock-ae-challenge-06.xml', import.meta.url);
const published06Sha256 = 'aa189344c491948a1df2d18d9bff529d696e618ebb2f73ebe607445031744433';

function invariant(condition, message) {
  if (!condition) throw new Error(`AE Challenge -07 packet: ${message}`);
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

const xml = readFileSync(new URL(`UPLOAD-THIS/${basename}.xml`, root), 'utf8');
const txt = readFileSync(new URL(`RENDERS/${basename}.txt`, root), 'utf8');
const flatXml = xml.replace(/\s+/g, ' ');
const flatTxt = txt.replace(/\s+/g, ' ');

for (const required of [
  `docName="${basename}"`,
  `value="${basename}"`,
  '<date year="2026" month="August" day="10"/>',
  'Transport-Neutral Core Data Model',
  'Required Members and JSON Types',
  'A core challenge MUST contain <tt>@version</tt>',
  '<tt>sha256:</tt> followed by 64 lowercase hexadecimal digits',
  '<tt>mechanism</tt> and <tt>uri</tt> are absolute URIs',
  'computing the complete authenticated challenge-body digest',
  'MUST cover every core and extension member, including unknown members',
  'integers from 0 through 2147483647 inclusive',
  'Every entry in <tt>required_evidence</tt> is a conjunctive requirement',
  'Every listed <tt>proof_predicates</tt> value is conjunctive',
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
  'one atomic nonce-claim-and-capacity-reservation transition',
  'The security replay key is the authenticated issuer identity and nonce',
  '<tt>challenge_id</tt> is not part of that key',
  'stable authenticated issuer identity used in that replay key',
  'MUST map it to the same issuer identity and authoritative replay domain',
  'MUST pin the semantics of the selected <tt>action_profile</tt>',
  'current exact-action agreement',
  'rederive the action digest from the current proposed action',
  'claimed-with-capacity',
  'exact-body-replay',
  'body-collision',
  'authoritative equality between the returned body digest and the registered body digest',
  'capacity-refused',
  '<tt>expired</tt>',
  'caller reports temporary unavailability',
  'replay or collision classification takes precedence over expiry',
  'one coordinating transaction or preallocated quotas',
  'old fencing token',
  'duplicate member names',
  'Hint SSRF and credential forwarding',
  'adding <tt>jitter_sec</tt> to <tt>not_before</tt>',
  'MUST still produce an instant before <tt>expires_at</tt>',
  'whether that first evaluation is still in flight or has completed',
  'State Bounds and Exhaustion',
  'finite aggregate upper bound',
  'per-presenter and per-audience bounds',
  'administrative bound per tenant',
  'self-describing issuance',
  'authoritative replay domain',
  'MUST NOT evict a live in-flight or consumed nonce',
  'State Exhaustion Conformance Cases',
  'A read-only capacity check, a reservation followed by a separate nonce claim',
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
  'Changes since -06',
  'https://iana.org/assignments/http-problem-types#ae-required',
  'Deployment Scenarios and Gap Analysis for AI Agent Gateway',
  'The Action Evidence Boundary for Consequential Agent Effects',
  'HTTP Problem Types',
  'Specification Required',
  'withdraws the earlier request',
  'MUST be used only when the server is returning a fresh evidence challenge',
  'MAY use 409 Conflict',
]) {
  invariant(flatXml.includes(required), `XML is missing required -07 text: ${required}`);
}
for (const required of [
  'Expires: 11 February 2027',
  'Transport-Neutral Core Data Model',
  'Required Members and JSON Types',
  'A core challenge MUST contain @version',
  'sha256: followed by 64 lowercase hexadecimal digits',
  'computing the complete authenticated challenge-body digest',
  'integers from 0 through 2147483647 inclusive',
  'Every entry in required_evidence is a conjunctive requirement',
  'Every listed proof_predicates value is conjunctive',
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
  'reservation followed by a separate nonce claim',
  'capacity response wins',
  'stateless list of remaining requirements',
  'route the claim to the owner before classifying the nonce',
  'temporary unavailability, not replay',
  'owner timeout, partition, or uncertain response',
  'absolute URI',
  'claimed-with-capacity',
  'exact-body-replay',
  'body-collision',
  'authoritative equality between the returned body digest and the registered body digest',
  'capacity-refused',
  'expired',
  'authenticated issuer identity and nonce',
  'same issuer identity and authoritative replay domain',
  'pin the semantics of the selected action_profile',
  'replay or collision classification takes precedence over expiry',
  'duplicate member names',
  'Hint SSRF and credential forwarding',
  'first evaluation is still in flight',
  'committed capacity is not over-allocated',
  'structured refusal or error payload',
  'does not preserve one action binding across hops',
  'Capability discovery',
  'Sumit P. Ahuja',
  'Guigui Wang',
  'Henri Sirkkavaara',
  'Changes since -06',
  'Specification Required',
  'MAY use 409 Conflict',
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
invariant(
  implementation.indexOf('presented evidence binds a different action than the challenge (action swap)')
    < implementation.indexOf('if (await store.consume(challenge) !== true)'),
  'durable runtime consumes before action agreement',
);
const challengeStore = readFileSync(new URL('../packages/gate/src/challenge-store.ts', import.meta.url), 'utf8');
invariant(challengeStore.includes("hashCanonical({ nonce: challenge.nonce })"), 'challenge store is not keyed by nonce');
invariant(challengeStore.includes('ae-challenge:v2:'), 'challenge store does not use the v2 replay-key namespace');
invariant(challengeStore.includes('challenge-open:v2:'), 'challenge store does not use the v2 open-state marker');
invariant(challengeStore.includes('challenge-consumed:v2:'), 'challenge store does not use the v2 consumed-state marker');
invariant(!challengeStore.includes('challenge-open:v1:'), 'challenge store still accepts the v1 open-state marker');
invariant(!challengeStore.includes('challenge-consumed:v1:'), 'challenge store still accepts the v1 consumed-state marker');
invariant(!challengeStore.includes("hashCanonical({ challenge_id: challenge.challenge_id, nonce: challenge.nonce })"), 'challenge_id still participates in the replay key');
const migration = readFileSync(new URL('../packages/gate/CHALLENGE-STORE-V2-MIGRATION.md', import.meta.url), 'utf8');
for (const required of [
  'Do not run v1 and v2 challenge issuers concurrently',
  'wait until every v1 challenge has expired',
  'backend-specific atomic migration',
  'must leave v2 issuance disabled',
]) invariant(migration.includes(required), `v2 migration guidance is missing: ${required}`);
for (const forbidden of [
  'application/authorization-evidence-challenge+json in the standards tree',
  'with status 428',
  'EP-APPROVAL-v1',
  '<authorization-evidence-required problem type URI>',
  'AI Agent Gateway Scenarios and Gap Analysis',
  'Action Evidence Boundary for High-Risk Agent Actions',
  'docName="draft-schrock-ae-challenge-06"',
  '<name>Changes since -04</name>',
  'MUST include <tt>retry_timing</tt> in <tt>critical</tt>',
  'Durable body-bound nonce registration is required before challenge exposure',
  '2026-08-08T',
  'Section 7.8 of the proposed next revision',
  'action agreement; expiry; authoritative routing; binding capacity reservation; atomic nonce claim',
  '"action_digest": "sha256:..."',
  '"policy_digest": "sha256:..."',
  '"nonce": "..."',
  'sha256:<relying-party-derived digest>',
  'sha256:<relying-party policy digest>',
]) {
  invariant(!flatXml.includes(forbidden), `retired protocol or revision text survived: ${forbidden}`);
  invariant(!flatTxt.includes(forbidden), `retired rendered text survived: ${forbidden}`);
}

invariant(
  sha256(readFileSync(published06)) === published06Sha256,
  'immutable published -06 XML changed',
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

console.log('AE Challenge -07: compound claim/capacity transition, collision and audience binding, retry/parser hardening, renders, checksums, and immutable -06 PASS.');
