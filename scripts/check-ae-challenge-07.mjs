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
  'HTTP Challenge Response Carrier',
  'This section defines only the HTTP refusal response that carries a challenge',
  'This core does not define a generic successful-response envelope',
  'MUST NOT replace a <tt>401 Unauthorized</tt>',
  '<tt>429 Too Many Requests</tt>',
  'uses 409 Conflict only when an application profile establishes a conflict',
  'The <tt>status</tt> member MAY be omitted',
  'relative to the time it received the response',
  'Informative DMSC Gateway Illustration',
  'This is an illustration, not a DMSC conformance requirement',
  'Future Work',
  'not required to implement the core data model',
  '16 random octets',
  'unpadded base64url',
  '22 through 128 ASCII characters',
  'The security replay key is the authenticated issuer identity and nonce',
  '<tt>challenge_id</tt> is not part of that key',
  'collision-resistant digest procedure with an output of at least 256 bits',
  'MUST be domain-separated for AE-CHALLENGE bodies',
  'MUST cover every core and extension member, including unknown members',
  'preserves every data-model distinction accepted by the binding',
  'pin, for the lifetime of the challenge, the security semantics',
  'authenticated minimal tombstone binding the replay key',
  'generic unknown-challenge refusal',
  'anonymous or transferable exception satisfying the core rules',
  'top-level members of the core challenge only',
  'nested core objects in <tt>required_evidence</tt>',
  'current exact-action agreement',
  'does not freeze the action for a later executor admission',
  'claim binds the nonce to the registered challenge body, not to a digest of the presented evidence payload',
  'one atomic owner-side transition',
  'First, a retained claimed record produces',
  'Second, when no claimed record exists, expiry produces',
  'Only the positive incremental delta',
  'zero-increment transfer',
  'separate finite anti-abuse budget',
  'reduces the value of exhaustion handling as a policy-discovery oracle',
  'Detailed diagnostics are limited to authenticated and locally authorized operational channels',
  'Digests do not make low-entropy values secret',
  'claimed-with-capacity',
  'exact-body-replay',
  'body-collision',
  'capacity-refused',
  '<tt>expired</tt>',
  'temporary unavailability, not replay',
  'one coordinating transaction or preallocated quotas',
  'old fencing token',
  'OAuth Non-Substitution Conformance Case',
  'Satisfying AE-CHALLENGE never satisfies a native OAuth grant requirement',
  'https://iana.org/assignments/http-problem-types#ae-required',
  'requires approval by a designated expert',
  'reference.RFC.4648.xml',
  'reference.RFC.6234.xml',
  'reference.RFC.6585.xml',
  'anchor="RFC9111"',
  'Changes since -06',
  'Sumit P. Ahuja',
  'Guigui Wang',
  'Henri Sirkkavaara',
]) {
  invariant(flatXml.includes(required), `XML is missing required -07 text: ${required}`);
}

for (const required of [
  'Expires: 11 February 2027',
  'HTTP Challenge Response Carrier',
  'HTTP refusal response that carries a challenge',
  'does not define a generic',
  '401 Unauthorized',
  '429 Too Many Requests',
  'status member MAY be omitted',
  'Informative DMSC Gateway Illustration',
  'not a DMSC conformance requirement',
  'Future Work',
  '16 random octets',
  'unpadded base64url',
  '22 through 128 ASCII characters',
  'authenticated issuer identity and nonce',
  'collision-resistant digest',
  'domain-separated',
  'security semantics of every evidence',
  'authenticated minimal tombstone',
  'anonymous or transferable exception',
  'current exact-action agreement',
  'does not freeze the action',
  'registered challenge body, not to a digest of the presented evidence',
  'First, a retained claimed record',
  'positive incremental delta',
  'zero-increment transfer',
  'separate finite anti-abuse budget',
  'reduces the value',
  'Digests do not make low-entropy values secret',
  'claimed-with-capacity',
  'exact-body-replay',
  'body-collision',
  'capacity-refused',
  'Specification Required',
  'designated expert',
  'RFC 4648',
  'RFC 6234',
  'RFC 6585',
  'RFC 9111',
  'Changes since -06',
]) {
  invariant(flatTxt.includes(required), `TXT rendering is stale or missing: ${required}`);
}

for (const forbidden of [
  '<name>HTTP Binding</name>',
  '<name>Informative DMSC Gateway Profile</name>',
  '<name>Interoperability Questions for Review</name>',
  '<name>Implementation Status</name>',
  'transaction_authorization_required',
  'replay or collision classification takes precedence over expiry',
  'MAY use 409 Conflict for those disclosed state conflicts',
  'with status 428',
  'application/authorization-evidence-challenge+json in the standards tree',
  'prevents an unauthenticated or weakly authenticated load probe',
  'Section 7.8 of the proposed next revision',
  'docName="draft-schrock-ae-challenge-06"',
]) {
  invariant(!flatXml.includes(forbidden), `retired or overstated text survived: ${forbidden}`);
  invariant(!flatTxt.includes(forbidden.replace(/<[^>]+>/g, '')), `retired rendered text survived: ${forbidden}`);
}

const implementation = readFileSync(new URL('../lib/negotiate/evidence-challenge.ts', import.meta.url), 'utf8');
for (const required of [
  "const DURABLE_NONCE_RE = /^[A-Za-z0-9_-]{22,128}$/",
  'isAuthoritativeChallengeOwnerStore(store)',
  'store.finalizeReservation(reservation',
  'production challenge nonces are generated internally',
  'authenticated presenter is required for production evaluation',
  "challenge.present_as.includes(CHALLENGE_PRESENTATION_METHOD)",
  "verdict: 'unavailable'",
  "state_changed: 'unknown'",
]) invariant(implementation.includes(required), `runtime hardening is missing: ${required}`);
invariant(!implementation.includes('REQUIRED_PRODUCTION_STORE_CAPABILITIES'), 'production must not trust self-declared capability booleans');

const generatedImplementation = readFileSync(new URL('../lib/negotiate/evidence-challenge.js', import.meta.url), 'utf8');
for (const required of [
  "const DURABLE_NONCE_RE = /^[A-Za-z0-9_-]{22,128}$/",
  'isAuthoritativeChallengeOwnerStore(store)',
  'store.finalizeReservation(reservation',
  'production challenge nonces are generated internally',
  'authenticated presenter is required for production evaluation',
  "verdict: 'unavailable'",
]) invariant(generatedImplementation.includes(required), `generated runtime is stale: ${required}`);
invariant(!implementation.includes('compoundClaimAndCapacity: true'), 'a boolean capability must not impersonate the compound transition');

const challengeStore = readFileSync(new URL('../packages/gate/src/challenge-store.ts', import.meta.url), 'utf8');
for (const required of [
  "DURABLE_CHALLENGE_STORE_VERSION = 'EP-DURABLE-CHALLENGE-STORE-v3'",
  "issuer: normalizedIssuerIdentity(issuerIdentity)",
  'nonce: challenge.nonce',
  'ae-challenge:v3:',
  'challenge-open:v3:',
  'challenge-consumed:v3:',
  "'open-body-collision'",
  "'claimed-body-collision'",
  "AUTHORITATIVE_CHALLENGE_OWNER_VERSION = 'EP-AE-CHALLENGE-OWNER-v1'",
  'new WeakSet<object>()',
  'createAuthoritativeChallengeOwnerStore',
  'authoritativeNowMs',
  'compoundClaimAndCapacity',
  'finalizeReservation',
  'recoverReservation',
  'recoveryAuthorizer',
]) invariant(challengeStore.includes(required), `challenge store hardening is missing: ${required}`);

const postgresOwner = readFileSync(new URL('../packages/gate/src/challenge-store-postgres.ts', import.meta.url), 'utf8');
for (const required of [
  "AE_CHALLENGE_POSTGRES_OWNER_VERSION = 'EP-AE-CHALLENGE-PG-OWNER-v1'",
  'transaction_timestamp()',
  'ORDER BY bucket_key FOR UPDATE',
  'BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE',
  'createPostgresChallengeOwnerBackend',
]) invariant(postgresOwner.includes(required), `PostgreSQL owner contract is missing: ${required}`);

const migration = readFileSync(new URL('../packages/gate/CHALLENGE-STORE-V3-MIGRATION.md', import.meta.url), 'utf8');
for (const required of [
  'Do not repurpose the v2 namespace',
  'wait until every v2 challenge has expired',
  'backend-specific atomic migration',
  'leaves v3 issuance disabled',
]) invariant(migration.includes(required), `v3 migration guidance is missing: ${required}`);

const model = readFileSync(new URL('../formal/evidence-challenge-claim-capacity.model.mjs', import.meta.url), 'utf8');
for (const required of [
  'BOUNDED-MODEL-v2',
  'CAP_BUCKETS',
  'registerOutstanding',
  'positive incremental delta',
  'JSON.stringify([issuer, nonce])',
  'owner_token,',
  'CHECKED_PROPERTIES',
]) invariant(model.includes(required), `finite owner-transition model is missing: ${required}`);
const modelRunnerBytes = readFileSync(new URL('../formal/check-evidence-challenge-claim-capacity.mjs', import.meta.url));
const modelResult = readFileSync(new URL('../formal/results/evidence-challenge-claim-capacity.summary.txt', import.meta.url), 'utf8');
invariant(modelResult.includes(`Model SHA-256: ${sha256(Buffer.from(model))}`), 'finite model result is not bound to current model bytes');
invariant(modelResult.includes(`Runner SHA-256: ${sha256(modelRunnerBytes)}`), 'finite model result is not bound to current runner bytes');
invariant(modelResult.includes('Checked properties, not proved obligations:'), 'finite model result overstates checked properties as proof obligations');
invariant(!modelResult.includes(': verified'), 'finite model result still labels bounded scenarios as verified');

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

console.log('AE Challenge -07: private red-team packet, HTTP carrier boundaries, replay/capacity model, v3 migration, renders, checksums, and immutable -06 PASS.');
