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
// Page footers and running headers can fall inside a sentence; drop them
// before flattening so required text is matched as a reader sees it.
const flatTxt = txt
  .split('\n')
  .filter((line) => !/\[Page \d+\]$/.test(line) && !/^Internet-Draft {2,}.* \d{4}$/.test(line))
  .join('\n')
  .replace(/\f/g, '')
  .replace(/\s+/g, ' ');

for (const required of [
  `docName="${basename}"`,
  `value="${basename}"`,
  'submissionType="independent"',
  '<date year="2026" month="September" day="27"/>',
  'Optional Evaluation Lineage Profile',
  'AE-EVALUATION-LINEAGE-v1',
  'predecessor_challenge_digest',
  'presentation_profile',
  'presentation_digest',
  'evaluation_profile',
  'evaluation_profile_digest',
  'evaluated_at',
  '<dt>VERIFIED:</dt>',
  '<dt>ACCEPTED:</dt>',
  '<dt>SATISFIED:</dt>',
  '<dt>UNSATISFIED:</dt>',
  'missing_evidence',
  'evidence_not_verified',
  'evidence_not_evaluated',
  'evidence_not_accepted',
  'action_not_matched',
  'stale_evidence',
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
  '<section anchor="implementation-status" removeInRFC="true">',
  'reference.RFC.7942.xml',
  'reference.RFC.8792.xml',
  "NOTE: '\\' line wrapping per RFC 8792",
  '<reference anchor="AIMS"',
  'value="draft-ietf-wimse-aims-00"',
  'value="draft-schrock-ep-authorization-evidence-chain-07"',
  '<name>References</name>',
  'https://iana.org/assignments/http-problem-types#ae-required',
  'Changes since -07',
]) invariant(flatXml.includes(required), `XML is missing required -08 text: ${required}`);

for (const required of [
  'Optional Evaluation Lineage Profile',
  'AE-EVALUATION-LINEAGE-v1',
  'predecessor_challenge_digest',
  'evaluation_profile_digest',
  'The closed outcome values are SATISFIED and UNSATISFIED',
  'restated here so that this document does not depend on that specification',
  'VERIFIED says nothing about whether the relying party trusts the key, issuer, or policy',
  'evidence_not_accepted (a presented artifact is VERIFIED and not ACCEPTED)',
  'evidence_not_evaluated (VERIFIED could not be evaluated for a presented artifact',
  'this is not a verification failure',
  'under the relying party\'s authenticated live policy (Section 2.2), by evidence that is VERIFIED, ACCEPTED, and bound to the exact action',
  'The relying party\'s evaluation time in this document is the verification time of [AEC].',
  'live policy changes before evaluation, the relying party MUST start a fresh challenge under the changed policy',
  'it does not authenticate the challenge issuer or the returning presenter',
  'It does not rederive the current proposed action before the claim',
  'A follow-up challenge copies the stored action digest',
  '11 over all 1,024 combinations of four storage capabilities and six challenge bindings, and 6 over a single configuration each',
  'MUST NOT mix the two kinds',
  'A recipient MUST NOT read an evaluation that did not complete as a completed refusal or as success',
  'successor_challenge_digest MAY appear only with an UNSATISFIED outcome whose reason_ids are completed-evaluation reasons',
  'not authorization, admission, execution',
  'MUST NOT rewrite an earlier artifact',
  'authenticated issuer statement',
  'does not prove challenge consumption',
  'data-minimized',
  'MUST NOT contain a credential, bearer token, secret, or sensitive query parameter',
  'This section is to be removed before publishing as an RFC.',
  'this document is intended for the Independent Submission Stream',
  'The reference is narrower than this document.',
  'Its store keys a registration by challenge identifier and nonce within one relying party',
  'Its durable path accepts nonces of 16 through 128 base64url characters',
  'It does not implement the capacity, outstanding-state, and exhaustion requirements',
  'That adapter is exercised against an in-process emulation of its SQL statements, not a live database.',
  'None of this is an independent implementation',
  'SATISFIED concerns evidence sufficiency only.',
  // "Changes since -07" compares with the posted -07, which has no SATISFIED
  // term, and says which -07 implementation claims are withdrawn.
  'SATISFIED concerns evidence sufficiency only; the relying party\'s local authorization decision is outside it.',
  'This withdraws the description in Section 2.6.2 of -07',
  'is outside SATISFIED and is not reported with these reasons',
  'it requires that the confirmation be bound to a verifiable authorization grant issued by the authorization server, which makes the final decision',
  'The type is not specific to one application or deployment.',
  'Section 10.7 of [AIMS]',
  'draft-ietf-wimse-aims-00',
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
  // The -08 draft's own third outcome vocabulary, replaced by AEC's terms.
  'evidence_sufficient',
  'evidence_insufficient',
  'evaluation_indeterminate',
  'unverifiable_evidence',
  // Implementation claims that no code in the repository supports.
  'PostgreSQL transaction backend',
  'owner state machine',
  '65536',
  '114 small scenarios',
  'stale-worker fencing',
  'Model-to-Matter',
  // Moved out of the core (it describes the implementation) and the
  // vocabulary that missed the VERIFIED-but-not-ACCEPTED case.
  'The reference HTTP helpers consume already decoded objects',
  'missing, stale, or unverifiable',
  'promise capacity or acceptance',
  'treats a user confirmation obtained during task execution as authorization only when',
  // Earlier -08 wording: SATISFIED under a challenge-bound policy snapshot,
  // an unkeyed policy-change rule, and a model description that put all 17
  // obligations over 1,024 configurations.
  'under the policy snapshot the challenge binds',
  'this optional profile requires the relying party to start a fresh challenge',
  '1,024 storage-capability configurations',
  // A Changes bullet that described a change from the unposted 2026-08-27
  // candidate instead of from the posted -07.
  'States that SATISFIED concerns evidence sufficiency only and that',
  // The replaced KLRC draft is no longer cited.
  'draft-klrc-aiagent-auth-03',
  'target="KLRC"',
  '[KLRC]',
]) {
  invariant(!flatXml.includes(forbidden), `retired or unsupported text survived: ${forbidden}`);
  invariant(!flatTxt.includes(forbidden), `retired or unsupported rendered text survived: ${forbidden}`);
}

invariant(/^[\x09\x0a\x0d\x20-\x7e]*$/.test(xml), 'XML source must be printable ASCII');
invariant(/^[\x09\x0a\x0c\x0d\x20-\x7e]*$/.test(txt), 'TXT render must be printable ASCII');
invariant(txt.split('\n').every((line) => line.length <= 72), 'TXT render has a line over 72 columns');
invariant(!/[\u2013\u2014]/.test(xml) && !/[\u2013\u2014]/.test(txt), 'no en or em dash may appear');

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

console.log('AE Challenge -08: AEC outcome terms restated without a normative dependency, closed reasons, bounded successor reference, Independent Stream shape, renders, checksums, and published -07 integrity PASS.');
