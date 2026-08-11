#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/NEXT-BOUNDED-CAPABILITY-04/', import.meta.url);
const basename = 'draft-schrock-ep-bounded-capability-receipts-04';

function invariant(condition, message) {
  if (!condition) throw new Error(`Bounded Capability -04 packet: ${message}`);
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
invariant(xml.includes('submissionType="IETF"'), 'the inherited submission type changed');
invariant(xml.includes('<date year="2026" month="August" day="11"/>'), 'date must be 11 August 2026');
invariant(txt.includes(basename) && html.includes(basename), 'renderings must identify -04');

for (const required of [
  '<tt>revocation_mode</tt>',
  'Exactly <tt>direct</tt> or <tt>cascade</tt>',
  'complete authority-bearing ancestor lineage',
  'revocation transition and a descendant reservation',
  '<tt>capability_ancestor_status_unavailable</tt>',
  'quarantines legacy rows without an explicit mode',
  'reservation that commits first remains owned and reconcilable',
  'separate -03 revocation-inheritance model',
  'This non-strict subset relation is reflexive and transitive',
  '<tt>definition-derived</tt>',
  '<tt>mechanically-checkable</tt>',
  '<tt>asserted</tt>',
  'performed the complete enumeration itself or relied on a prior conformance run',
  'makes the record stale for this evaluation',
  'A mutable alias or version label alone is insufficient',
  '<tt>NO_BROADER</tt>',
  'every scope value used in the composed chain',
  'under relying-party-pinned trust policy',
  'A self-authenticated or otherwise untrusted runner is insufficient',
  'contributes no current comparison result',
  'Transitivity established separately for two different relations does not prove that those relations compose',
  '<bcp14>MUST NOT</bcp14> establish descendant authority across a path of more than one delegation edge',
  'same mutable version label over different profile or rule content',
  '<strong>Comparison-proof substitution and exhaustion.</strong>',
  'authoritative operation key is the tuple of capability receipt digest and operation ID',
  'form one idempotent logical operation bound to the capability receipt digest',
  'authoritative time sample obtained inside the same state transaction',
  'terminal with outcome <tt>not_entered</tt>',
  'remain as a replay tombstone after budget restoration',
  '<strong>External predicate freshness.</strong>',
  'same raw operation ID under a different capability is not by itself a replay',
  'Replay refusal in this document means refusal of an already-seen operation key',
  'add a durable action fence or bind a unique occurrence identifier',
  'assigns no automatic trust rank',
  'solely to avoid reporting the relied-on mode',
  'without repeating the enumeration',
  'mechanical-establishment provenance',
  'Sumit P. Ahuja',
  'local-only or chain-composable',
  'An asserted-transitive profile',
  'atomic root-issuance registration rule is also not implemented',
  'capability-scoped operation key and terminal budget-restoring',
  '<name>Implementation Status</name>',
]) {
  invariant(xmlText.includes(required), `XML is missing required -04 text: ${required}`);
}
for (const required of [
  'revocation_mode',
  'direct or cascade',
  'complete authority-bearing ancestor lineage',
  'capability_ancestor_status_unavailable',
  'quarantines legacy rows without an explicit mode',
  'remains owned and reconcilable',
  'revocation-inheritance model',
  'non-strict subset relation is reflexive and transitive',
  'definition-derived',
  'mechanically-checkable',
  'performed the complete enumeration itself or relied on a prior conformance run',
  'makes the record stale for this evaluation',
  'A mutable alias or version label alone is insufficient',
  'NO_BROADER',
  'every scope value used in the composed chain',
  'under relying-party-pinned trust policy',
  'self-authenticated or otherwise untrusted runner is insufficient',
  'contributes no current comparison result',
  'Transitivity established separately for two different relations does not prove that those relations compose',
  'MUST NOT establish descendant authority across a path of more than one delegation edge',
  'same mutable version label over different profile or rule content',
  'Comparison-proof substitution and exhaustion',
  'authoritative operation key is the tuple of capability receipt digest and operation ID',
  'form one idempotent logical operation bound to the capability receipt digest',
  'authoritative time sample obtained inside the same state transaction',
  'terminal with outcome not_entered',
  'remain as a replay tombstone after budget restoration',
  'External predicate freshness',
  'same raw operation ID under a different capability is not by itself a replay',
  'Replay refusal in this document means refusal of an already-seen operation key',
  'add a durable action fence or bind a unique occurrence identifier',
  'assigns no automatic trust rank',
  'solely to avoid reporting the relied-on mode',
  'without repeating the enumeration',
  'mechanical-establishment provenance',
  'Sumit P. Ahuja',
  'local-only or chain-composable',
  'asserted-transitive profile',
  'not yet emit per-component decidability records',
  'atomic root-issuance registration rule is also not implemented',
  'capability-scoped operation key and terminal budget-restoring',
  'Implementation Status',
]) {
  invariant(txtText.includes(required), `TXT rendering is stale or missing: ${required}`);
}
for (const forbidden of [
  'does not yet implement the mandatory revocation_mode field',
  'atomic cascade-ancestor traversal, or the direct-versus-cascade',
  'No runtime conformance claim is made',
  'versioned or content-digest-pinned',
  'stale record MUST yield a local-only result',
  'globally unique operation ID',
  'reject any already-seen operation ID',
]) {
  invariant(!xmlText.includes(forbidden), `forbidden stale claim survived: ${forbidden}`);
  invariant(!txtText.includes(forbidden), `forbidden rendered claim survived: ${forbidden}`);
}

// Executable editorial controls for the relation-composition mistakes that
// motivated -04. This is a decision-model check over the draft's normative
// contract, not an implementation-conformance claim.
function relationContextKey(context) {
  return [
    context.profileDigest,
    context.ruleDigest,
    context.domainDigest ?? '',
    context.procedureDigest ?? '',
    context.basis,
  ].join('|');
}

function chainComposable({ hops, establishment }) {
  if (hops.length === 0) return false;
  if (hops.some((hop) => hop.localResult !== 'NO_BROADER')) return false;
  if (hops.length === 1) return true;

  const context = relationContextKey(hops[0].context);
  if (hops.some((hop) => relationContextKey(hop.context) !== context)) return false;
  if (hops[0].context.basis === 'asserted') return false;
  if (hops[0].context.basis === 'definition-derived') return true;
  if (hops[0].context.basis !== 'mechanically-checkable') return false;
  if (!establishment?.authenticated || !establishment?.runnerTrusted || !establishment?.exactContextMatch) return false;
  const domain = new Set(establishment.domain);
  return hops.every((hop) => domain.has(hop.parent) && domain.has(hop.child));
}

const mechanicalContext = {
  profileDigest: 'sha256:profile-a',
  ruleDigest: 'sha256:rule-a',
  domainDigest: 'sha256:domain-a',
  procedureDigest: 'sha256:procedure-a',
  basis: 'mechanically-checkable',
};
const matchingRecord = {
  authenticated: true,
  runnerTrusted: true,
  exactContextMatch: true,
  domain: ['root', 'middle', 'leaf'],
};

invariant(chainComposable({
  hops: [
    { parent: 'root', child: 'middle', localResult: 'NO_BROADER', context: mechanicalContext },
    { parent: 'middle', child: 'leaf', localResult: 'NO_BROADER', context: mechanicalContext },
  ],
  establishment: matchingRecord,
}), 'matching trusted complete-domain proof must compose');

invariant(!chainComposable({
  hops: [
    { parent: 'root', child: 'middle', localResult: 'NO_BROADER', context: mechanicalContext },
    { parent: 'middle', child: 'leaf', localResult: 'NO_BROADER', context: { ...mechanicalContext, ruleDigest: 'sha256:rule-b' } },
  ],
  establishment: matchingRecord,
}), 'individually transitive but heterogeneous relations must not compose');

invariant(!chainComposable({
  hops: [
    { parent: 'root', child: 'outside-domain', localResult: 'NO_BROADER', context: mechanicalContext },
    { parent: 'outside-domain', child: 'leaf', localResult: 'NO_BROADER', context: mechanicalContext },
  ],
  establishment: matchingRecord,
}), 'off-domain values must not inherit the mechanical proof');

invariant(!chainComposable({
  hops: [
    { parent: 'root', child: 'middle', localResult: 'NO_BROADER', context: mechanicalContext },
    { parent: 'middle', child: 'leaf', localResult: 'NO_BROADER', context: mechanicalContext },
  ],
  establishment: { ...matchingRecord, runnerTrusted: false },
}), 'self-authenticated but untrusted runner must not establish composition');

invariant(!chainComposable({
  hops: [
    { parent: 'root', child: 'middle', localResult: 'NO_BROADER', context: mechanicalContext },
    { parent: 'middle', child: 'leaf', localResult: 'NO_BROADER', context: mechanicalContext },
  ],
  establishment: { ...matchingRecord, exactContextMatch: false },
}), 'stale same-label record must not establish composition');

invariant(chainComposable({
  hops: [{ parent: 'root', child: 'leaf', localResult: 'NO_BROADER', context: { ...mechanicalContext, basis: 'asserted' } }],
}), 'one current edge does not require transitive induction');

function operationKey(capabilityDigest, operationId) {
  return `${capabilityDigest}\u0000${operationId}`;
}

invariant(
  operationKey('sha256:capability-a', 'op-1') === operationKey('sha256:capability-a', 'op-1'),
  'exact operation replay must retain one key',
);
invariant(
  operationKey('sha256:capability-a', 'op-1') !== operationKey('sha256:capability-b', 'op-1'),
  'the same raw operation id under a different capability must not collide',
);

// A root registration either records the exact receipt under the consumed
// issuance authorization, returns that same record idempotently, or refuses.
// An uncertain consumption cannot be reused to mint a different receipt.
function registerRoot(state, receiptDigest) {
  if (state.registrationDigest !== null) {
    return state.registrationDigest === receiptDigest ? 'EXISTING' : 'REFUSE';
  }
  if (state.authorizationStatus === 'indeterminate') {
    return state.boundDigest === receiptDigest ? 'INDETERMINATE' : 'REFUSE';
  }
  if (state.authorizationStatus !== 'available') return 'REFUSE';
  state.authorizationStatus = 'consumed';
  state.boundDigest = receiptDigest;
  state.registrationDigest = receiptDigest;
  return 'REGISTERED';
}

const rootState = {
  authorizationStatus: 'available',
  boundDigest: null,
  registrationDigest: null,
};
invariant(registerRoot(rootState, 'sha256:root-a') === 'REGISTERED', 'fresh root must register');
invariant(registerRoot(rootState, 'sha256:root-a') === 'EXISTING', 'same root retry must be idempotent');
invariant(registerRoot(rootState, 'sha256:root-b') === 'REFUSE', 'consumed authorization must not mint another root');
invariant(registerRoot({
  authorizationStatus: 'indeterminate',
  boundDigest: 'sha256:root-a',
  registrationDigest: null,
}, 'sha256:root-b') === 'REFUSE', 'uncertain issuance consumption must not mint a different root');

// A proved pre-entry failure restores reserved capacity but retains the
// operation tombstone. Post-entry uncertainty consumes capacity.
function reconcile(operation, evidence) {
  if (operation.state !== 'reserved') return operation;
  if (evidence === 'authenticated_not_entered') {
    return { ...operation, state: 'not_entered', reserved: 0, consumed: 0, tombstone: true };
  }
  return { ...operation, state: 'indeterminate', reserved: 0, consumed: operation.amount, tombstone: true };
}

const reserved = { state: 'reserved', amount: 7, reserved: 7, consumed: 0, tombstone: true };
const restored = reconcile(reserved, 'authenticated_not_entered');
invariant(restored.state === 'not_entered' && restored.reserved === 0 && restored.consumed === 0 && restored.tombstone,
  'proved non-entry must restore capacity and retain a tombstone');
const uncertain = reconcile(reserved, 'unknown');
invariant(uncertain.state === 'indeterminate' && uncertain.reserved === 0 && uncertain.consumed === 7 && uncertain.tombstone,
  'post-entry uncertainty must consume capacity and retain a tombstone');

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

console.log('Bounded Capability -04: source, renders, relation-proof attack controls, metadata, and checksums PASS.');
