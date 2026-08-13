#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../standards/staged/', import.meta.url);

function invariant(condition, message) {
  if (!condition) throw new Error(`Emergency authority freeze drafts: ${message}`);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function readPacket(directory, basename) {
  const packet = new URL(`${directory}/`, root);
  invariant(
    JSON.stringify(readdirSync(packet).sort())
      === JSON.stringify(['README.md', 'RENDERS', 'SHA256SUMS.txt', 'UPLOAD-THIS', 'VALIDATION.md']),
    `${directory} packet inventory drifted`,
  );
  invariant(
    JSON.stringify(readdirSync(new URL('UPLOAD-THIS/', packet)).sort())
      === JSON.stringify([`${basename}.xml`]),
    `${directory} UPLOAD-THIS must contain exactly ${basename}.xml`,
  );
  invariant(
    JSON.stringify(readdirSync(new URL('RENDERS/', packet)).sort())
      === JSON.stringify([`${basename}.html`, `${basename}.txt`]),
    `${directory} RENDERS must contain exactly the TXT and HTML renderings`,
  );
  const artifacts = [
    `UPLOAD-THIS/${basename}.xml`,
    `RENDERS/${basename}.html`,
    `RENDERS/${basename}.txt`,
  ];
  const manifest = new Map(
    readFileSync(new URL('SHA256SUMS.txt', packet), 'utf8').trim().split('\n').map((line) => {
      const match = /^([a-f0-9]{64})  (.+)$/.exec(line);
      invariant(match, `${directory} has malformed checksum line ${line}`);
      return [match[2], match[1]];
    }),
  );
  invariant(
    JSON.stringify([...manifest.keys()].sort()) === JSON.stringify(artifacts.slice().sort()),
    `${directory} checksum inventory drifted`,
  );
  for (const artifact of artifacts) {
    invariant(
      sha256(readFileSync(new URL(artifact, packet))) === manifest.get(artifact),
      `${directory} checksum mismatch for ${artifact}`,
    );
  }
  return {
    xml: readFileSync(new URL(artifacts[0], packet), 'utf8').replace(/\s+/g, ' '),
    html: readFileSync(new URL(artifacts[1], packet), 'utf8').replace(/\s+/g, ' '),
    txt: readFileSync(new URL(artifacts[2], packet), 'utf8').replace(/\s+/g, ' '),
  };
}

const bcrName = 'draft-schrock-ep-bounded-capability-receipts-05';
const architectureName = 'draft-schrock-ep-architecture-03';
const bcr = readPacket('NEXT-BOUNDED-CAPABILITY-05', bcrName);
const architecture = readPacket('NEXT-ARCHITECTURE-03', architectureName);

for (const [name, packet] of [['BCR-05', bcr], ['Architecture-03', architecture]]) {
  invariant(packet.xml.includes(`docName="${name === 'BCR-05' ? bcrName : architectureName}"`), `${name} XML identity drifted`);
  invariant(packet.txt.includes(name === 'BCR-05' ? bcrName : architectureName), `${name} TXT identity drifted`);
  invariant(packet.html.includes(name === 'BCR-05' ? bcrName : architectureName), `${name} HTML identity drifted`);
}

for (const required of [
  'admission-control domain',
  'captured at reservation',
  'decrease <tt>reserved</tt>, and increase <tt>consumed</tt>',
  'budget again',
  'wrong-holder',
  'authority-instance digest',
  'does not require unused budget',
  'MUST NOT</bcp14> authorize restoration',
  'remaining lease lifetime plus the declared relative clock uncertainty and local enforcement delay',
  'not yet implemented',
  'Absence of a receipt proves only',
]) invariant(bcr.xml.includes(required), `BCR-05 missing ${required}`);

for (const required of [
  'Emergency Authority Freeze',
  'provider entry moves the admitted amount from reserved to consumed',
  'A cached status callback cannot close that race',
  'already-consumed authority to be unused or currently unexpired',
  'remaining lease lifetime plus relative clock uncertainty and local enforcement delay',
  'does not stop computation, undo effects',
  'Absence of a receipt in one examined evidence domain does not prove',
]) invariant(architecture.xml.includes(required), `Architecture-03 missing ${required}`);

for (const forbidden of [
  'exactly-once physical execution',
  'instant global kill',
  'No receipt = unauthorized action',
  'absence of a receipt is proof of unauthorized action',
  'cryptographic proof of when authority stopped',
  'The TLS of authority',
  'TCP/IP of consequential action',
]) {
  invariant(!bcr.xml.includes(forbidden), `BCR-05 contains forbidden overclaim ${forbidden}`);
  invariant(!architecture.xml.includes(forbidden), `Architecture-03 contains forbidden overclaim ${forbidden}`);
}

// Executable editorial decision model for the normative race table. This is
// not an implementation-conformance claim or a PostgreSQL concurrency test.
function state(total = 10) {
  return {
    domainPresent: true,
    domain: { status: 'active', epoch: 1 },
    budget: { total, reserved: 0, consumed: 0 },
    operations: new Map(),
    freezeEvents: new Map(),
  };
}

function reserve(model, { id, token, amount, deadline = 100 }) {
  if (!model.domainPresent || model.domain.status !== 'active') return 'refused';
  if (model.operations.has(id)) return 'refused';
  if (model.budget.total - model.budget.reserved - model.budget.consumed < amount) return 'refused';
  model.budget.reserved += amount;
  model.operations.set(id, { status: 'reserved', token, amount, epoch: model.domain.epoch, deadline, outcome: null });
  return 'reserved';
}

function beginProviderEntry(model, { id, token, now = 0 }) {
  const operation = model.operations.get(id);
  if (!operation) return 'refused';
  if (operation.token !== token) return 'refused';
  if (operation.status === 'provider_entered') return 'already_entered';
  if (operation.status !== 'reserved') return 'indeterminate';
  if (!model.domainPresent) return 'indeterminate';
  if (model.domain.status !== 'active' || operation.epoch !== model.domain.epoch || now >= operation.deadline) {
    operation.status = 'released';
    operation.outcome = 'not_entered';
    model.budget.reserved -= operation.amount;
    return 'not_entered';
  }
  operation.status = 'provider_entered';
  model.budget.reserved -= operation.amount;
  model.budget.consumed += operation.amount;
  return 'provider_entered';
}

function commitOutcome(model, { id, token, outcome }) {
  const operation = model.operations.get(id);
  if (!operation || operation.token !== token || operation.status !== 'provider_entered') return 'refused';
  operation.status = 'committed';
  operation.outcome = outcome;
  return 'committed';
}

function freeze(model, request) {
  if (!request.signatureValid) return { status: 'refused' };
  const prior = model.freezeEvents.get(request.operationId);
  if (prior) {
    if (prior.domain !== request.domain
        || prior.actionDigest !== request.actionDigest
        || prior.authorityDigest !== request.authorityDigest) return { status: 'refused' };
    return { ...prior.result, idempotent: true };
  }
  if (!request.currentlyValid || request.remaining < 1) return { status: 'refused' };
  if (model.domain.status === 'frozen') return { status: 'already_frozen', epoch: model.domain.epoch };
  request.remaining -= 1;
  model.domain.status = 'frozen';
  model.domain.epoch += 1;
  const result = { status: 'frozen', epoch: model.domain.epoch };
  model.freezeEvents.set(request.operationId, {
    domain: request.domain,
    actionDigest: request.actionDigest,
    authorityDigest: request.authorityDigest,
    result,
  });
  return result;
}

function restore(model, request) {
  if (!request.currentlyValid || request.action !== 'restore' || model.domain.status !== 'frozen') return 'refused';
  model.domain.status = 'active';
  model.domain.epoch += 1;
  return 'restored';
}

function freezeRequest(overrides = {}) {
  return {
    operationId: 'freeze-1',
    domain: 'domain-a',
    actionDigest: 'sha256:freeze-a',
    authorityDigest: 'sha256:bcr-a',
    signatureValid: true,
    currentlyValid: true,
    remaining: 1,
    ...overrides,
  };
}

{
  const model = state();
  freeze(model, freezeRequest());
  invariant(reserve(model, { id: 'op', token: 'owner', amount: 2 }) === 'refused', 'freeze-before-reservation must refuse');
}
{
  const model = state();
  reserve(model, { id: 'op', token: 'owner', amount: 2 });
  freeze(model, freezeRequest());
  invariant(beginProviderEntry(model, { id: 'op', token: 'owner' }) === 'not_entered', 'freeze after reservation must prove non-entry');
  invariant(model.budget.reserved === 0 && model.budget.consumed === 0, 'proved non-entry must release exactly once');
}
{
  const model = state();
  reserve(model, { id: 'op', token: 'owner', amount: 2 });
  invariant(beginProviderEntry(model, { id: 'op', token: 'owner' }) === 'provider_entered', 'provider entry must succeed while active');
  freeze(model, freezeRequest());
  invariant(model.operations.get('op').status === 'provider_entered', 'freeze must not relabel entered operation');
  invariant(model.budget.reserved === 0 && model.budget.consumed === 2, 'provider entry must consume exactly once');
  commitOutcome(model, { id: 'op', token: 'owner', outcome: 'indeterminate' });
  invariant(model.budget.consumed === 2, 'outcome commit must not double debit');
}
{
  const model = state();
  reserve(model, { id: 'op', token: 'owner', amount: 2 });
  freeze(model, freezeRequest());
  invariant(beginProviderEntry(model, { id: 'op', token: 'attacker' }) === 'refused', 'wrong holder must refuse');
  invariant(model.operations.get('op').status === 'reserved' && model.budget.reserved === 2, 'wrong holder must retain owner reservation');
}
{
  const model = state();
  reserve(model, { id: 'op', token: 'owner', amount: 2 });
  beginProviderEntry(model, { id: 'op', token: 'owner' });
  freeze(model, freezeRequest());
  invariant(beginProviderEntry(model, { id: 'op', token: 'owner' }) === 'already_entered', 'entered operation must never become not_entered');
}
{
  const model = state();
  reserve(model, { id: 'op', token: 'owner', amount: 2 });
  freeze(model, freezeRequest());
  restore(model, { currentlyValid: true, action: 'restore' });
  invariant(beginProviderEntry(model, { id: 'op', token: 'owner' }) === 'not_entered', 'restore must not revive an old epoch');
}
{
  const model = state();
  reserve(model, { id: 'op', token: 'owner', amount: 2 });
  beginProviderEntry(model, { id: 'op', token: 'owner' });
  freeze(model, freezeRequest());
  restore(model, { currentlyValid: true, action: 'restore' });
  invariant(commitOutcome(model, { id: 'op', token: 'owner', outcome: 'executed' }) === 'committed', 'pre-freeze entered operation must remain reconcilable');
}
{
  const model = state();
  const request = freezeRequest();
  const first = freeze(model, request);
  const retry = freeze(model, { ...request, currentlyValid: false, remaining: 0 });
  invariant(first.status === 'frozen' && retry.status === 'frozen' && retry.idempotent, 'lost-response exact retry must resolve after consumption');
  invariant(request.remaining === 0 && model.domain.epoch === 2, 'exact retry must spend and advance epoch once');
}
{
  const model = state();
  freeze(model, freezeRequest());
  const second = freeze(model, freezeRequest({ operationId: 'freeze-2', authorityDigest: 'sha256:bcr-b' }));
  invariant(second.status === 'already_frozen' && model.domain.epoch === 2 && model.freezeEvents.size === 1, 'distinct request against frozen domain must not advance or append transition');
}
{
  const model = state();
  freeze(model, freezeRequest());
  const conflict = freeze(model, freezeRequest({ signatureValid: true, currentlyValid: true, authorityDigest: 'sha256:attacker' }));
  invariant(conflict.status === 'refused', 'same operation id under different authority must refuse');
}
{
  const model = state();
  const invalid = freeze(model, freezeRequest({ signatureValid: false }));
  invariant(invalid.status === 'refused' && !('epoch' in invalid), 'invalid authority must not reveal idempotency state');
}

const staleAdmissionWindow = ({ remainingLease, relativeClockUncertainty, localEnforcementDelay }) => (
  remainingLease + relativeClockUncertainty + localEnforcementDelay
);
invariant(staleAdmissionWindow({ remainingLease: 30, relativeClockUncertainty: 2, localEnforcementDelay: 1 }) === 33, 'edge stale-admission window must add uncertainty and enforcement delay');

console.log('Emergency authority freeze draft packets: PASS');
