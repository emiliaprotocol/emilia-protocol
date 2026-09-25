#!/usr/bin/env node

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const packet = join(root, 'standards', 'staged', 'NEXT-GRID-CURTAILMENT-01');
const source = join(
  packet,
  'REVIEW-SOURCE',
  'draft-schrock-kintzele-grid-curtailment-01.xml',
);
const renderBase = join(packet, 'RENDERS', 'draft-schrock-kintzele-grid-curtailment-01');
const priorSource = join(
  root,
  'standards',
  'profiles',
  'NEXT-GRID-CURTAILMENT-00',
  'REVIEW-SOURCE',
  'draft-schrock-kintzele-grid-curtailment-00.xml',
);

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const read = (path) => readFileSync(path, 'utf8');
const expectText = (body, value, label = value) => {
  assert.ok(body.includes(value), `missing required text: ${label}`);
};

const xml = read(source);
const txt = read(`${renderBase}.txt`);
const html = read(`${renderBase}.html`);
const packetReadme = read(join(packet, 'README.md'));
const inputs = read(join(packet, 'OPEN-COAUTHOR-INPUTS.md'));

assert.equal(
  sha256(readFileSync(priorSource)),
  '0c656d9cbdb0701a23668420460a6d1143efcf74db8919f4a9c24f4fd5697ba6',
  'the published -00 review source changed',
);

expectText(xml, 'docName="draft-schrock-kintzele-grid-curtailment-01"');
expectText(xml, '<seriesInfo name="Internet-Draft" value="draft-schrock-kintzele-grid-curtailment-01"/>');
expectText(xml, '<date year="2026" month="September" day="24"/>');

const documentFront = xml.match(/<front>([\s\S]*?)<abstract>/)?.[1] ?? '';
expectText(documentFront, '<author fullname="Iman Schrock">');
expectText(documentFront, '<author fullname="Justin D Kintzele">');
expectText(documentFront, '<author fullname="Blake Morrison">');
expectText(documentFront, '<author fullname="Drew Dylan">');
expectText(documentFront, '<organization>Alter Meridian Pty Ltd</organization>');
expectText(documentFront, '<email>blake@truealter.com</email>');
expectText(documentFront, '<email>drew@truealter.com</email>');

for (const anchor of [
  'trust',
  'actuation-plan',
  'admission',
  'dispatch',
  'meter',
  'outcome',
  'safety',
  'action-state',
  'rdu101-example',
  'conformance',
]) {
  expectText(xml, `<section anchor="${anchor}">`, `section ${anchor}`);
}

for (const text of [
  'EMILIA supplies the exact-action',
  'GRACE then',
  'Both bindings',
  'It is downstream evidence about a dispatch that',
  'same communications card is in the same control',
  'hardwired interlocks are outside the GRACE authority and admission path',
  'MUST NOT</bcp14> invoke the same',
  'no outlet was',
  'does not report an energized actuation',
  'Vertiv Liebert GXT5-3000LVRT2UXLN',
  'firmware 1.9.3.0',
  'SNMPv3 AuthPriv',
  'SHA-1',
  'AES-128',
  '1.3.6.1.4.1.476.1.42.3.9.20.1.20.1.2.1.4365.2',
  'instrumented',
  'Modbus power meter through a separate channel and control domain',
  'There is no ambient',
  'effect_observed',
  'effect_divergent',
  'degraded_transport_timeout',
  'channel_unavailable',
  'not_invoked_refused',
  'summary label shown to an operator',
  'replace those facts in storage',
  'normalize either form into the other',
  'yield the same native-command digest',
  'neither it nor the admission is sufficient dispatch',
  'Consented and Attributable Agent Authority for Operational-Technology Control Actions',
  'thirteen behavioral cases',
]) {
  expectText(xml, text);
}

assert.ok(!xml.includes('qualifier encoding may identify'), 'DNP3 result remains non-deterministic');

expectText(xml, 'draft-morrison-ot-command-authority-02');
assert.ok(!xml.includes('draft-morrison-ot-command-authority-03'), 'references an unpublished -03');

const commandAuthority = xml.indexOf('[OT-COMMAND-AUTHORITY] action-specific proof + proposed action');
const emilia = xml.indexOf('EMILIA exact-action authority + admission + one-time consumption');
const cosa = xml.indexOf('COSA adapter -> RDU101 SNMPv3 SET');
const meter = xml.indexOf('separate Modbus domain -> independent meter readback');
const interlock = xml.indexOf('REPO / E-stop / branch protection: hardwired outside every path');
assert.ok(commandAuthority >= 0 && commandAuthority < emilia && emilia < cosa && cosa < meter && meter < interlock,
  'worked-example control order changed');

for (const value of [
  '[OT-COMMAND-AUTHORITY] action-specific proof + proposed action',
  'EMILIA exact-action authority + admission + one-time consumption',
  'Non-Normative RDU101 Worked Example',
  'does not report an energized actuation',
]) {
  expectText(txt, value);
}
expectText(html, 'Non-Normative RDU101 Worked Example');
assert.ok(statSync(`${renderBase}.pdf`).size > 100_000, 'PDF render is unexpectedly small');

expectText(packetReadme, 'review candidate');
expectText(packetReadme, 'has not been submitted');
for (const name of ['Blake', 'Drew', 'Justin', 'All four']) {
  expectText(inputs, name);
}

const manifest = read(join(packet, 'SHA256SUMS.txt')).trim().split('\n');
assert.ok(manifest.length >= 8, 'checksum manifest is incomplete');
for (const line of manifest) {
  const match = line.match(/^([0-9a-f]{64})  (.+)$/);
  assert.ok(match, `malformed checksum line: ${line}`);
  const file = join(packet, match[2]);
  assert.equal(sha256(readFileSync(file)), match[1], `checksum mismatch: ${relative(root, file)}`);
}

console.log('GRACE -01 staged candidate checks passed.');
