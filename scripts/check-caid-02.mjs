#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeCaid } from '../caid/impl/js/caid.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packet = path.join(root, 'standards/staged/NEXT-CAID-02');
const sourceRel = 'UPLOAD-THIS/draft-schrock-canonical-action-identifier-02.xml';
const textRel = 'RENDERS/draft-schrock-canonical-action-identifier-02.txt';
const htmlRel = 'RENDERS/draft-schrock-canonical-action-identifier-02.html';
const source = readFileSync(path.join(packet, sourceRel), 'utf8');
const text = readFileSync(path.join(packet, textRel), 'utf8');
const html = readFileSync(path.join(packet, htmlRel), 'utf8');
const registry = JSON.parse(readFileSync(path.join(root, 'caid/registry/action-types.json'), 'utf8'));

const assert = (condition, message) => {
  if (!condition) throw new Error(`CAID-02 packet: ${message}`);
};

assert(source.includes('docName="draft-schrock-canonical-action-identifier-02"'), 'wrong source revision');
assert(source.includes('category="std"'), 'candidate is not Standards Track');
assert(!source.includes('submissionType='), 'individual draft must not claim an adopted stream');
for (const current of [
  'draft-schrock-ep-authorization-receipts-10',
  'draft-schrock-action-evidence-boundary-03',
  'draft-schrock-ep-authorization-evidence-chain-05',
  'draft-thallapelly-oasnt-caid-01',
]) assert(source.includes(current), `missing current reference ${current}`);
for (const stale of [
  'draft-schrock-ep-authorization-receipts-08',
  'draft-schrock-action-evidence-boundary-00',
  'draft-schrock-ep-authorization-evidence-chain-04',
]) assert(!source.includes(stale), `stale reference ${stale}`);

const toolCall = registry.types.find((entry) => entry.action_type === 'tool.call.1');
assert(toolCall?.required_fields?.[0]?.name === 'tool', 'tool.call.1 does not require tool');
assert(toolCall?.required_fields?.[1]?.name === 'args', 'tool.call.1 does not require args');
assert(!toolCall.required_fields.some((field) => field.name === 'arguments'), 'tool.call.1 admits divergent arguments member');

const example = {
  action_type: 'tool.call.1',
  tool: 'payment.release',
  args: { amount_usd: 4000, beneficiary: 'vendor@example.com', memo: 'invoice 7781' },
};
const computed = computeCaid(example, { suite: 'jcs-sha256', definitions: registry.types });
const expected = 'caid:1:tool.call.1:jcs-sha256:v7Rbw0z8-twT08DTzQs82ME2Tg1cJsFGtH1gqgdeVjk';
assert(computed.caid === expected, 'tool.call.1 example does not reproduce the draft CAID');
const withoutWhitespace = (value) => value.replace(/\s+/g, '');
assert(withoutWhitespace(source).includes(expected), 'example CAID missing from source');
assert(withoutWhitespace(text).includes(expected), 'example CAID missing from TXT render');
assert(html.includes('v7Rbw0z8-twT08DTzQs82ME2Tg1cJsFG') && html.includes('tH1gqgdeVjk'), 'example CAID missing from HTML render');
assert(text.includes('Intended status: Standards Track'), 'TXT render has the wrong intended status');

const sums = readFileSync(path.join(packet, 'SHA256SUMS.txt'), 'utf8').trim().split('\n');
const expectedPaths = new Set([sourceRel, textRel, htmlRel]);
for (const line of sums) {
  const match = line.match(/^([0-9a-f]{64})  (.+)$/);
  assert(match, `malformed checksum line ${line}`);
  const [, expectedHash, relative] = match;
  assert(expectedPaths.delete(relative), `unexpected or duplicate checksum path ${relative}`);
  const actual = createHash('sha256').update(readFileSync(path.join(packet, relative))).digest('hex');
  assert(actual === expectedHash, `checksum mismatch for ${relative}`);
}
assert(expectedPaths.size === 0, `missing checksum path ${[...expectedPaths].join(', ')}`);

console.log('CAID-02: Standards Track source, current references, registry type, example, renders, and checksums PASS.');
