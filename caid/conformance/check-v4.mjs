#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Proves that corpus version 6 carries version 4 forward across the URI
// scheme migration, from the two
// files alone (no oracle, no implementation):
//   - history/vectors.v4.json is byte-identical to the version 4 corpus
//     whose digest vectors.json records;
//   - every version 4 vector is present in version 6 under the same id and
//     kind, with the same definitions and suite, with a valid `caid:`
//     argument represented as the corresponding `canactid:` argument, and with its
//     object as JSON text whose tokens are exactly the version 4 tokens;
//   - every version 4 vector that computed a CAID expects the same digest
//     under the `canactid:` scheme; the frozen historical `caid:` spelling
//     remains byte-identical and is covered by the explicit legacy verifier;
//   - every other version 4 result is unchanged except the six vectors the
//     version 5 envelope names, and the only other differences are the
//     additive members (definition_sha256, details);
//   - the same for mapping corpus version 1 carried through current version 3.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { minify, rawSpans } from './tools/jsontext.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const read = (rel) => readFileSync(path.join(ROOT, rel));
const sha = (buf) => 'sha256:' + createHash('sha256').update(buf).digest('hex');
const failures = [];
const fail = (m) => failures.push(m);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

const current = JSON.parse(read('caid/conformance/vectors.json').toString('utf8'));
const entry = current.previous_versions.find((p) => p.version === 4);
const v4Bytes = read(entry.history);
if (sha(v4Bytes) !== entry.sha256) fail(`${entry.history} does not match the recorded version 4 digest ${entry.sha256}`);
const v4Text = v4Bytes.toString('utf8');
const v4 = JSON.parse(v4Text);
const spans = rawSpans(v4Text, (p) => p.length === 4 && p[0] === 'vectors' && p[2] === 'input' && p[3] === 'object');
const byId = new Map(current.vectors.map((v) => [v.id, v]));
const currentIdentifier = (value) => typeof value === 'string' && value.startsWith('caid:')
  ? `canactid:${value.slice('caid:'.length)}` : value;
const CHANGED = new Map([
  ['refuse-lone-surrogate-string-value', ['malformed_json']],
  ['refuse-lone-surrogate-member-name', ['malformed_json']],
  ['verify-lone-surrogate-against-replacement-caid', ['malformed_json']],
  ['refuse-suite-unregistered', ['unknown_suite']],
  ['refuse-suite-unregistered-unchecked-digest', ['unknown_suite']],
  ['verify-malformed-unregistered-suite', ['unknown_suite']],
]);
let reproduced = 0;
v4.vectors.forEach((old, index) => {
  const now = byId.get(old.id);
  if (!now) { fail(`version 4 vector ${old.id} is missing from version 6`); return; }
  if (now.kind !== old.kind) fail(`${old.id}: kind ${now.kind}, version 4 ${old.kind}`);
  if (old.kind !== 'parse' && !same(now.definitions, old.definitions)) fail(`${old.id}: definitions differ from version 4`);
  if (!same(now.input.suite, old.input.suite)) fail(`${old.id}: input.suite differs from version 4`);
  if (!same(now.input.caid, currentIdentifier(old.input.caid))) fail(`${old.id}: input.caid is not the exact current-scheme form of version 4`);
  if (old.kind === 'compute' || old.kind === 'verify') {
    const raw = spans.get(JSON.stringify(['vectors', index, 'input', 'object']));
    if (now.input.json !== minify(raw)) fail(`${old.id}: input.json is not the version 4 object's tokens`);
  }
  const changed = CHANGED.get(old.id);
  if (old.kind === 'compute') {
    if (old.expect.caid !== undefined) {
      if (now.expect.caid !== currentIdentifier(old.expect.caid) || now.expect.digest !== old.expect.digest) fail(`${old.id}: version 4 digest is not expected under the current canactid scheme`);
      else reproduced += 1;
    } else if (!same(now.expect.refusals, changed ?? old.expect.refusals)) fail(`${old.id}: refusals changed without a named rule`);
  } else if (old.kind === 'verify') {
    if (now.expect.valid !== (changed ? false : old.expect.valid) || !same(now.expect.reasons, changed ?? old.expect.reasons)) fail(`${old.id}: verification result changed without a named rule`);
  } else if (!same(now.expect, changed ? { ok: false, refusals: changed } : old.expect)) fail(`${old.id}: parse result changed without a named rule`);
});
const computed = v4.vectors.filter((v) => v.kind === 'compute' && v.expect.caid !== undefined).length;
if (reproduced !== computed) fail(`${reproduced} of ${computed} version 4 CAIDs carried forward`);

// Mapping version 1 -> current version 3.
const currentMapping = JSON.parse(read('caid/conformance/mapping-vectors.json').toString('utf8'));
const m1Entry = currentMapping.previous_versions.find((p) => p.version === 1);
const m1Bytes = read(m1Entry.history);
if (sha(m1Bytes) !== m1Entry.sha256) fail(`${m1Entry.history} does not match the recorded mapping version 1 digest`);
const m1 = JSON.parse(m1Bytes.toString('utf8'));
const currentMappingById = new Map(currentMapping.vectors.map((v) => [v.id, v]));
for (const old of m1.vectors) {
  const now = currentMappingById.get(old.id);
  if (!now) { fail(`mapping vector ${old.id} is missing from version 3`); continue; }
  for (const k of ['left', 'right', 'mutations', 'repin_after_mutation']) if (!same(now[k], old[k])) fail(`mapping ${old.id}: ${k} differs from version 1`);
  if (now.change_since_v1) continue;
  if (now.expect.verdict !== old.expect.verdict) fail(`mapping ${old.id}: verdict changed`);
  if (old.expect.reasons && !same(now.expect.reasons, old.expect.reasons)) fail(`mapping ${old.id}: reasons changed`);
  if (old.expect.reason_contains && !now.expect.reasons.includes(old.expect.reason_contains)) fail(`mapping ${old.id}: lost ${old.expect.reason_contains}`);
}

if (failures.length) {
  for (const f of failures) console.error(`FAIL ${f}`);
  process.exit(1);
}
console.log(`PASS version 4 carried forward: ${v4.vectors.length} vectors, ${reproduced} digests preserved under canactid:, ${CHANGED.size} results changed by named -04 rules; mapping version 1: ${m1.vectors.length} vectors carried forward`);
