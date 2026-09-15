// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { parseArguments, SOURCE_LOCK, verifyDocumentBytes, verifyPinnedSources } from './verify-sources.mjs';

const bytes = Buffer.from('fixture bytes\n', 'utf8');
const pin = { name: 'fixture', url: 'https://example.invalid/fixture', bytes: bytes.length,
  sha256: createHash('sha256').update(bytes).digest('hex') };

test('hash verification checks bytes, not the existence of a declared pin', () => {
  assert.equal(verifyDocumentBytes(pin, bytes).passed, true);
  assert.equal(verifyDocumentBytes(pin, Buffer.from('Fixture bytes\n')).passed, false);
  assert.equal(verifyDocumentBytes(pin, Buffer.concat([bytes, Buffer.from('\n')])).passed, false);
  assert.equal(verifyDocumentBytes({ ...pin, bytes: pin.bytes + 1 }, bytes).passed, false);
  assert.equal(verifyDocumentBytes({ ...pin, sha256: '0'.repeat(64) }, bytes).passed, false);
});

test('failed downloads and substituted documents cannot produce a passing report', async () => {
  const unavailable = await verifyPinnedSources(async () => { throw new Error('offline'); });
  assert.equal(unavailable.passed, false);
  assert.equal(unavailable.checks.length, 2);
  assert.equal(unavailable.checks.every((check) => !check.passed), true);
  const substituted = await verifyPinnedSources(async () => bytes);
  assert.equal(substituted.passed, false);
  assert.equal(substituted.checks.every((check) => !check.passed), true);
});

test('source lock retains separate revisions and historical external credit', () => {
  assert.equal(SOURCE_LOCK.draft.name, 'draft-correctover-ccs-09');
  assert.equal(SOURCE_LOCK.previous_draft.name, 'draft-correctover-ccs-08');
  assert.notEqual(SOURCE_LOCK.draft.sha256, SOURCE_LOCK.previous_draft.sha256);
  assert.equal(SOURCE_LOCK.historical_credit.draft, 'draft-correctover-ccs-05');
  for (const source of [SOURCE_LOCK.draft, SOURCE_LOCK.previous_draft]) {
    assert.equal(source.url, `https://www.ietf.org/archive/id/${source.name}.txt`);
    assert.match(source.sha256, /^[a-f0-9]{64}$/);
    assert.ok(source.bytes > 0);
  }
});

test('network access is explicit and unknown or conflicting options are refused', () => {
  assert.deepEqual(parseArguments(['--online']), { mode: 'online' });
  assert.equal(parseArguments(['--directory', '.']).mode, 'directory');
  for (const args of [[], ['--directory'], ['--directory', '--online'], ['--online', '--write'],
    ['--online', '--directory', '.']]) assert.throws(() => parseArguments(args));
});
