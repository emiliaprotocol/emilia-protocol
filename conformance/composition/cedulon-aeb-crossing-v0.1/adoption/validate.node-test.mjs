// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { COMMANDS } from './independent-runner.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));

function text(name) {
  return readFileSync(resolve(HERE, name), 'utf8');
}

test('independent runner exposes only the fixed reviewed command set', () => {
  assert.deepEqual(COMMANDS, [
    ['npm', '--prefix', 'packages/verify', 'run', 'build'],
    ['node', '--test', 'conformance/composition/cedulon-aeb-crossing-v0.1/adoption/validate.node-test.mjs'],
    ['node', '--test', 'conformance/composition/cedulon-aeb-crossing-v0.1/run.test.mjs'],
    ['node', 'conformance/composition/cedulon-aeb-crossing-v0.1/run.mjs'],
    ['node', 'packages/verify/cli.js', 'crossing-lab', 'run', 'conformance/composition/cedulon-aeb-crossing-v0.1/workspace'],
  ]);
  assert.equal(Object.isFrozen(COMMANDS), true);
  assert.equal(COMMANDS.every(Object.isFrozen), true);
});

test('attestation template is closed around reproduction, identity, and claim limits', () => {
  const template = JSON.parse(text('independent-run-attestation.template.json'));
  assert.deepEqual(Object.keys(template), [
    '@version', 'profile', 'run_record_sha256', 'run_record_report_digest',
    'reviewed_commit', 'runner', 'independence_statement', 'exceptions',
    'claim_boundary', 'signed_at', 'signature_scheme', 'signature',
  ]);
  assert.equal(template.profile, 'cedulon-aeb-crossing-v0.1');
  assert.deepEqual(Object.values(template.claim_boundary), [false, false, false, false, false, false]);
});

test('pilot runbook names both replay fences, exact fields, and fail-closed operations', () => {
  const runbook = text('buyer-gate-pilot-runbook.md');
  const semanticDocs = `${runbook}\n${text('README.md')}\n${text('native-author-confirmation.md')}`;
  for (const value of ['amount', 'currency', 'payee', 'tool', 'nonce', 'manifestHash']) {
    assert.match(runbook, new RegExp(`\\b${value}\\b`));
  }
  assert.match(runbook, /\(`issuer_key_id`, `consumer_deployment_id`, `singleUseId`\)/);
  assert.match(runbook, /\(`issuer_key_id`, `consumer_deployment_id`, `nonce`\)/);
  for (const requirement of [
    'buyer-controlled source', 'PROVIDER_ENTRY_STARTED', 'INDETERMINATE',
    'never released', 'newly issued Decision Token', 'fresh identities',
    'Deny bypasses', 'Restart', 'Reconciliation',
  ]) assert.ok(runbook.includes(requirement), requirement);
  assert.doesNotMatch(semanticDocs, /may release|can release|release either fence/i);
  assert.match(semanticDocs, /first settlement attempt[\s\S]*fail-closed abort/);
  assert.match(semanticDocs, /`NOT_ENTERED`[\s\S]*never (?:restores|released)/);
  assert.match(runbook, /same database transaction[\s\S]*`RESERVED`/);
  assert.match(runbook, /`PROVIDER_ENTRY_STARTED`[\s\S]*before any provider I\/O/);
});

test('cover sheet and author checklist retain the non-claim boundary', () => {
  const combined = `${text('README.md')}\n${text('native-author-confirmation.md')}`;
  for (const limit of [
    'endorsement', 'certification', 'authorization', 'production deployment',
    'settlement', 'payment', 'finality', 'general protocol security',
  ]) assert.match(combined.toLowerCase(), new RegExp(limit));
});
