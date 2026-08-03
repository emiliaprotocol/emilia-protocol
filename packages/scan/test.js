// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, linkSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { classifyAction, scanActions, KNOWN_CATEGORIES, HIGH_RISK_ACTION_PACKS } from './index.js';

test('STRUCTURAL: every category maps to a real risk pack (no guessed ids)', () => {
  const realIds = new Set(HIGH_RISK_ACTION_PACKS.map((p) => p.id));
  for (const cat of KNOWN_CATEGORIES) {
    assert.ok(realIds.has(cat), `category "${cat}" does not match any risk-pack id — it would lose its tier and required_fields`);
  }
});

test('tiers are correct, not defaulted (quorum stays quorum)', () => {
  assert.equal(classifyAction({ name: 'grantAdminRole', description: 'give admin privileges' }).assurance_class, 'quorum');
  assert.equal(classifyAction({ name: 'overrideRegulatedDecision', description: 'override a benefits decision' }).assurance_class, 'quorum');
  const del = classifyAction({ name: 'deleteCustomer', description: 'permanently remove a record' });
  assert.equal(del.category, 'records.delete');
  assert.ok(del.required_fields.includes('before_state_hash'), 'record delete must bind the pre-state, not fall back to just action_type');
});
import { HIGH_RISK_ACTION_PACKS as VENDORED } from './risk-packs.js';
// Monorepo-only: gate is a sibling here, never shipped with this package. This
// guards the vendored risk packs against drifting from the authoritative Gate copy.
import { HIGH_RISK_ACTION_PACKS as GATE } from '../gate/action-packs.js';

test('DRIFT GUARD: vendored risk-packs match the authoritative Gate action packs', () => {
  assert.deepEqual(JSON.parse(JSON.stringify(VENDORED)), JSON.parse(JSON.stringify(GATE)),
    'packages/scan/risk-packs.js drifted from packages/gate/action-packs.js — re-sync it');
});

test('recognized high-risk actions are gated at the right tier', () => {
  const wire = classifyAction({ name: 'sendWire', description: 'outgoing wire to a beneficiary' });
  assert.equal(wire.decision, 'gate');
  assert.equal(wire.receipt_required, true);
  assert.equal(wire.assurance_class, 'class_a');

  const deploy = classifyAction({ name: 'deployToProduction', description: 'ship build to prod' });
  assert.equal(deploy.decision, 'gate');
  assert.equal(deploy.assurance_class, 'quorum');

  const bank = classifyAction({ name: 'updateBeneficiaryBankDetails', description: 'change destination account for a payee' });
  assert.equal(bank.decision, 'gate');
  assert.equal(bank.category, 'money_movement.bank_details_change', 'payee/beneficiary must land in bank-detail-change, not generic release');
});

test('read-only actions pass through', () => {
  assert.equal(classifyAction({ name: 'getAccountBalance' }).decision, 'pass_through');
  assert.equal(classifyAction({ name: 'searchTransactions' }).decision, 'pass_through');
  assert.equal(classifyAction({ name: 'summarizeTicket', annotations: { readOnlyHint: true } }).decision, 'pass_through');
});

test('presenter-authored readOnlyHint cannot launder a dangerous or ambiguous action', () => {
  const payment = classifyAction({ name: 'release_payment', annotations: { readOnlyHint: true } });
  assert.equal(payment.decision, 'gate');
  assert.match(payment.reason, /conflicting readOnlyHint ignored/);

  const opaque = classifyAction({ name: 'frobnicate', annotations: { readOnlyHint: true } });
  assert.equal(opaque.decision, 'review_fail_closed');
  assert.equal(opaque.receipt_required, true);
});

test('THE HONEST CORE: a mutating action of unrecognized category fails closed, never waved through', () => {
  const c = classifyAction({ name: 'reconcileLedger', description: 'reconcile ledger and post adjustments' });
  assert.equal(c.decision, 'review_fail_closed');
  assert.equal(c.receipt_required, true, 'an unrecognized mutator MUST default to requiring a receipt');
});

test('MCP destructiveHint annotation is honored', () => {
  const c = classifyAction({ name: 'rotateApiKey', annotations: { destructiveHint: true } });
  assert.equal(c.decision, 'gate');
  assert.equal(c.receipt_required, true);
});

test('the emitted manifest fails closed on every discovered action', () => {
  const rep = scanActions([
    { name: 'getBalance' },
    { name: 'sendWire', description: 'wire funds' },
    { name: 'reconcileLedger', description: 'post adjustments' },
  ]);
  const discovered = rep.manifest.actions.filter((a) => String(a.id).startsWith('discovered.'));
  assert.ok(discovered.length >= 2, 'both mutating actions should be in the manifest');
  assert.ok(discovered.every((a) => a.receipt_required === true), 'no discovered action may be receipt_required:false');
});

test('malformed or oversized action surfaces are refused', () => {
  assert.throws(() => scanActions([null]), /each action/);
  assert.throws(() => scanActions([{ name: 'x'.repeat(257) }]), /bounded/);
  assert.throws(() => scanActions(Array.from({ length: 10_001 }, () => ({ name: 'get_x' }))), /at most/);
});

test('duplicate, colliding, and source-confusing tool names are refused', () => {
  assert.throws(() => scanActions([{ name: 'wire-now' }, { name: 'wire_now' }]), /normalized action name collision/);
  assert.throws(() => scanActions([{ name: 'same' }, { name: 'same' }]), /duplicate action name/);
  for (const name of ['__proto__', 'prototype', 'constructor', 'bad\u202Ename', 'bad\u0000name']) {
    assert.throws(() => scanActions([{ name }]), /action name is unsafe/);
  }
});

test('codemod refuses duplicate JSON members and symlinked output paths', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-scan-'));
  const duplicate = join(dir, 'duplicate.json');
  writeFileSync(duplicate, '{"tools":[],"tools":[{"name":"sendWire"}]}');
  const duplicateRun = spawnSync(process.execPath, [join(import.meta.dirname, 'codemod.mjs'), duplicate], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.notEqual(duplicateRun.status, 0);
  assert.match(`${duplicateRun.stdout}${duplicateRun.stderr}`, /duplicate object member/);

  const target = join(dir, 'elsewhere');
  const link = join(dir, 'emilia');
  symlinkSync(target, link, 'dir');
  const symlinkRun = spawnSync(process.execPath, [join(import.meta.dirname, 'codemod.mjs'), '--sample', '--out', 'emilia', '--apply', '--force'], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.notEqual(symlinkRun.status, 0);
  assert.match(`${symlinkRun.stdout}${symlinkRun.stderr}`, /symlinked output path/);
});

test('codemod refuses symlinked input and hard-linked output leaves', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-scan-links-'));
  const declaration = join(dir, 'tools.json');
  const inputLink = join(dir, 'linked-tools.json');
  writeFileSync(declaration, '[{"name":"deleteCustomer"}]');
  symlinkSync(declaration, inputLink);

  const linkedInputRun = spawnSync(process.execPath, [join(import.meta.dirname, 'codemod.mjs'), inputLink], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.notEqual(linkedInputRun.status, 0);
  assert.match(`${linkedInputRun.stdout}${linkedInputRun.stderr}`, /symlinked input/);

  const first = spawnSync(process.execPath, [join(import.meta.dirname, 'codemod.mjs'), '--sample', '--apply'], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.equal(first.status, 0, `${first.stdout}\n${first.stderr}`);
  const external = join(dir, 'must-not-change.txt');
  const leaf = join(dir, 'emilia', 'guard.mjs');
  writeFileSync(external, 'preserve-me');
  unlinkSync(leaf);
  linkSync(external, leaf);

  const hardLinkRun = spawnSync(process.execPath, [join(import.meta.dirname, 'codemod.mjs'), '--sample', '--apply', '--force'], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.notEqual(hardLinkRun.status, 0);
  assert.match(`${hardLinkRun.stdout}${hardLinkRun.stderr}`, /hard-linked output file/);
  assert.equal(readFileSync(external, 'utf8'), 'preserve-me');
});

test('scan protect routes to the dry-run hardener without writing files', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-protect-dry-'));
  const run = spawnSync(process.execPath, [join(import.meta.dirname, 'cli.mjs'), 'protect', '--sample'], {
    cwd: dir,
    encoding: 'utf8',
  });

  assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
  assert.match(run.stdout, /DRY RUN — nothing written/);
  assert.match(run.stdout, /would create: emilia\/guard\.mjs/);
  assert.match(run.stdout, /would create: emilia\/verify-setup\.mjs/);
  assert.equal(spawnSync(process.execPath, ['-e', "import('node:fs').then(fs => process.exit(fs.existsSync('emilia') ? 1 : 0))"], {
    cwd: dir,
  }).status, 0, 'dry-run must not create the output directory');
});

test('generated MCP protection separates durable production state from the explicit local check', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-protect-apply-'));
  const run = spawnSync(process.execPath, [
    join(import.meta.dirname, 'cli.mjs'),
    'protect',
    '--sample',
    '--out',
    'emilia',
    '--apply',
  ], {
    cwd: dir,
    encoding: 'utf8',
  });

  assert.equal(run.status, 0, `${run.stdout}\n${run.stderr}`);
  const guardPath = join(dir, 'emilia', 'guard.mjs');
  const checkPath = join(dir, 'emilia', 'verify-setup.mjs');
  const integrationPath = join(dir, 'emilia', 'INTEGRATION.md');
  const guardSource = readFileSync(guardPath, 'utf8');
  const checkSource = readFileSync(checkPath, 'utf8');
  const integration = readFileSync(integrationPath, 'utf8');
  const productionSource = guardSource.split('export function guardDispatchDemo')[0];

  assert.match(productionSource, /runtime\.ledger/);
  assert.match(productionSource, /runtime\.store/);
  assert.doesNotMatch(productionSource, /allowEphemeralLedger:\s*true/,
    'the production wrapper must never opt into ephemeral provenance');
  assert.match(guardSource, /export function guardDispatchDemo[\s\S]*allowEphemeralLedger:\s*true/,
    'the standalone local check must make its ephemeral state explicit in its helper');
  assert.match(checkSource, /Ephemeral state here is intentional and demo-only/);
  assert.match(integration, /durable provenance ledger/i);
  assert.match(integration, /shared atomic consumption store/i);

  const scope = join(dir, 'node_modules', '@emilia-protocol');
  mkdirSync(scope, { recursive: true });
  cpSync(join(import.meta.dirname, '..', 'mcp-guard'), join(scope, 'mcp-guard'), { recursive: true });
  cpSync(join(import.meta.dirname, '..', 'require-receipt'), join(scope, 'require-receipt'), { recursive: true });

  const imported = await import(`${new URL(`file://${guardPath}`).href}?test=${Date.now()}`);
  assert.throws(
    () => imported.guardDispatch(async () => ({ ok: true })),
    /durable provenance ledger and shared atomic consumption store/,
  );
  const methods = {
    async reserve() { return true; },
    async commit() { return true; },
    async release() { return true; },
  };
  const secureStore = {
    ...methods,
    durable: true,
    ownershipFenced: true,
    permanentConsumption: true,
  };
  assert.throws(
    () => imported.guardDispatch(async () => ({ ok: true }), {
      ledger: { durable: true },
      store: { ...methods, durable: false, ownershipFenced: true, permanentConsumption: true },
      trustedKeys: ['pinned-key'],
    }),
    /durable, ownership-fenced, permanent consumption store/,
  );
  assert.throws(
    () => imported.guardDispatch(async () => ({ ok: true }), {
      ledger: { durable: true },
      store: secureStore,
      trustedKeys: [],
    }),
    /at least one pinned trusted key/,
  );

  const check = spawnSync(process.execPath, [checkPath], { cwd: dir, encoding: 'utf8' });
  assert.equal(check.status, 0, `${check.stdout}\n${check.stderr}`);
  assert.match(check.stdout, /EMILIA PROTECT CHECK: PASS/);
  assert.match(check.stdout, /underlying handler was not called/);

  const productionDemo = spawnSync(process.execPath, [checkPath], {
    cwd: dir,
    encoding: 'utf8',
    env: { ...process.env, NODE_ENV: 'production' },
  });
  assert.notEqual(productionDemo.status, 0);
  assert.match(`${productionDemo.stdout}${productionDemo.stderr}`, /demo guard is unavailable in production/);
});
