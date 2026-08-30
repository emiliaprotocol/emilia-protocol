// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { classifyAction, scanActions, KNOWN_CATEGORIES, HIGH_RISK_ACTION_PACKS } from './index.js';

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function installLocalMcpGuard(dir) {
  const scope = join(dir, 'node_modules', '@emilia-protocol');
  mkdirSync(scope, { recursive: true });
  cpSync(join(import.meta.dirname, '..', 'mcp-guard'), join(scope, 'mcp-guard'), { recursive: true });
  cpSync(join(import.meta.dirname, '..', 'require-receipt'), join(scope, 'require-receipt'), { recursive: true });
  cpSync(join(import.meta.dirname, '..', 'verify'), join(scope, 'verify'), { recursive: true });
}

function expectedScaffoldBinding(dir) {
  const files = ['guard.mjs', 'verify-setup.mjs', 'INTEGRATION.md'].map((file) => ({
    file,
    sha256: sha256(readFileSync(join(dir, 'emilia', file))),
  }));
  return { sha256: sha256(Buffer.from(JSON.stringify(files), 'utf8')), files };
}

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
  assert.equal(wire.category, 'money_movement.release');
  assert.ok(wire.required_fields.includes('amount_usd'), 'a wire must bind payment fields, not bank-change fields');

  const deploy = classifyAction({ name: 'deployToProduction', description: 'ship build to prod' });
  assert.equal(deploy.decision, 'gate');
  assert.equal(deploy.assurance_class, 'quorum');

  const bank = classifyAction({ name: 'updateBeneficiaryBankDetails', description: 'change destination account for a payee' });
  assert.equal(bank.decision, 'gate');
  assert.equal(bank.category, 'money_movement.bank_details_change', 'change intent plus payee/beneficiary must land in bank-detail-change');

  assert.equal(
    classifyAction({ name: 'getBeneficiary', description: 'read the current beneficiary' }).decision,
    'pass_through',
    'mentioning a beneficiary without change intent must not become a bank-detail change',
  );
  assert.equal(
    classifyAction({ name: 'getPayeeAsset', description: 'read the current payee asset' }).decision,
    'pass_through',
    'pay inside payee and set inside asset must not create payment or change intent',
  );
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
  assert.throws(
    () => scanActions([{ name: 'sendWire', http_method: 'post' }], { source: 'openapi' }),
    /OpenAPI action requires a bounded HTTP method and route path/,
  );
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

test('scan and protect refuse oversized, non-regular, and ancestor-symlinked inputs before parsing', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-scan-bounded-read-'));
  const oversized = join(dir, 'oversized.json');
  writeFileSync(oversized, Buffer.alloc((8 * 1024 * 1024) + 1, 0x20));
  for (const args of [[oversized], ['protect', oversized]]) {
    const run = spawnSync(process.execPath, [join(import.meta.dirname, 'cli.mjs'), ...args], {
      cwd: dir,
      encoding: 'utf8',
      timeout: 2_000,
    });
    assert.notEqual(run.status, 0);
    assert.match(`${run.stdout}${run.stderr}`, /exceeds 8388608 bytes/i);
  }

  const nonRegular = spawnSync(process.execPath, [join(import.meta.dirname, 'cli.mjs'), '/dev/zero'], {
    cwd: dir,
    encoding: 'utf8',
    timeout: 2_000,
  });
  assert.notEqual(nonRegular.status, 0);
  assert.equal(nonRegular.signal, null, 'non-regular input must be rejected, not timeout-killed');
  assert.match(`${nonRegular.stdout}${nonRegular.stderr}`, /non-regular input/i);

  const realParent = join(dir, 'real-parent');
  const linkedParent = join(dir, 'linked-parent');
  mkdirSync(realParent);
  writeFileSync(join(realParent, 'tools.json'), '[{"name":"getAccountBalance"}]');
  symlinkSync(realParent, linkedParent, 'dir');
  const linked = spawnSync(process.execPath, [join(import.meta.dirname, 'cli.mjs'), join(linkedParent, 'tools.json')], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.notEqual(linked.status, 0);
  assert.match(`${linked.stdout}${linked.stderr}`, /symlinked input path component/i);
});

test('scan and protect reject unknown options with usage status', () => {
  for (const args of [['--sample', '--definitely-unknown'], ['protect', '--sample', '--definitely-unknown']]) {
    const run = spawnSync(process.execPath, [join(import.meta.dirname, 'cli.mjs'), ...args], {
      encoding: 'utf8',
    });
    assert.equal(run.status, 64, `${args.join(' ')}\n${run.stdout}\n${run.stderr}`);
    assert.match(run.stderr, /unknown option: --definitely-unknown/);
  }
});

test('protect installs atomically and force replaces only an exact generated Gate Starter', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-protect-atomic-'));
  const nested = spawnSync(process.execPath, [
    join(import.meta.dirname, 'cli.mjs'), 'protect', '--sample', '--out', 'nested/emilia', '--apply',
  ], { cwd: dir, encoding: 'utf8' });
  assert.notEqual(nested.status, 0);
  assert.match(`${nested.stdout}${nested.stderr}`, /portable direct-child slug|refusing nested output directory/i);
  assert.equal(existsSync(join(dir, 'nested')), false);

  mkdirSync(join(dir, 'emilia'), { mode: 0o700 });
  writeFileSync(join(dir, 'emilia', 'stale.txt'), 'must never be treated as a generated Gate Starter');
  const arbitrary = spawnSync(process.execPath, [
    join(import.meta.dirname, 'cli.mjs'), 'protect', '--sample', '--out', 'emilia', '--apply', '--force',
  ], { cwd: dir, encoding: 'utf8' });
  assert.notEqual(arbitrary.status, 0);
  assert.match(`${arbitrary.stdout}${arbitrary.stderr}`, /Gate Starter marker|current Gate Starter marker schema/i);
  assert.equal(readFileSync(join(dir, 'emilia', 'stale.txt'), 'utf8'), 'must never be treated as a generated Gate Starter');

  const first = spawnSync(process.execPath, [
    join(import.meta.dirname, 'cli.mjs'), 'protect', '--sample', '--out', 'starter', '--apply',
  ], { cwd: dir, encoding: 'utf8' });
  assert.equal(first.status, 0, `${first.stdout}\n${first.stderr}`);
  const replaced = spawnSync(process.execPath, [
    join(import.meta.dirname, 'cli.mjs'), 'protect', '--sample', '--out', 'starter', '--apply', '--force',
  ], { cwd: dir, encoding: 'utf8' });
  assert.equal(replaced.status, 0, `${replaced.stdout}\n${replaced.stderr}`);
  assert.deepEqual(readdirSync(join(dir, 'starter')).sort(), [
    '.emilia-gate-starter.json',
    'INTEGRATION.md', 'action-control.manifest.json', 'authority-map.html', 'guard.mjs', 'verify-setup.mjs',
  ]);
  assert.equal(statSync(join(dir, 'starter', '.emilia-gate-starter.json')).mode & 0o077, 0);
  assert.equal(readdirSync(dir).some((entry) => entry.startsWith('.starter.')), false);
});

test('protect refuses reserved roots case-insensitively even with force and preserves their bytes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-protect-reserved-'));
  for (const out of ['.git', '.HG', '.SvN', 'NODE_MODULES']) {
    const target = join(dir, out);
    mkdirSync(target);
    writeFileSync(join(target, 'keep.txt'), `preserve:${out}`);
    const run = spawnSync(process.execPath, [
      join(import.meta.dirname, 'cli.mjs'), 'protect', '--sample', '--out', out, '--apply', '--force',
    ], { cwd: dir, encoding: 'utf8' });
    assert.equal(run.status, 64, `${out}\n${run.stdout}\n${run.stderr}`);
    assert.match(`${run.stdout}${run.stderr}`, /reserved output directory/i);
    assert.equal(readFileSync(join(target, 'keep.txt'), 'utf8'), `preserve:${out}`);
  }
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
  assert.match(run.stdout, /would create: emilia\/authority-map\.html/);
  assert.match(run.stdout, /would create: emilia\/verify-setup\.mjs/);
  assert.equal(spawnSync(process.execPath, ['-e', "import('node:fs').then(fs => process.exit(fs.existsSync('emilia') ? 1 : 0))"], {
    cwd: dir,
  }).status, 0, 'dry-run must not create the output directory');
});

test('scan CLI exercises MCP, OpenAPI, sample, emit, and refusal paths', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-scan-cli-'));
  const mcpInput = join(dir, 'tools.json');
  const emitted = join(dir, 'manifest.json');
  writeFileSync(mcpInput, JSON.stringify({
    tools: [
      { name: 'getAccountBalance', description: 'Read the balance' },
      { name: 'rotateApiKey', description: 'Fetch the current key and rotate it' },
    ],
  }));

  const mcp = spawnSync(process.execPath, [join(import.meta.dirname, 'cli.mjs'), mcpInput, '--emit', emitted], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.equal(mcp.status, 0, `${mcp.stdout}\n${mcp.stderr}`);
  assert.match(mcp.stdout, /mcp surface, 2 actions/);
  assert.match(mcp.stdout, /rotateApiKey/);
  assert.match(mcp.stdout, /REVIEW \(fail-closed\)/);
  assert.match(mcp.stdout, /Only statically-listed tools are visible/);
  const emittedManifest = JSON.parse(readFileSync(emitted, 'utf8'));
  assert.ok(emittedManifest.actions.some((action) => action.match?.tool === 'rotateApiKey'));

  const overwrite = spawnSync(process.execPath, [join(import.meta.dirname, 'cli.mjs'), mcpInput, '--emit', emitted], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.equal(overwrite.status, 2);
  assert.match(`${overwrite.stdout}${overwrite.stderr}`, /refusing to overwrite existing manifest/);

  const openApiInput = join(dir, 'openapi.json');
  writeFileSync(openApiInput, JSON.stringify({
    openapi: '3.1.0',
    paths: {
      '/status': {
        parameters: [],
        get: { description: 'Read service health' },
      },
      '/jobs': {
        post: { operationId: 'startJob', summary: 'Start a background job' },
      },
    },
  }));
  const openApi = spawnSync(process.execPath, [join(import.meta.dirname, 'cli.mjs'), openApiInput], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.equal(openApi.status, 0, `${openApi.stdout}\n${openApi.stderr}`);
  assert.match(openApi.stdout, /openapi surface, 2 actions/);
  assert.match(openApi.stdout, /get \/status/);
  assert.match(openApi.stdout, /startJob/);
  assert.match(openApi.stdout, /undocumented endpoints/);

  const completeOpenApiInput = join(dir, 'openapi-complete.json');
  writeFileSync(completeOpenApiInput, JSON.stringify({
    openapi: '3.1.0',
    paths: {
      '/admin': {
        head: { operationId: 'headReplay', summary: 'Inspect replay state' },
        options: { operationId: 'configurePolicy', summary: 'Change policy options' },
        trace: { operationId: 'traceSecrets', summary: 'Trace sensitive request details' },
      },
    },
  }));
  const completeOpenApi = spawnSync(process.execPath, [join(import.meta.dirname, 'cli.mjs'), completeOpenApiInput], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.equal(completeOpenApi.status, 0, `${completeOpenApi.stdout}\n${completeOpenApi.stderr}`);
  assert.match(completeOpenApi.stdout, /openapi surface, 3 actions/);
  assert.match(completeOpenApi.stdout, /headReplay/);
  assert.match(completeOpenApi.stdout, /configurePolicy/);
  assert.match(completeOpenApi.stdout, /traceSecrets/);

  const invalidOpenApiInput = join(dir, 'openapi-invalid.json');
  const invalidManifest = join(dir, 'invalid-manifest.json');
  writeFileSync(invalidOpenApiInput, JSON.stringify({ openapi: '3.1.0', paths: [] }));
  const invalidOpenApi = spawnSync(process.execPath, [
    join(import.meta.dirname, 'cli.mjs'),
    invalidOpenApiInput,
    '--emit',
    invalidManifest,
  ], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.notEqual(invalidOpenApi.status, 0);
  assert.match(`${invalidOpenApi.stdout}${invalidOpenApi.stderr}`, /OpenAPI paths must be an object/);
  assert.equal(existsSync(invalidManifest), false, 'malformed OpenAPI must not emit a false-empty manifest');

  const sample = spawnSync(process.execPath, [join(import.meta.dirname, 'cli.mjs'), '--sample'], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.equal(sample.status, 0, `${sample.stdout}\n${sample.stderr}`);
  assert.match(sample.stdout, /built-in sample/);

  const unrecognized = join(dir, 'unrecognized.json');
  writeFileSync(unrecognized, JSON.stringify({ not_tools: true }));
  const refused = spawnSync(process.execPath, [join(import.meta.dirname, 'cli.mjs'), unrecognized], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.notEqual(refused.status, 0);
  assert.match(`${refused.stdout}${refused.stderr}`, /Unrecognized input/);

  const missing = spawnSync(process.execPath, [join(import.meta.dirname, 'cli.mjs')], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.equal(missing.status, 2);
  assert.match(`${missing.stdout}${missing.stderr}`, /usage: cli\.mjs/);
});

test('scan CLI requires an output path after --emit before scanning or writing', () => {
  for (const args of [['--sample', '--emit'], ['--emit', '--sample']]) {
    const dir = mkdtempSync(join(tmpdir(), 'emilia-scan-missing-emit-'));
    const run = spawnSync(process.execPath, [join(import.meta.dirname, 'cli.mjs'), ...args], {
      cwd: dir,
      encoding: 'utf8',
    });

    assert.equal(run.status, 2, `${args.join(' ')}\n${run.stdout}\n${run.stderr}`);
    assert.equal(run.stdout, '', 'argument errors must be rejected before scan output');
    assert.match(run.stderr, /--emit requires a value/);
    assert.deepEqual(readdirSync(dir), [], 'argument errors must not create output');
  }
});

test('scan protect requires an output directory after --out before scanning or writing', () => {
  for (const args of [['protect', '--sample', '--out'], ['protect', '--sample', '--out', '--apply']]) {
    const dir = mkdtempSync(join(tmpdir(), 'emilia-protect-missing-out-'));
    const run = spawnSync(process.execPath, [join(import.meta.dirname, 'cli.mjs'), ...args], {
      cwd: dir,
      encoding: 'utf8',
    });

    assert.equal(run.status, 2, `${args.join(' ')}\n${run.stdout}\n${run.stderr}`);
    assert.equal(run.stdout, '', 'argument errors must be rejected before protect output');
    assert.match(run.stderr, /--out requires a value/);
    assert.deepEqual(readdirSync(dir), [], 'argument errors must not create output');
  }
});

test('OpenAPI scan preserves route selectors but protect refuses verification-only HTTP scaffolds', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-protect-openapi-'));
  const input = join(dir, 'openapi.json');
  writeFileSync(input, JSON.stringify({
    openapi: '3.1.0',
    paths: {
      '/payments/{paymentId}': {
        post: { operationId: 'sendWire', summary: 'Send an outgoing wire transfer' },
      },
      '/customers/{customerId}': {
        delete: { operationId: 'deleteCustomer', summary: 'Permanently delete a customer' },
      },
    },
  }));

  const run = spawnSync(process.execPath, [
    join(import.meta.dirname, 'cli.mjs'),
    'protect',
    input,
    '--apply',
  ], {
    cwd: dir,
    encoding: 'utf8',
  });

  assert.notEqual(run.status, 0, 'OpenAPI protect must not emit a replayable verification-only gate');
  assert.match(`${run.stdout}${run.stderr}`, /OpenAPI protect is unavailable until durable one-use consumption is wired/);
  assert.equal(spawnSync(process.execPath, ['-e', "import('node:fs').then(fs => process.exit(fs.existsSync('emilia') ? 1 : 0))"], {
    cwd: dir,
  }).status, 0, 'refused OpenAPI protect must not create an output directory');

  const manifest = scanActions([
    { name: 'sendWire', description: 'Send an outgoing wire transfer', http_method: 'post', route_path: '/payments/{paymentId}' },
    { name: 'deleteCustomer', description: 'Permanently delete a customer', http_method: 'delete', route_path: '/customers/{customerId}' },
  ], { source: 'openapi' }).manifest;
  assert.deepEqual(
    manifest.actions
      .filter((action) => String(action.id).startsWith('discovered.'))
      .map((action) => action.match),
    [
      { protocol: 'http', method: 'POST', path: '/payments/{paymentId}' },
      { protocol: 'http', method: 'DELETE', path: '/customers/{customerId}' },
    ],
  );
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

  installLocalMcpGuard(dir);

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
  assert.match(check.stdout, /EMILIA RR-1 CHECK: PASS/);
  assert.match(check.stdout, /synthetic local handler ran exactly once/);
  const repeatedCheck = spawnSync(process.execPath, [checkPath], { cwd: dir, encoding: 'utf8' });
  assert.equal(repeatedCheck.status, 0, `${repeatedCheck.stdout}\n${repeatedCheck.stderr}`);
  const firstDigest = check.stdout.match(/RR-1 results digest: (sha256:[0-9a-f]{64})/)?.[1];
  const repeatedDigest = repeatedCheck.stdout.match(/RR-1 results digest: (sha256:[0-9a-f]{64})/)?.[1];
  assert.ok(firstDigest, 'first RR-1 run did not print a results digest');
  assert.equal(repeatedDigest, firstDigest, 'RR-1 report digest changed across equivalent independent runs');

  const productionDemo = spawnSync(process.execPath, [checkPath], {
    cwd: dir,
    encoding: 'utf8',
    env: { ...process.env, NODE_ENV: 'production' },
  });
  assert.notEqual(productionDemo.status, 0);
  assert.match(`${productionDemo.stdout}${productionDemo.stderr}`, /demo guard is unavailable in production/);
});

test('selected-action Gate Starter is two-stage, blocks every unselected runtime tool, and emits no handoff before review', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-selected-starter-'));
  const input = join(dir, 'tools.json');
  writeFileSync(input, JSON.stringify([
    { name: 'sendWire', description: 'Send an outgoing wire transfer' },
    { name: 'deployToProduction', description: 'Ship the current build to production' },
    { name: 'getAccountBalance', description: 'Read the current balance' },
  ]));
  installLocalMcpGuard(dir);

  const apply = spawnSync(process.execPath, [
    join(import.meta.dirname, 'cli.mjs'),
    'protect',
    input,
    '--action',
    'sendWire',
    '--apply',
    '--verify',
  ], { cwd: dir, encoding: 'utf8' });
  assert.equal(apply.status, 0, `${apply.stdout}\n${apply.stderr}`);
  assert.match(apply.stdout, /EMILIA RR-1 CHECK: PASS — 4\/4/);
  assert.match(apply.stdout, /refused an exact synthetic receipt for an unscanned runtime tool/i);

  const starter = join(dir, 'emilia');
  const handoffPath = join(starter, 'scan-adoption-handoff.json');
  assert.equal(existsSync(handoffPath), false, 'generation plus RR-1 must not silently become owner review');
  assert.deepEqual(readdirSync(starter).sort(), [
    '.emilia-gate-starter.json',
    'INTEGRATION.md',
    'action-control.manifest.json',
    'authority-map.html',
    'guard.mjs',
    'verify-setup.mjs',
  ]);
  const authorityMap = readFileSync(join(starter, 'authority-map.html'), 'utf8');
  assert.match(authorityMap, /EMILIA Authority Brain/);
  assert.doesNotMatch(authorityMap, /--apply --verify/);
  assert.match(authorityMap, /--action 'sendWire' --reviewed/);
  assert.match(authorityMap, /Review-pending in this Gate Starter/);
  assert.match(authorityMap, /Do not overwrite this starter with --force/);
  assert.doesNotMatch(authorityMap, /https?:\/\//i);

  const guardPath = join(starter, 'guard.mjs');
  const imported = await import(`${new URL(`file://${guardPath}`).href}?selected=${Date.now()}`);
  assert.match(imported.protectionSelection.declared_surface_sha256, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(imported.protectionSelection.selected_tools, ['sendWire']);
  assert.deepEqual(imported.protectionSelection.visible_read_only_tools, ['getAccountBalance']);
  assert.deepEqual(imported.protectionSelection.review_pending_tools, ['deployToProduction']);

  let calls = 0;
  const guarded = imported.guardDispatchDemo(async (name) => {
    calls += 1;
    return { executed: name };
  });
  const pending = await guarded('deployToProduction', {
    __ep: { receipt: { syntactically: 'present-but-must-not-be-processed' } },
  });
  assert.equal(pending.code, 'emilia_owner_review_required');
  const unseen = await guarded('__runtime_only_tool__', {
    __ep: { receipt: { syntactically: 'present-but-must-not-be-processed' } },
  });
  assert.equal(unseen.code, 'emilia_owner_review_required');
  assert.equal(calls, 0, 'unselected and unseen tools must be refused before their handler');
  assert.deepEqual(await guarded('getAccountBalance', {}), { executed: 'getAccountBalance' });
  assert.equal(calls, 1, 'only the explicitly visible read-only action may bypass receipt processing');

  const protectedBytes = new Map(
    readdirSync(starter).map((leaf) => [leaf, readFileSync(join(starter, leaf))]),
  );
  const reviewed = spawnSync(process.execPath, [
    join(import.meta.dirname, 'cli.mjs'),
    'protect',
    input,
    '--action',
    'sendWire',
    '--reviewed',
    '--crossing-profile',
    'ccs-wang-draft08-v13',
  ], { cwd: dir, encoding: 'utf8' });
  assert.equal(reviewed.status, 0, `${reviewed.stdout}\n${reviewed.stderr}`);
  assert.match(reviewed.stdout, /Reviewed handoff created without changing the Gate Starter/);
  const handoff = JSON.parse(readFileSync(handoffPath, 'utf8'));
  assert.deepEqual(handoff.selected_actions.map((action) => action.selector.tool), ['sendWire']);
  for (const [leaf, bytes] of protectedBytes) {
    assert.deepEqual(readFileSync(join(starter, leaf)), bytes, `reviewed shortcut rewrote ${leaf}`);
  }
  const handoffBytes = readFileSync(handoffPath);
  const overwrite = spawnSync(process.execPath, [
    join(import.meta.dirname, 'cli.mjs'),
    'protect', input, '--action', 'sendWire', '--reviewed', '--crossing-profile', 'ccs-wang-draft08-v13',
  ], { cwd: dir, encoding: 'utf8' });
  assert.notEqual(overwrite.status, 0);
  assert.match(`${overwrite.stdout}${overwrite.stderr}`, /refusing to overwrite existing handoff/i);
  assert.deepEqual(readFileSync(handoffPath), handoffBytes);
});

test('reviewed selected action requires an explicit launch profile and creates a bound unsealed Lab workspace', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-scan-crossing-seed-'));
  const input = join(dir, 'tools.json');
  writeFileSync(input, JSON.stringify([
    { name: 'sendWire', description: 'Send an outgoing wire transfer' },
    { name: 'getAccountBalance', description: 'Read the current balance' },
  ]));
  installLocalMcpGuard(dir);
  const cli = join(import.meta.dirname, 'cli.mjs');
  const apply = spawnSync(process.execPath, [
    cli, 'protect', input, '--action', 'sendWire', '--apply',
  ], { cwd: dir, encoding: 'utf8' });
  assert.equal(apply.status, 0, `${apply.stdout}\n${apply.stderr}`);

  const missingProfile = spawnSync(process.execPath, [
    cli, 'protect', input, '--action', 'sendWire', '--reviewed',
  ], { cwd: dir, encoding: 'utf8' });
  assert.equal(missingProfile.status, 64);
  assert.match(`${missingProfile.stdout}${missingProfile.stderr}`, /--reviewed requires --crossing-profile/);
  assert.equal(existsSync(join(dir, 'emilia', 'scan-crossing-seed.json')), false);
  assert.equal(existsSync(join(dir, 'emilia-crossing-lab')), false);

  const reviewed = spawnSync(process.execPath, [
    cli,
    'protect',
    input,
    '--action',
    'sendWire',
    '--reviewed',
    '--crossing-profile',
    'ccs-wang-draft08-v13',
  ], { cwd: dir, encoding: 'utf8' });
  assert.equal(reviewed.status, 0, `${reviewed.stdout}\n${reviewed.stderr}`);
  assert.match(reviewed.stdout, /unsealed Crossing Lab workspace/i);

  const seedPath = join(dir, 'emilia', 'scan-crossing-seed.json');
  const handoffPath = join(dir, 'emilia', 'scan-adoption-handoff.json');
  const workspaceRoot = join(dir, 'emilia-crossing-lab');
  const seed = JSON.parse(readFileSync(seedPath, 'utf8'));
  const handoff = JSON.parse(readFileSync(handoffPath, 'utf8'));
  const workspace = JSON.parse(readFileSync(join(workspaceRoot, 'workspace.json'), 'utf8'));

  assert.equal(seed['@version'], 'EP-SCAN-CROSSING-SEED-v1');
  assert.equal(seed.verify_version, '3.21.0');
  assert.equal(seed.profile_id, 'ccs-wang-draft08-v13');
  assert.deepEqual(seed.profile_contract, {
    action_type: 'agent.tool-invocation.1',
    material_fields: ['action_type', 'parameters'],
  });
  assert.equal(seed.profile_compatibility, 'UNVERIFIED_OPERATOR_CONFIRMATION_REQUIRED');
  assert.equal(seed.operator_confirmation.required_inputs.includes('profile_compatibility_confirmation'), true);
  assert.deepEqual(seed.selected_action.material_fields, [
    'action_type',
    'amount_usd',
    'currency',
    'payment_instruction_id',
    'beneficiary_account_hash',
  ]);
  assert.equal(seed.reviewed_manifest.sha256, handoff.reviewed_manifest.sha256);
  assert.deepEqual(handoff.crossing_seed, {
    file: 'scan-crossing-seed.json',
    sha256: sha256(readFileSync(seedPath)),
  });
  assert.deepEqual(readdirSync(workspaceRoot).sort(), ['adapter.mjs', 'artifact.json', 'workspace.json']);
  assert.equal(workspace['@version'], 'EP-AEB-CROSSING-LAB-DRAFT-v1');
  assert.equal(workspace.state, 'UNSEALED_OPERATOR_INPUT_REQUIRED');
  assert.equal(workspace.verify_version, '3.21.0');
  assert.deepEqual(workspace.profile_contract, seed.profile_contract);
  assert.equal(workspace.profile_compatibility, 'UNVERIFIED_OPERATOR_CONFIRMATION_REQUIRED');
  assert.equal(workspace.source_seed.sha256, handoff.crossing_seed.sha256);
  assert.deepEqual(workspace.selected_action, seed.selected_action);
  assert.equal(handoff['@version'], 'EP-SCAN-ADOPTION-HANDOFF-v3');
  assert.equal(statSync(seedPath).mode & 0o777, 0o600);
  assert.equal(statSync(join(workspaceRoot, 'workspace.json')).mode & 0o777, 0o600);
});

test('selected-action shortcut refuses unknown, read-only, multiple, and unavailable verification requests before writes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-selected-refusals-'));
  const input = join(dir, 'tools.json');
  writeFileSync(input, JSON.stringify([
    { name: 'sendWire', description: 'Send an outgoing wire transfer' },
    { name: 'deployToProduction', description: 'Ship the current build to production' },
    { name: 'getAccountBalance', description: 'Read the current balance' },
  ]));
  const run = (...extra) => spawnSync(process.execPath, [
    join(import.meta.dirname, 'cli.mjs'), 'protect', input, ...extra,
  ], { cwd: dir, encoding: 'utf8' });

  const unknown = run('--action', 'notDeclared', '--apply');
  assert.equal(unknown.status, 64);
  assert.match(`${unknown.stdout}${unknown.stderr}`, /not one visible consequential MCP tool/);

  const readOnly = run('--action', 'getAccountBalance', '--apply');
  assert.equal(readOnly.status, 64);
  assert.match(`${readOnly.stdout}${readOnly.stderr}`, /not one visible consequential MCP tool/);

  const multiple = run('--action', 'sendWire', '--action', 'deployToProduction', '--apply');
  assert.equal(multiple.status, 64);
  assert.match(`${multiple.stdout}${multiple.stderr}`, /exactly one --action may be selected/);

  const controlAction = run('--action', 'sendWire\u001b[2J', '--apply');
  assert.equal(controlAction.status, 64);
  assert.match(`${controlAction.stdout}${controlAction.stderr}`, /source-confusing characters/);
  assert.equal(`${controlAction.stdout}${controlAction.stderr}`.includes('\u001b'), false,
    'control-bearing action must not be echoed to the terminal');

  const noAction = run('--apply', '--verify');
  assert.equal(noAction.status, 64);
  assert.match(`${noAction.stdout}${noAction.stderr}`, /--verify requires exactly one --action/);

  const missingRuntime = run('--action', 'sendWire', '--apply', '--verify');
  assert.equal(missingRuntime.status, 1);
  assert.match(`${missingRuntime.stdout}${missingRuntime.stderr}`, /npm install --save-exact @emilia-protocol\/mcp-guard@0\.6\.0/);
  assert.equal(existsSync(join(dir, 'emilia')), false, 'failed verification preflight must not write a partial starter');

  const hostileOutput = spawnSync(process.execPath, [
    join(import.meta.dirname, 'cli.mjs'),
    'protect',
    input,
    '--out',
    "x';globalThis.__emiliaInjected=1;'",
    '--action',
    'sendWire',
    '--apply',
  ], { cwd: dir, encoding: 'utf8' });
  assert.equal(hostileOutput.status, 64);
  assert.match(`${hostileOutput.stdout}${hostileOutput.stderr}`, /portable direct-child slug/i);
  assert.equal(readdirSync(dir).some((entry) => entry.includes('__emiliaInjected')), false);

  writeFileSync(input, JSON.stringify([
    { name: 'sendWire', description: 'Send an outgoing wire transfer' },
    { name: 'sendWire', description: 'A second declaration is ambiguous' },
  ]));
  const ambiguous = run('--action', 'sendWire', '--apply');
  assert.notEqual(ambiguous.status, 0);
  assert.match(`${ambiguous.stdout}${ambiguous.stderr}`, /duplicate action name/i);
  assert.equal(existsSync(join(dir, 'emilia')), false);
});

test('reviewed shortcut refuses manifest drift, wrong selected action, and handoff overwrite without changing existing bytes', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-reviewed-shortcut-safety-'));
  const input = join(dir, 'tools.json');
  writeFileSync(input, JSON.stringify([
    { name: 'sendWire', description: 'Send an outgoing wire transfer' },
    { name: 'deployToProduction', description: 'Ship the current build to production' },
  ]));
  installLocalMcpGuard(dir);
  const cli = join(import.meta.dirname, 'cli.mjs');
  const apply = spawnSync(process.execPath, [
    cli, 'protect', input, '--action', 'sendWire', '--apply',
  ], { cwd: dir, encoding: 'utf8' });
  assert.equal(apply.status, 0, `${apply.stdout}\n${apply.stderr}`);

  const guardPath = join(dir, 'emilia', 'guard.mjs');
  const originalGuard = readFileSync(guardPath);
  writeFileSync(guardPath, `${originalGuard.toString('utf8')}\n// reviewed edit\n`);
  const runtimeDrift = spawnSync(process.execPath, [
    cli, 'protect', input, '--action', 'sendWire', '--reviewed', '--crossing-profile', 'ccs-wang-draft08-v13',
  ], { cwd: dir, encoding: 'utf8' });
  assert.notEqual(runtimeDrift.status, 0);
  assert.match(`${runtimeDrift.stdout}${runtimeDrift.stderr}`, /generated file digest changed: guard\.mjs/i);
  assert.equal(existsSync(join(dir, 'emilia', 'scan-adoption-handoff.json')), false);
  writeFileSync(guardPath, originalGuard);

  const wrong = spawnSync(process.execPath, [
    cli, 'protect', input, '--action', 'deployToProduction', '--reviewed', '--crossing-profile', 'ccs-wang-draft08-v13',
  ], { cwd: dir, encoding: 'utf8' });
  assert.notEqual(wrong.status, 0);
  assert.match(`${wrong.stdout}${wrong.stderr}`, /does not match the generated Gate Starter/);
  assert.equal(existsSync(join(dir, 'emilia', 'scan-adoption-handoff.json')), false);

  writeFileSync(input, JSON.stringify([
    { name: 'sendWire', description: 'Send an outgoing wire transfer' },
    { name: 'deployToProduction', description: 'Ship the current build to production' },
    { name: 'getAccountBalance', description: 'Read the current balance' },
  ]));
  const surfaceDrift = spawnSync(process.execPath, [
    cli, 'protect', input, '--action', 'sendWire', '--reviewed', '--crossing-profile', 'ccs-wang-draft08-v13',
  ], { cwd: dir, encoding: 'utf8' });
  assert.notEqual(surfaceDrift.status, 0);
  assert.match(`${surfaceDrift.stdout}${surfaceDrift.stderr}`, /declared surface does not match the generated Gate Starter/);
  assert.equal(existsSync(join(dir, 'emilia', 'scan-adoption-handoff.json')), false);
  writeFileSync(input, JSON.stringify([
    { name: 'sendWire', description: 'Send an outgoing wire transfer' },
    { name: 'deployToProduction', description: 'Ship the current build to production' },
  ]));

  const manifestPath = join(dir, 'emilia', 'action-control.manifest.json');
  const originalManifest = readFileSync(manifestPath);
  writeFileSync(manifestPath, `${originalManifest.toString('utf8').trim()}\n \n`);
  const drift = spawnSync(process.execPath, [
    cli, 'protect', input, '--action', 'sendWire', '--reviewed', '--crossing-profile', 'ccs-wang-draft08-v13',
  ], { cwd: dir, encoding: 'utf8' });
  assert.notEqual(drift.status, 0);
  assert.match(`${drift.stdout}${drift.stderr}`, /generated file digest changed: action-control\.manifest\.json|existing manifest is not the current scanner proposal/);
  assert.equal(existsSync(join(dir, 'emilia', 'scan-adoption-handoff.json')), false);
});

test('reviewed shortcut cannot relabel a legacy surface-wide scaffold as a selected-action Gate Starter', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-reviewed-legacy-refusal-'));
  installLocalMcpGuard(dir);
  const cli = join(import.meta.dirname, 'cli.mjs');
  const apply = spawnSync(process.execPath, [
    cli, 'protect', '--sample', '--apply',
  ], { cwd: dir, encoding: 'utf8' });
  assert.equal(apply.status, 0, `${apply.stdout}\n${apply.stderr}`);

  const reviewed = spawnSync(process.execPath, [
    cli, 'protect', '--sample', '--action', 'sendWire', '--reviewed', '--crossing-profile', 'ccs-wang-draft08-v13',
  ], { cwd: dir, encoding: 'utf8' });
  assert.notEqual(reviewed.status, 0);
  assert.match(`${reviewed.stdout}${reviewed.stderr}`, /requires an existing selected-action Gate Starter/);
  assert.equal(existsSync(join(dir, 'emilia', 'scan-adoption-handoff.json')), false);
});

test('scan-to-adoption handoff binds reviewed bytes and explicit consequential actions without ambient data', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-handoff-contract-'));
  const input = join(dir, 'tools.json');
  const sensitive = {
    argument: 'customer-secret-argument-991',
    credential: 'ep_live_private_credential_992',
    outsidePath: '/Users/private-operator/hidden/config.json',
    username: 'private-operator-993',
    host: 'private-host-994.internal',
  };
  writeFileSync(input, JSON.stringify([
    {
      name: 'deleteCustomer',
      description: `Permanently remove a record; runtime argument ${sensitive.argument}; source ${sensitive.outsidePath}`,
    },
    { name: 'deployToProduction', description: 'Ship the current build to production' },
    { name: 'getAccountBalance', description: 'Read the current balance' },
  ]));

  const protect = spawnSync(process.execPath, [
    join(import.meta.dirname, 'codemod.mjs'),
    input,
    '--out',
    'emilia',
    '--apply',
  ], { cwd: dir, encoding: 'utf8' });
  assert.equal(protect.status, 0, `${protect.stdout}\n${protect.stderr}`);
  installLocalMcpGuard(dir);

  const verifyPath = join(dir, 'emilia', 'verify-setup.mjs');
  const handoffPath = join(dir, 'emilia', 'scan-adoption-handoff.json');
  const defaultVerify = spawnSync(process.execPath, [verifyPath], { cwd: dir, encoding: 'utf8' });
  assert.equal(defaultVerify.status, 0, `${defaultVerify.stdout}\n${defaultVerify.stderr}`);
  assert.equal(existsSync(handoffPath), false, 'verification must not write a handoff without an explicit flag');

  const manifestDigest = sha256(readFileSync(join(dir, 'emilia', 'action-control.manifest.json')));
  const emit = spawnSync(process.execPath, [
    verifyPath,
    '--emit-handoff',
    '--reviewed-manifest-digest',
    manifestDigest,
    '--action',
    'deleteCustomer',
    '--action',
    'deployToProduction',
  ], {
    cwd: dir,
    encoding: 'utf8',
    env: {
      ...process.env,
      EP_TRUSTED_ISSUER_KEYS: sensitive.credential,
      USER: sensitive.username,
      HOSTNAME: sensitive.host,
      HOME: sensitive.outsidePath,
    },
  });
  assert.equal(emit.status, 0, `${emit.stdout}\n${emit.stderr}`);

  const handoffText = readFileSync(handoffPath, 'utf8');
  const handoff = JSON.parse(handoffText);
  assert.deepEqual(Object.keys(handoff), [
    '@version',
    'reviewed_manifest',
    'generated_scaffold',
    'selected_actions',
    'local_refusal',
    'local_rr1',
  ]);
  assert.equal(handoff['@version'], 'EP-SCAN-ADOPTION-HANDOFF-v2');
  assert.deepEqual(handoff.reviewed_manifest, {
    file: 'action-control.manifest.json',
    sha256: manifestDigest,
  });
  assert.deepEqual(handoff.generated_scaffold, expectedScaffoldBinding(dir));
  assert.deepEqual(handoff.selected_actions, [
    {
      id: 'discovered.deletecustomer',
      selector: { protocol: 'mcp', tool: 'deleteCustomer' },
      action_type: 'record.delete',
      assurance_class: 'class_a',
      receipt_required: true,
    },
    {
      id: 'discovered.deploytoproduction',
      selector: { protocol: 'mcp', tool: 'deployToProduction' },
      action_type: 'deploy.production',
      assurance_class: 'quorum',
      receipt_required: true,
    },
  ]);
  assert.deepEqual(handoff.local_refusal, {
    status: 'passed',
    claim: 'selected synthetic calls were refused by the generated local demo wrapper before the supplied handler',
    handler_called: false,
    state: 'ephemeral_demo_only',
    claim_boundary: {
      asserted: [
        'selected_actions_refused_locally',
        'supplied_handler_not_called',
      ],
      not_asserted: [
        'production_enforcement',
        'complete_mediation',
        'credential_isolation',
        'durable_state',
        'trusted_key_configuration',
        'signed_refusal_artifact',
        'public_verification',
      ],
    },
  });
  assert.equal(handoff.local_rr1.status, 'passed');
  assert.equal(handoff.local_rr1.profile, 'EP-RR-1-LOCAL-v1');
  assert.equal(handoff.local_rr1.manifest_sha256, manifestDigest);
  assert.deepEqual(
    handoff.local_rr1.tested_actions,
    handoff.selected_actions.map(({ selector, action_type, assurance_class, receipt_required }) => ({
      selector,
      action_type,
      assurance_class,
      receipt_required,
    })),
  );
  assert.equal(handoff.local_rr1.synthetic_handler_calls, 2);
  assert.deepEqual(
    handoff.local_rr1.cases.map(({ case_id, observed, handler_calls_after }) => ({
      case_id,
      observed,
      handler_calls_after,
    })),
    [
      { case_id: 'RR1-01-missing-receipt:deleteCustomer', observed: 'emilia_receipt_required', handler_calls_after: 0 },
      { case_id: 'RR1-02-valid-receipt:deleteCustomer', observed: 'admitted', handler_calls_after: 1 },
      { case_id: 'RR1-03-action-substitution:deleteCustomer', observed: 'action_mismatch', handler_calls_after: 1 },
      { case_id: 'RR1-04-replay:deleteCustomer', observed: 'replay_refused', handler_calls_after: 1 },
      { case_id: 'RR1-01-missing-receipt:deployToProduction', observed: 'emilia_receipt_required', handler_calls_after: 1 },
      { case_id: 'RR1-02-valid-receipt:deployToProduction', observed: 'admitted', handler_calls_after: 2 },
      { case_id: 'RR1-03-action-substitution:deployToProduction', observed: 'action_mismatch', handler_calls_after: 2 },
      { case_id: 'RR1-04-replay:deployToProduction', observed: 'replay_refused', handler_calls_after: 2 },
    ],
  );
  assert.match(handoff.local_rr1.results_digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(handoff.local_rr1.claim_boundary.not_asserted.includes('named_human_approval'), true);
  assert.equal(statSync(handoffPath).mode & 0o777, 0o600, 'handoff must be owner-only');

  for (const forbidden of [...Object.values(sensitive), dir, 'customer_id', 'synthetic-customer-001']) {
    assert.equal(handoffText.includes(forbidden), false, `handoff leaked forbidden value: ${forbidden}`);
  }
});

test('handoff emission requires review acknowledgement, consequential selection, and safe-create output', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-handoff-safety-'));
  const apply = spawnSync(process.execPath, [
    join(import.meta.dirname, 'codemod.mjs'),
    '--sample',
    '--apply',
  ], { cwd: dir, encoding: 'utf8' });
  assert.equal(apply.status, 0, `${apply.stdout}\n${apply.stderr}`);
  installLocalMcpGuard(dir);

  const verifyPath = join(dir, 'emilia', 'verify-setup.mjs');
  const manifestDigest = sha256(readFileSync(join(dir, 'emilia', 'action-control.manifest.json')));
  const run = (...extra) => spawnSync(process.execPath, [verifyPath, '--emit-handoff', ...extra], {
    cwd: dir,
    encoding: 'utf8',
  });

  const unreviewed = run('--action', 'deleteCustomer');
  assert.notEqual(unreviewed.status, 0);
  assert.match(`${unreviewed.stdout}${unreviewed.stderr}`, /reviewed manifest digest or --acknowledge-reviewed-manifest is required/i);

  const missingDigestValue = run('--reviewed-manifest-digest', '-h');
  assert.notEqual(missingDigestValue.status, 0);
  assert.match(`${missingDigestValue.stdout}${missingDigestValue.stderr}`, /reviewed manifest digest is required after/i);

  const missingActionValue = run(
    '--reviewed-manifest-digest',
    manifestDigest,
    '--action',
    '-h',
  );
  assert.notEqual(missingActionValue.status, 0);
  assert.match(`${missingActionValue.stdout}${missingActionValue.stderr}`, /tool name is required after --action/i);

  const mismatched = run(
    '--reviewed-manifest-digest',
    `sha256:${'0'.repeat(64)}`,
    '--action',
    'deleteCustomer',
  );
  assert.notEqual(mismatched.status, 0);
  assert.match(`${mismatched.stdout}${mismatched.stderr}`, /reviewed manifest digest does not match/i);

  const nonConsequential = run(
    '--reviewed-manifest-digest',
    manifestDigest,
    '--action',
    'getAccountBalance',
  );
  assert.notEqual(nonConsequential.status, 0);
  assert.match(`${nonConsequential.stdout}${nonConsequential.stderr}`, /not a visible consequential action/i);

  const first = run(
    '--reviewed-manifest-digest',
    manifestDigest,
    '--action',
    'deleteCustomer',
  );
  assert.equal(first.status, 0, `${first.stdout}\n${first.stderr}`);
  const handoffPath = join(dir, 'emilia', 'scan-adoption-handoff.json');
  const firstBytes = readFileSync(handoffPath);

  const overwrite = run(
    '--reviewed-manifest-digest',
    manifestDigest,
    '--action',
    'deleteCustomer',
  );
  assert.notEqual(overwrite.status, 0);
  assert.match(`${overwrite.stdout}${overwrite.stderr}`, /refusing to overwrite existing handoff/i);
  assert.deepEqual(readFileSync(handoffPath), firstBytes, 'existing handoff bytes must be preserved');

  unlinkSync(handoffPath);
  const external = join(dir, 'external-must-not-change.json');
  writeFileSync(external, '{"preserve":true}\n');
  symlinkSync(external, handoffPath);
  const symlink = run(
    '--reviewed-manifest-digest',
    manifestDigest,
    '--action',
    'deleteCustomer',
  );
  assert.notEqual(symlink.status, 0);
  assert.match(`${symlink.stdout}${symlink.stderr}`, /refusing to overwrite existing handoff/i);
  assert.equal(readFileSync(external, 'utf8'), '{"preserve":true}\n');
});
