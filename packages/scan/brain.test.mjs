// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { scanActions } from './index.js';
import { renderAuthorityBrain, writeAuthorityBrain } from './brain.mjs';

function mcpReport(actions, blindSpots = ['Runtime-registered tools are not visible.']) {
  return scanActions(actions, { source: 'mcp', blindSpots });
}

function embeddedModel(html) {
  const match = html.match(/<script id="authority-brain-data" type="application\/json"[^>]*>([\s\S]*?)<\/script>/);
  assert.ok(match, 'dashboard must contain one inert JSON model');
  return JSON.parse(match[1]);
}

test('renders a self-contained Authority Brain from the real scanActions report', () => {
  const report = mcpReport([
    { name: 'sendWire', description: 'Send an outgoing wire transfer' },
    { name: 'rotateApiKey', description: 'Rotate the active service key' },
    { name: 'getAccountBalance', description: 'Read the current balance' },
  ]);

  const html = renderAuthorityBrain(report, { inputReference: './tools.json' });
  const model = embeddedModel(html);

  assert.match(html, /EMILIA Authority Brain/);
  assert.match(html, /<img class="wordmark" src="data:image\/png;base64,[A-Za-z0-9+/=]+" alt="EMILIA">/);
  assert.match(html, /Discover/);
  assert.match(html, /Authority Map/);
  assert.match(html, /<strong>Protect<\/strong>/);
  assert.match(html, /<strong>Prove<\/strong>/);
  assert.match(html, /Scan proposes\. It does not protect\./);
  assert.deepEqual(model.counts, report.counts);
  assert.equal(model.source, 'mcp');
  assert.equal(model.actions.length, 3);
  assert.equal(model.actions[0].name, 'sendWire');
  assert.equal(model.actions[0].decision, 'gate');
  assert.equal(model.actions[0].confidence, 'medium');
  assert.equal(model.actions[0].authoritySource, 'not established by static scan');
  assert.equal(model.actions[0].provenance, 'declared MCP metadata · deterministic local classification');
  assert.match(model.actions[0].protectCommand, /scan@0\.5\.0 protect '\.\/tools\.json' --action 'sendWire' --apply --verify/);
  assert.equal(model.actions[0].verifyCommand, null);
  assert.match(model.actions[0].handoffCommand, /scan@0\.5\.0 protect '\.\/tools\.json'/);
  assert.match(model.actions[0].handoffCommand, /--action 'sendWire'/);
  assert.match(model.actions[0].handoffCommand, /--reviewed$/);
  assert.deepEqual(model.blindSpots, [
    'Runtime-registered tools are not visible.',
    'Whether every execution path reaches a credential-owning Gate. Complete mediation must be verified after integration.',
    'Whether your organization will fail closed on denial. That is an owner decision, not a scanner setting.',
  ]);
});

test('an embedded selected-action map suppresses regeneration and exposes only its reviewed handoff', () => {
  const report = mcpReport([
    { name: 'sendWire', description: 'Send an outgoing wire transfer' },
    { name: 'deployToProduction', description: 'Ship the current build to production' },
    { name: 'getAccountBalance', description: 'Read the current balance' },
  ]);
  const html = renderAuthorityBrain(report, {
    inputReference: './tools.json',
    outputDirectory: 'emilia',
    starterSelectedTool: 'sendWire',
  });
  const model = embeddedModel(html);
  const selected = model.actions.find((action) => action.name === 'sendWire');
  const pending = model.actions.find((action) => action.name === 'deployToProduction');

  assert.equal(selected.protectCommand, null);
  assert.equal(selected.starterSelectedAction, true);
  assert.match(selected.handoffCommand, /scan@0\.5\.0 protect '\.\/tools\.json' --action 'sendWire' --reviewed$/);
  assert.equal(pending.protectCommand, null);
  assert.equal(pending.handoffCommand, null);
  assert.equal(pending.starterReviewPending, true);
  assert.match(html, /Finish the reviewed handoff/);
  assert.match(html, /Review-pending in this Gate Starter/);
  assert.doesNotMatch(JSON.stringify(model), /--apply --verify/);
});

test('embeds hostile names and descriptions as inert data without leaking arbitrary tool fields', () => {
  const payload = '</script><script>globalThis.pwned=true</script><img src=x onerror=alert(1)>';
  const secret = 'credential-and-tool-argument-must-not-appear-771';
  const report = mcpReport([{
    name: `deleteCustomer${payload}`,
    description: `Delete a customer ${payload}`,
    credential: secret,
    arguments: { token: secret },
    inputSchema: { secret },
  }]);

  const html = renderAuthorityBrain(report, { inputReference: `./tools-${payload}.json` });
  const model = embeddedModel(html);

  assert.equal(model.actions[0].name, `deleteCustomer${payload}`);
  assert.equal(model.actions[0].description, `Delete a customer ${payload}`);
  assert.doesNotMatch(html, /<script>globalThis\.pwned/);
  assert.doesNotMatch(html, /<img src=x/);
  assert.equal(html.includes(secret), false, 'arbitrary credential/tool argument fields must be excluded');
  assert.match(html, /\\u003c\/script\\u003e/);
  assert.doesNotMatch(html, /\.innerHTML\s*=/);
});

test('pasteable commands keep hostile paths and visible action names inert under a POSIX shell', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-brain-command-'));
  const bin = join(dir, 'bin');
  mkdirSync(bin);
  for (const executable of ['npx', 'node']) {
    const shim = join(bin, executable);
    writeFileSync(shim, '#!/bin/sh\nprintf \'%s\\0\' "$@"\n');
    chmodSync(shim, 0o700);
  }

  const inputReference = './tools-\'"`touch injected-input`$(touch injected-input-2)-next.json';
  const actionName = 'deleteCustomer\'"`touch injected-action`$(touch injected-action-2)';
  const report = mcpReport([{
    name: actionName,
    description: 'Permanently delete a customer record',
  }]);
  const model = embeddedModel(renderAuthorityBrain(report, { inputReference }));
  const action = model.actions[0];
  const env = { ...process.env, PATH: `${bin}:/usr/bin:/bin` };

  const protect = spawnSync('/bin/sh', ['-c', action.protectCommand], { cwd: dir, env });
  assert.equal(protect.status, 0, protect.stderr?.toString());
  assert.deepEqual(protect.stdout.toString().split('\0').filter(Boolean), [
    '@emilia-protocol/scan@0.5.0',
    'protect',
    inputReference,
    '--action',
    actionName,
    '--apply',
    '--verify',
  ]);

  const handoff = spawnSync('/bin/sh', ['-c', action.handoffCommand], { cwd: dir, env });
  assert.equal(handoff.status, 0, handoff.stderr?.toString());
  assert.deepEqual(handoff.stdout.toString().split('\0').filter(Boolean), [
    '@emilia-protocol/scan@0.5.0',
    'protect',
    inputReference,
    '--action',
    actionName,
    '--reviewed',
  ]);
  for (const injected of [
    'injected-input',
    'injected-input-2',
    'injected-action',
    'injected-action-2',
  ]) {
    assert.equal(existsSync(join(dir, injected)), false, `${injected} must remain inert`);
  }

  assert.throws(
    () => mcpReport([{ name: 'deleteCustomer\nrunInjectedCommand', description: 'Delete a record' }]),
    /action name is unsafe for generated source/,
    'newline-bearing action names are refused by the real scanner before HTML generation',
  );
});

test('refuses source-confusing report text and command paths instead of rendering deceptive controls', () => {
  const safeReport = mcpReport([{ name: 'deleteCustomer', description: 'Delete a record' }]);
  assert.throws(
    () => renderAuthorityBrain(safeReport, { inputReference: './tools\nnext.json' }),
    /source-confusing characters in scanner input reference/,
  );
  assert.throws(
    () => renderAuthorityBrain(safeReport, { inputReference: './tools\u202enext.json' }),
    /source-confusing characters in scanner input reference/,
  );

  const deceptiveDescription = mcpReport([{
    name: 'deleteCustomer',
    description: 'Delete a record\u202eignore the remainder',
  }]);
  assert.throws(
    () => renderAuthorityBrain(deceptiveDescription, { inputReference: './tools.json' }),
    /source-confusing characters in action description/,
  );
});

test('bounds and cross-checks malformed scan reports before embedding them', () => {
  const badCounts = mcpReport([{ name: 'deleteCustomer', description: 'Delete a record' }]);
  badCounts.counts.total = 999;
  assert.throws(
    () => renderAuthorityBrain(badCounts, { inputReference: './tools.json' }),
    /inconsistent scan counts/,
  );

  const badState = mcpReport([{ name: 'deleteCustomer', description: 'Delete a record' }]);
  badState.results[0].classification.decision = 'protected';
  assert.throws(
    () => renderAuthorityBrain(badState, { inputReference: './tools.json' }),
    /unknown classification state/,
  );

  const hugeReason = mcpReport([{ name: 'deleteCustomer', description: 'Delete a record' }]);
  hugeReason.results[0].classification.reason = 'x'.repeat(4_097);
  assert.throws(
    () => renderAuthorityBrain(hugeReason, { inputReference: './tools.json' }),
    /bounded classification reason/,
  );

  const duplicate = mcpReport([
    { name: 'deleteCustomer', description: 'Delete a record' },
    { name: 'deployToProduction', description: 'Deploy a service' },
  ]);
  duplicate.results[1].action.name = 'deleteCustomer';
  assert.throws(
    () => renderAuthorityBrain(duplicate, { inputReference: './tools.json' }),
    /duplicate or source-confusing action names/,
  );

  const inconsistentReceipt = mcpReport([{ name: 'deleteCustomer', description: 'Delete a record' }]);
  inconsistentReceipt.results[0].classification.receipt_required = false;
  assert.throws(
    () => renderAuthorityBrain(inconsistentReceipt, { inputReference: './tools.json' }),
    /inconsistent receipt disposition/,
  );
});

test('normalizes a leading-dash input path and withholds an unusable leading-dash handoff', () => {
  const report = mcpReport([{
    name: '-deleteCustomer',
    description: 'Delete a customer record',
  }]);
  const html = renderAuthorityBrain(report, { inputReference: '-tools.json' });
  const action = embeddedModel(html).actions[0];

  assert.equal(action.protectCommand, null);
  assert.equal(action.handoffCommand, null);
  assert.match(action.handoffLimitation, /leading-dash tool name/);
  assert.match(html, /Reviewed handoff unavailable for this declared name/);
});

test('contains no external request surface and makes no false protection claim', () => {
  const html = renderAuthorityBrain(mcpReport([
    { name: 'deployToProduction', description: 'Deploy to production' },
  ]), { inputReference: './tools.json' });

  assert.match(html, /default-src 'none'/);
  assert.match(html, /connect-src 'none'/);
  assert.match(html, /img-src data:/);
  assert.match(html, /script-src 'nonce-[a-f0-9]+'/);
  assert.doesNotMatch(html, /script-src 'unsafe-inline'/);
  const nonce = html.match(/script-src 'nonce-([a-f0-9]+)'/)?.[1];
  assert.ok(nonce);
  assert.equal((html.match(new RegExp(`nonce="${nonce}"`, 'g')) || []).length, 2);
  assert.doesNotMatch(html, /https?:\/\//i);
  assert.doesNotMatch(html, /<(?:script|link|iframe)[^>]+(?:src|href)\s*=/i);
  assert.doesNotMatch(html, /<img[^>]+src=["'](?!data:image\/png;base64,)/i);
  assert.match(html, /Nothing is enforced by this dashboard/);
  assert.match(html, /Neither command installs production enforcement/);
  assert.match(html, /Copy was unavailable; the command is selected/);
  assert.doesNotMatch(html, /you are protected/i);
});

test('OpenAPI dashboards are explicitly passive-only and expose no protect command', () => {
  const report = scanActions([{
    name: 'deleteCustomer',
    description: 'Delete a customer record',
    http_method: 'delete',
    route_path: '/customers/{customerId}',
  }], {
    source: 'openapi',
    blindSpots: ['Undocumented endpoints are not visible.'],
  });
  const html = renderAuthorityBrain(report, { inputReference: './openapi.json' });
  const model = embeddedModel(html);

  assert.equal(model.actions[0].sourceDetail, 'DELETE /customers/{customerId}');
  assert.equal(model.actions[0].protectCommand, null);
  assert.equal(model.actions[0].verifyCommand, null);
  assert.equal(model.actions[0].handoffCommand, null);
  assert.match(html, /OpenAPI is passive-only until the durable admission edge is wired/);
});

test('writes an owner-only direct-child file atomically and refuses overwrite by default', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-brain-write-'));
  const target = writeAuthorityBrain('<!doctype html>first', { cwd: dir });

  assert.equal(target, join(dir, 'emilia-authority-brain.html'));
  assert.equal(readFileSync(target, 'utf8'), '<!doctype html>first');
  assert.equal(statSync(target).mode & 0o777, 0o600);
  assert.throws(
    () => writeAuthorityBrain('<!doctype html>second', { cwd: dir }),
    /Refusing to overwrite existing Authority Brain dashboard/,
  );
  assert.equal(readFileSync(target, 'utf8'), '<!doctype html>first');
  assert.equal(readdirSync(dir).some((entry) => entry.includes('.stage-') || entry.includes('.backup-')), false);
});

test('refuses nested, escaping, symlinked, hard-linked, and non-regular output paths', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-brain-refuse-'));
  const outside = join(tmpdir(), `emilia-brain-outside-${process.pid}.html`);
  writeFileSync(outside, 'preserve');

  assert.throws(
    () => writeAuthorityBrain('nested', { cwd: dir, outPath: 'nested/brain.html' }),
    /direct-child output file/,
  );
  assert.throws(
    () => writeAuthorityBrain('escape', { cwd: dir, outPath: '../brain.html' }),
    /direct-child output file/,
  );

  const symlink = join(dir, 'symlink.html');
  symlinkSync(outside, symlink);
  assert.throws(
    () => writeAuthorityBrain('replace', { cwd: dir, outPath: basename(symlink), force: true }),
    /symlinked output file/,
  );
  assert.equal(readFileSync(outside, 'utf8'), 'preserve');

  const original = join(dir, 'original.html');
  const hardlink = join(dir, 'hardlink.html');
  writeFileSync(original, 'preserve-hardlink');
  linkSync(original, hardlink);
  assert.throws(
    () => writeAuthorityBrain('replace', { cwd: dir, outPath: basename(hardlink), force: true }),
    /hard-linked output file/,
  );
  assert.equal(readFileSync(original, 'utf8'), 'preserve-hardlink');

  const directoryTarget = join(dir, 'directory.html');
  mkdirSync(directoryTarget);
  assert.throws(
    () => writeAuthorityBrain('replace', { cwd: dir, outPath: basename(directoryTarget), force: true }),
    /non-regular output file/,
  );
});

test('force replaces one regular file as a complete owner-only artifact', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-brain-force-'));
  const target = join(dir, 'brain.html');
  writeFileSync(target, 'old');

  writeAuthorityBrain('new-complete-dashboard', {
    cwd: dir,
    outPath: 'brain.html',
    force: true,
  });

  assert.equal(readFileSync(target, 'utf8'), 'new-complete-dashboard');
  assert.equal(statSync(target).mode & 0o777, 0o600);
  assert.equal(lstatSync(target).nlink, 1);
  assert.equal(readdirSync(dir).some((entry) => entry.includes('.stage-') || entry.includes('.backup-')), false);
  assert.deepEqual(
    readFileSync(target, 'utf8'),
    'new-complete-dashboard',
    'replacement must install the complete staged bytes',
  );
});

test('force never overwrites a file created concurrently after the original is preserved', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-brain-force-race-'));
  const target = join(dir, 'brain.html');
  writeFileSync(target, 'original-dashboard');
  const originalRenameSync = fs.renameSync;
  fs.renameSync = (source, destination) => {
    originalRenameSync(source, destination);
    if (source === target) writeFileSync(target, 'concurrent-file');
  };

  try {
    assert.throws(
      () => writeAuthorityBrain('new-dashboard', {
        cwd: dir,
        outPath: 'brain.html',
        force: true,
      }),
      /Refusing output created during Authority Brain replacement/,
    );
  } finally {
    fs.renameSync = originalRenameSync;
  }

  assert.equal(readFileSync(target, 'utf8'), 'concurrent-file');
  const backup = readdirSync(dir).find((entry) => entry.includes('.backup-'));
  assert.ok(backup, 'the displaced original must remain recoverable');
  assert.equal(readFileSync(join(dir, backup), 'utf8'), 'original-dashboard');
  assert.equal(readdirSync(dir).some((entry) => entry.includes('.stage-')), false);
});

test('brain CLI generates real MCP and OpenAPI dashboards from bounded JSON inputs', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-brain-inputs-'));
  const cli = join(import.meta.dirname, 'cli.mjs');
  writeFileSync(join(dir, 'tools.json'), JSON.stringify({
    tools: [
      { name: 'sendWire', description: 'Send an outgoing wire transfer' },
      { name: 'getAccountBalance', description: 'Read the balance' },
    ],
  }));
  writeFileSync(join(dir, 'openapi.json'), JSON.stringify({
    openapi: '3.1.0',
    paths: {
      '/customers/{customerId}': {
        delete: { operationId: 'deleteCustomer', summary: 'Delete a customer record' },
      },
    },
  }));

  const mcp = spawnSync(process.execPath, [cli, 'brain', 'tools.json', '--out', 'mcp-brain.html'], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.equal(mcp.status, 0, `${mcp.stdout}\n${mcp.stderr}`);
  const mcpModel = embeddedModel(readFileSync(join(dir, 'mcp-brain.html'), 'utf8'));
  assert.equal(mcpModel.source, 'mcp');
  assert.equal(mcpModel.actions.length, 2);
  assert.equal(mcpModel.actions[0].protectCommand,
    "npx @emilia-protocol/scan@0.5.0 protect 'tools.json' --action 'sendWire' --apply --verify");

  const openapi = spawnSync(process.execPath, [cli, 'brain', 'openapi.json', '--out', 'openapi-brain.html'], {
    cwd: dir,
    encoding: 'utf8',
  });
  assert.equal(openapi.status, 0, `${openapi.stdout}\n${openapi.stderr}`);
  const openapiModel = embeddedModel(readFileSync(join(dir, 'openapi-brain.html'), 'utf8'));
  assert.equal(openapiModel.source, 'openapi');
  assert.equal(openapiModel.actions[0].sourceDetail, 'DELETE /customers/{customerId}');
  assert.equal(openapiModel.actions[0].protectCommand, null);
});

test('brain --sample creates the default dashboard and requires explicit force to replace it', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-brain-sample-'));
  const cli = join(import.meta.dirname, 'cli.mjs');
  const first = spawnSync(process.execPath, [cli, 'brain', '--sample'], { cwd: dir, encoding: 'utf8' });

  assert.equal(first.status, 0, `${first.stdout}\n${first.stderr}`);
  assert.match(first.stdout, /Authority Brain written/);
  const output = join(dir, 'emilia-authority-brain.html');
  assert.equal(existsSync(output), true);
  assert.equal(statSync(output).mode & 0o777, 0o600);
  const model = embeddedModel(readFileSync(output, 'utf8'));
  assert.equal(model.source, 'mcp');
  assert.equal(model.inputMode, 'sample');
  assert.match(model.actions.find((action) => action.name === 'sendWire').protectCommand, /scan@0\.5\.0 protect --sample --action 'sendWire' --apply --verify/);

  const refused = spawnSync(process.execPath, [cli, 'brain', '--sample'], { cwd: dir, encoding: 'utf8' });
  assert.notEqual(refused.status, 0);
  assert.match(`${refused.stdout}${refused.stderr}`, /Refusing to overwrite/);

  const forced = spawnSync(process.execPath, [cli, 'brain', '--sample', '--force'], { cwd: dir, encoding: 'utf8' });
  assert.equal(forced.status, 0, `${forced.stdout}\n${forced.stderr}`);
});

test('brain CLI validates output arguments before reading or writing', () => {
  const cli = join(import.meta.dirname, 'cli.mjs');
  for (const args of [
    ['brain', '--sample', '--out'],
    ['brain', '--sample', '--out', '../escape.html'],
    ['brain', '--sample', '--unknown'],
    ['brain', '--sample', '--sample'],
    ['brain', '--sample', '--out', 'package.json'],
    ['brain', '--sample', '--out', 'bad\u001b[2J.html'],
  ]) {
    const dir = mkdtempSync(join(tmpdir(), 'emilia-brain-args-'));
    const run = spawnSync(process.execPath, [cli, ...args], { cwd: dir, encoding: 'utf8' });
    assert.notEqual(run.status, 0, `${args.join(' ')} unexpectedly passed`);
    assert.deepEqual(
      existsSync(join(dir, 'emilia-authority-brain.html')),
      false,
      `${args.join(' ')} must not write a dashboard`,
    );
  }
});

test('brain CLI escapes terminal controls in diagnostics', () => {
  const dir = mkdtempSync(join(tmpdir(), 'emilia-brain-diagnostic-'));
  const cli = join(import.meta.dirname, 'cli.mjs');
  const run = spawnSync(process.execPath, [cli, 'brain', 'missing\u001b[2J.json'], {
    cwd: dir,
    encoding: 'utf8',
  });

  assert.notEqual(run.status, 0);
  assert.equal(run.stderr.includes('\u001b'), false);
  assert.match(run.stderr, /\\u\{001b\}/);
});
