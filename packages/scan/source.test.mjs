// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  diffSourceDiscovery,
  scanSourceDirectory,
  sourceDiscoveryExitCode,
} from './dist/source/index.js';
import { sourceMain } from './dist/source/cli.js';

function fixture() {
  return mkdtempSync(join(tmpdir(), 'emilia-source-scan-'));
}

function write(root, relative, contents) {
  const file = join(root, relative);
  mkdirSync(join(file, '..'), { recursive: true });
  writeFileSync(file, contents);
  return file;
}

test('discovers literal MCP, LangChain, Vercel, Genkit, Python, and Java registrations with source evidence', () => {
  const root = fixture();
  write(root, 'src/mcp.ts', `server.tool('sendWire', 'Send an outgoing wire', handler);\nserver.tool(dynamicName, handler);\n`);
  write(root, 'src/langchain.ts', `import { tool } from '@langchain/core/tools';\nconst lookup = tool(fn, { name: 'readUntrustedEmail' });\n`);
  write(root, 'src/vercel.ts', `import { tool } from 'ai';\nconst publish = tool({ name: 'sendExternalWebhook', execute });\n`);
  write(root, 'src/genkit.ts', `const deploy = ai.defineTool({ name: 'deployToProduction' }, handler);\n`);
  write(root, 'agent/tools.py', `from langchain_core.tools import tool\n@tool\ndef read_credentials():\n    return 'redacted'\n`);
  write(root, 'java/Tools.java', `@Tool(name = "runShellCommand")\npublic String run() { return ""; }\n`);

  const report = scanSourceDirectory(root);
  assert.equal(report.version, 'EP-SOURCE-DISCOVERY-v1');
  assert.equal(report.parser_version, 'emilia-source-patterns-v1');
  assert.deepEqual(report.actions.map((action) => action.name).sort(), [
    'deployToProduction',
    'readUntrustedEmail',
    'read_credentials',
    'runShellCommand',
    'sendExternalWebhook',
    'sendWire',
  ]);
  for (const action of report.actions) {
    assert.match(action.file_sha256, /^sha256:[a-f0-9]{64}$/);
    assert.match(action.registration_sha256, /^sha256:[a-f0-9]{64}$/);
    assert.equal(Number.isInteger(action.line), true);
    assert.equal(action.line > 0, true);
    assert.equal(['high', 'medium'].includes(action.confidence), true);
    assert.equal(action.parser_version, report.parser_version);
  }
  assert.equal(report.unresolved_dynamic_registrations.length, 1);
  assert.equal(report.unresolved_dynamic_registrations[0].framework, 'mcp');
  assert.match(report.limitations.join(' '), /pattern-based/);
});

test('composition findings tighten classifications and never turn a guarded action into pass-through', () => {
  const root = fixture();
  write(root, 'tools.ts', [
    `server.tool('readUntrustedEmail', handler);`,
    `server.tool('sendWire', handler);`,
    `server.tool('updateBeneficiaryBankDetails', handler);`,
    `server.tool('runShellCommand', handler);`,
    `server.tool('readCredentials', handler);`,
    `server.tool('sendExternalWebhook', handler);`,
  ].join('\n'));

  const report = scanSourceDirectory(root);
  const findingIds = new Set(report.composition_findings.map((finding) => finding.id));
  for (const id of [
    'untrusted_input_plus_money_movement',
    'mutable_destination_plus_money_movement',
    'untrusted_reader_plus_shell_executor',
    'credential_access_plus_external_transmission',
  ]) assert.equal(findingIds.has(id), true, id);
  assert.equal(report.composition_findings.every((finding) => finding.only_tightens === true), true);
  for (const action of report.actions) {
    if (action.classification_before !== 'pass_through') {
      assert.notEqual(action.classification_after, 'pass_through');
    }
  }
});

test('source evidence is deterministic and changes when reviewed source bytes change', () => {
  const root = fixture();
  const file = write(root, 'tools.ts', `server.tool('sendWire', handler);\n`);
  const first = scanSourceDirectory(root);
  const again = scanSourceDirectory(root);
  assert.deepEqual(again, first);

  writeFileSync(file, `server.tool('sendWire', saferHandler);\n`);
  const changed = scanSourceDirectory(root);
  assert.notEqual(changed.actions[0].file_sha256, first.actions[0].file_sha256);
  assert.notEqual(changed.actions[0].registration_sha256, first.actions[0].registration_sha256);
});

test('commented examples and unrelated defineTool helpers are not reported as live registrations', () => {
  const root = fixture();
  write(root, 'examples.ts', `
    import { defineTool } from 'eve/tools';
    // server.tool('commentedMcp', handler);
    /* import { tool } from 'ai';
       const hidden = tool({ name: 'commentedVercel', execute }); */
    export default defineTool({ description: 'not Genkit and has no literal action name' });
  `);
  const report = scanSourceDirectory(root);
  assert.deepEqual(report.actions, []);
  assert.deepEqual(report.unresolved_dynamic_registrations, []);
});

test('baseline diff identifies new, removed, source-changed, and unresolved registrations without editing code', () => {
  const root = fixture();
  const file = write(root, 'tools.ts', `server.tool('readBalance', handler);\nserver.tool('sendWire', handler);\n`);
  const baselineReport = scanSourceDirectory(root);
  const reviewedBaseline = baselineReport.proposed_manifest;

  writeFileSync(file, `server.tool('sendWire', changedHandler);\nserver.tool('deleteCustomer', handler);\nserver.tool(runtimeName, handler);\n`);
  const current = scanSourceDirectory(root);
  const diff = diffSourceDiscovery(current, reviewedBaseline);
  assert.deepEqual(diff.new_actions, ['deleteCustomer']);
  assert.deepEqual(diff.removed_actions, ['readBalance']);
  assert.deepEqual(diff.changed_source_actions, ['sendWire']);
  assert.equal(diff.unresolved_dynamic_registrations, 1);
  assert.equal(diff.requires_review, true);
  assert.equal(sourceDiscoveryExitCode(diff), 1);
  assert.equal(readFileSync(file, 'utf8').includes('runtimeName'), true, 'scan never edits source');
});

test('duplicate names, symlinked files, and dynamic registration are surfaced as gaps, never hidden', () => {
  const root = fixture();
  write(root, 'a.ts', `server.tool('sendWire', first);\n`);
  write(root, 'b.ts', `server.tool('sendWire', second);\nserver.tool(nameFromConfig, handler);\n`);
  const outside = write(fixture(), 'outside.ts', `server.tool('deleteEverything', handler);\n`);
  symlinkSync(outside, join(root, 'linked.ts'));

  const report = scanSourceDirectory(root);
  assert.equal(report.actions.filter((action) => action.name === 'sendWire').length, 2);
  assert.equal(report.proposed_manifest.actions.some((action) => action.match?.tool === 'sendWire'), false);
  assert.equal(report.unresolved_dynamic_registrations.length, 1);
  assert.equal(report.skipped.some((entry) => entry.reason === 'symlink'), true);
  assert.equal(report.composition_findings.some((entry) => entry.id === 'duplicate_registration_name'), true);
});

test('CLI emits JSON and diff returns review-required without offering a fix mode', () => {
  const root = fixture();
  write(root, 'tools.ts', `server.tool('sendWire', handler);\n`);
  const stdout = [];
  const stderr = [];
  const code = sourceMain(['source', root, '--json'], {
    stdout: (value) => stdout.push(value),
    stderr: (value) => stderr.push(value),
  });
  assert.equal(code, 1);
  assert.equal(JSON.parse(stdout.join('')).actions[0].name, 'sendWire');
  assert.deepEqual(stderr, []);

  const bad = sourceMain(['source', root, '--fix'], {
    stdout: () => {},
    stderr: (value) => stderr.push(value),
  });
  assert.equal(bad, 64);
  assert.match(stderr.at(-1), /unknown option: --fix/);
});

test('baseline parsing refuses duplicate JSON members instead of accepting an ambiguous review artifact', () => {
  const root = fixture();
  write(root, 'tools.ts', `server.tool('sendWire', handler);\n`);
  const baseline = write(root, 'baseline.json', '{"actions":[],"actions":[]}');
  const stderr = [];
  const code = sourceMain(['diff', '--baseline', baseline, root, '--json'], {
    stdout: () => {},
    stderr: (value) => stderr.push(value),
  });
  assert.equal(code, 64);
  assert.match(stderr.join(''), /baseline refused: duplicate object member name/);
});
