// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  authorityExitCode,
  describeSecret,
  redactText,
  renderAuthorityJson,
  renderAuthorityText,
  runAuthorityScan,
  sanitizeArgs,
  sanitizeForReport,
} from './dist/authority/index.js';

const CLI = join(import.meta.dirname, 'cli.mjs');

test('both published npm bin targets start with a Node shebang', () => {
  for (const file of ['cli.mjs', 'codemod.mjs']) {
    assert.equal(
      readFileSync(join(import.meta.dirname, file), 'utf8').split('\n', 1)[0],
      '#!/usr/bin/env node',
      file,
    );
  }
});

function fixture(config = {}) {
  const root = mkdtempSync(join(tmpdir(), 'emilia-authority-scan-'));
  const home = join(root, 'home');
  const cwd = join(home, 'project');
  mkdirSync(cwd, { recursive: true });
  writeFileSync(join(cwd, '.mcp.json'), JSON.stringify(config), { mode: 0o600 });
  return { root, home, cwd };
}

test('underscore-separated secret key names are detected', () => {
  for (const key of ['MY_SECRET', 'GOOGLE_AI_API_KEY', 'GH_TOKEN', 'DB_PASSWORD']) {
    assert.equal(describeSecret(key, 'short').secret, true, key);
  }
});

test('generic bearer values, assignments, URLs, and high-entropy tokens are redacted', () => {
  const secret = 'A9z'.repeat(20);
  const values = [
    `Authorization: Bearer ${secret}`,
    `--api-key=${secret}`,
    `TOKEN=${secret}`,
    `password: ${secret}`,
    `https://user:${secret}@example.com/private/${secret}?token=${secret}`,
  ];
  for (const value of values) {
    const output = redactText(value);
    assert.ok(!output.includes(secret), value);
    assert.match(output, /<redacted/);
  }
});

test('PEM blocks and embedded connection strings are removed as complete values', () => {
  const pem = [
    '-----BEGIN PRIVATE KEY-----',
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
    '1234567890abcdefghijklmnopqrstuvwxyz',
    '-----END PRIVATE KEY-----',
  ].join('\n');
  const input = `command --certificate '${pem}' --cache redis://opaquecredential@example.com/0`;
  const output = redactText(input);
  assert.ok(!output.includes('abcdefghijklmnopqrstuvwxyz'));
  assert.ok(!output.includes('opaquecredential'));
  assert.match(output, /<redacted/);
});

test('secret flags redact the next argument even when the value has low entropy', () => {
  assert.deepEqual(
    sanitizeArgs(['server-package', '--token', 'short', '--mode', 'safe']),
    ['server-package', '--token', '<redacted credential argument>', '--mode', 'safe'],
  );
});

test('recursive report sanitizer removes secrets from arbitrary future fields', () => {
  const secret = 'Q7v'.repeat(20);
  const output = JSON.stringify(sanitizeForReport({
    nested: [{ authorization: secret }],
    freeform: `Bearer ${secret}`,
    args: ['--token', secret],
  }));
  assert.ok(!output.includes(secret));
});

test('MCP args and permission rules do not leak fake credentials in either output format', () => {
  const secret = 'R4n'.repeat(20);
  const { home, cwd } = fixture({
    mcpServers: {
      example: {
        command: 'npx',
        args: ['example-server', '--api-key', secret, `--header=Authorization: Bearer ${secret}`],
        env: { MY_SECRET: secret },
      },
    },
    permissions: {
      allow: [`Bash(curl -H "Authorization: Bearer ${secret}")`],
    },
  });
  const result = runAuthorityScan({
    cwd,
    home,
    applicationSupport: join(home, 'Library', 'Application Support'),
    managedCandidates: [],
  });
  const outputs = [renderAuthorityJson(result), renderAuthorityText(result)];
  for (const output of outputs) {
    assert.ok(!output.includes(secret));
  }
  assert.match(outputs[0], /<redacted/);
  const server = result.inventory.servers.find((entry) => entry.name === 'example');
  assert.ok(server);
  assert.deepEqual(server.args.slice(1, 3), ['--api-key', '<redacted credential argument>']);
});

test('unsupported TOML is excluded rather than called malformed or clean', () => {
  const { home, cwd } = fixture({});
  mkdirSync(join(home, '.codex'), { recursive: true });
  writeFileSync(join(home, '.codex', 'config.toml'), 'model = "safe"\n');
  const result = runAuthorityScan({
    cwd,
    home,
    applicationSupport: join(home, 'Library', 'Application Support'),
    managedCandidates: [],
  });
  const codex = result.inventory.sources.find((source) => source.runtime === 'codex');
  assert.equal(codex?.status, 'unsupported_format');
  assert.equal(authorityExitCode(result), 3);
});

test('malformed and duplicate-member JSON fail distinctly', () => {
  const { home, cwd } = fixture({});
  writeFileSync(join(cwd, '.mcp.json'), '{"mcpServers":{},"mcpServers":{"x":{}}}');
  const result = runAuthorityScan({
    cwd,
    home,
    applicationSupport: join(home, 'Library', 'Application Support'),
    managedCandidates: [],
  });
  assert.ok(result.inventory.sources.some((source) => source.status === 'malformed'));
  assert.equal(authorityExitCode(result), 2);
});

test('configuration-only scans never return a reassuring zero', () => {
  const { home, cwd } = fixture({});
  const result = runAuthorityScan({
    cwd,
    home,
    applicationSupport: join(home, 'Library', 'Application Support'),
    managedCandidates: [],
  });
  assert.equal(result.summary.coverage.computable, false);
  assert.notEqual(authorityExitCode(result), 0);
});

test('writability claim is tied to an actual current-process access check', () => {
  const { home, cwd } = fixture({ permissions: { allow: ['Bash(npm test)'] } });
  const result = runAuthorityScan({
    cwd,
    home,
    applicationSupport: join(home, 'Library', 'Application Support'),
    managedCandidates: [],
  });
  const permission = result.inventory.permissions.find((entry) => entry.source.endsWith('.mcp.json'));
  assert.equal(permission?.writable_by_current_process, true);
  assert.ok(result.signals.some((signal) => signal.id === 'BYPASS-01'));
});

test('environment-file discovery skips symlinks and emits key metadata only', () => {
  const secret = 'T8m'.repeat(20);
  const { home, cwd } = fixture({});
  writeFileSync(join(cwd, '.env'), `GOOGLE_AI_API_KEY=${secret}\n`);
  writeFileSync(join(cwd, 'outside.env'), `TOKEN=${secret}\n`);
  symlinkSync(join(cwd, 'outside.env'), join(cwd, '.env.link'));
  const result = runAuthorityScan({
    cwd,
    home,
    applicationSupport: join(home, 'Library', 'Application Support'),
    managedCandidates: [],
  });
  const serialized = JSON.stringify(result.inventory.env_files);
  assert.ok(!serialized.includes(secret));
  assert.ok(result.inventory.env_files.some((entry) => entry.path.endsWith('/.env')));
  assert.ok(!result.inventory.env_files.some((entry) => entry.path.endsWith('/.env.link')));
});

test('CLI writes owner-only reports and refuses overwrite or report-path symlinks', () => {
  const { home, cwd } = fixture({});
  const output = join(cwd, 'authority-report.json');
  const env = { ...process.env, HOME: home };
  const first = spawnSync(process.execPath, [CLI, 'authority', '--json', '--cwd', cwd, '--out', output], {
    encoding: 'utf8',
    env,
  });
  assert.ok(first.status === 1 || first.status === 3, `${first.stdout}\n${first.stderr}`);
  assert.equal(statSync(output).mode & 0o777, 0o600);
  assert.doesNotThrow(() => JSON.parse(readFileSync(output, 'utf8')));

  const second = spawnSync(process.execPath, [CLI, 'authority', '--json', '--cwd', cwd, '--out', output], {
    encoding: 'utf8',
    env,
  });
  assert.equal(second.status, 64);
  assert.match(`${second.stdout}${second.stderr}`, /refusing to overwrite/i);

  const target = join(cwd, 'target.json');
  const link = join(cwd, 'linked.json');
  writeFileSync(target, 'unchanged');
  symlinkSync(target, link);
  const linked = spawnSync(process.execPath, [CLI, 'authority', '--json', '--cwd', cwd, '--out', link], {
    encoding: 'utf8',
    env,
  });
  assert.equal(linked.status, 64);
  assert.equal(readFileSync(target, 'utf8'), 'unchanged');
  assert.equal(lstatSync(link).isSymbolicLink(), true);
});
