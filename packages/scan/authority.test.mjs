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
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  AUTHORITY_SCAN_VERSION,
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

test('authority reports the package release version from package metadata', () => {
  const packageMetadata = JSON.parse(readFileSync(join(import.meta.dirname, 'package.json'), 'utf8'));
  const packageVersion = packageMetadata.version;
  const root = mkdtempSync(join(tmpdir(), 'emilia-authority-version-'));
  const home = join(root, 'home');
  const cwd = join(home, 'project');
  mkdirSync(cwd, { recursive: true });
  assert.equal(AUTHORITY_SCAN_VERSION, packageVersion);
  assert.equal(packageMetadata.dependencies['@emilia-protocol/verify'], '^3.21.0');
  assert.equal(runAuthorityScan({
    cwd,
    home,
    applicationSupport: join(home, 'Library', 'Application Support'),
    managedCandidates: [],
    maxEnvDepth: 0,
  }).version, packageVersion);
});

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

test('short Authorization credentials are fully redacted', () => {
  for (const input of [
    'Authorization: Bearer s3cr3t',
    'Authorization: Basic dXNlcg==',
  ]) {
    const output = redactText(input);
    assert.ok(!output.includes(input.split(' ').at(-1)), input);
    assert.match(output, /<redacted (bearer|basic) credential>/);
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
    sanitizeArgs(['server-package', '--token', 'short', '--key', 'tiny', '--key=small', '--mode', 'safe']),
    [
      'server-package',
      '--token',
      '<redacted credential argument>',
      '--key',
      '<redacted credential argument>',
      '--key=<redacted credential>',
      '--mode',
      'safe',
    ],
  );
});

test('camelCase and slash-style short credentials never cross the report boundary', () => {
  const secrets = ['short-demo-secret', 'tiny-access-token'];
  const output = JSON.stringify(sanitizeForReport({
    command: `node server.js --clientSecret ${secrets[0]}`,
    args: [`/accessToken:${secrets[1]}`],
  }));
  for (const secret of secrets) assert.equal(output.includes(secret), false, secret);
  assert.match(output, /<redacted credential>/);
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

test('secret descriptors retain safe key names without retaining credential values', () => {
  assert.deepEqual(
    sanitizeForReport({ key: 'GOOGLE_AI_API_KEY', class: 'api_key', secret: true, length: 42 }),
    { key: 'GOOGLE_AI_API_KEY', class: 'api_key', secret: true, length: 42 },
  );
  assert.equal(
    sanitizeForReport({ key: 'unsafe key name with spaces', class: 'api_key', secret: true }).key,
    '<redacted invalid key name>',
  );
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

test('rendered reports redact short camelCase secret flags in split and equals forms', () => {
  const flagCases = ['clientSecret', 'accessToken', 'refreshToken', 'authToken'].flatMap(
    (flag, index) => [
      { flag, form: 'split', value: `short-${index}-split` },
      { flag, form: 'equals', value: `short-${index}-equals` },
    ],
  );
  const args = ['server-package'];
  for (const { flag, form, value } of flagCases) {
    if (form === 'split') args.push(`--${flag}`, value);
    else args.push(`--${flag}=${value}`);
  }
  const { home, cwd } = fixture({
    mcpServers: {
      hostile: { command: 'npx', args },
    },
  });
  const result = runAuthorityScan({
    cwd,
    home,
    applicationSupport: join(home, 'Library', 'Application Support'),
    managedCandidates: [],
  });

  for (const [format, output] of [
    ['json', renderAuthorityJson(result)],
    ['text', renderAuthorityText(result)],
  ]) {
    for (const { flag, form, value } of flagCases) {
      assert.equal(output.includes(value), false, `${format}: --${flag} ${form}`);
    }
  }
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

test('an absent unsupported-format candidate is reported absent', () => {
  const { home, cwd } = fixture({});
  const result = runAuthorityScan({
    cwd,
    home,
    applicationSupport: join(home, 'Library', 'Application Support'),
    managedCandidates: [],
    maxEnvDepth: 0,
  });
  const codex = result.inventory.sources.find((source) => source.runtime === 'codex');
  assert.equal(codex?.status, 'absent');
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

test('authority detection reports each consequential local-authority signal with bounded evidence', () => {
  const secret = 'authority-test-secret';
  const { home, cwd } = fixture({
    mcpServers: {
      shellRunner: {
        command: 'npx',
        args: ['shell-server'],
        env: { API_KEY: secret },
      },
      stripeControl: {
        url: 'https://api.stripe.example/mcp',
        headers: { Authorization: `Bearer ${secret}` },
      },
      disabledShell: {
        command: 'bash',
        disabled: true,
      },
    },
    permissions: {
      allow: ['Bash(curl:*)'],
      ask: ['Bash(git push:*)'],
      defaultMode: 'allowEdits',
      additionalDirectories: ['/private/shared'],
    },
  });
  mkdirSync(join(home, '.aws'), { recursive: true });
  writeFileSync(join(home, '.aws', 'credentials'), '[default]\naws_access_key_id=fake\n');
  writeFileSync(join(cwd, '.env.local'), `SERVICE_TOKEN=${secret}\n`);

  const result = runAuthorityScan({
    cwd,
    home,
    applicationSupport: join(home, 'Library', 'Application Support'),
    managedCandidates: [],
  });
  const ids = new Set(result.signals.map((signal) => signal.id));
  assert.deepEqual(
    [...ids].sort(),
    [
      'BYPASS-01',
      'BYPASS-02',
      'CRED-01',
      'CRED-02',
      'CRED-03',
      'EGRESS-01',
      'EXEC-01',
      'INFRA-01',
      'SHELL-01',
      'WILDCARD-01',
    ],
  );
  assert.equal(authorityExitCode(result), 1);
  assert.ok(!JSON.stringify(result).includes(secret));
  assert.ok(!result.signals.some((signal) => JSON.stringify(signal.observed).includes('disabledShell')));
  const text = renderAuthorityText(result);
  assert.match(text, /\[CRITICAL\] SHELL-01/);
  assert.match(text, /\[HIGH\] CRED-01/);
  assert.match(text, /\[MEDIUM\] WILDCARD-01/);
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

test('symlinked configuration sources are excluded without reading their target', () => {
  const secret = 'S7y'.repeat(20);
  const { home, cwd } = fixture({});
  const target = join(cwd, 'outside-config.json');
  writeFileSync(target, JSON.stringify({
    mcpServers: {
      unsafe: {
        command: 'node',
        env: { TOKEN: secret },
      },
    },
  }));
  unlinkSync(join(cwd, '.mcp.json'));
  symlinkSync(target, join(cwd, '.mcp.json'));
  const result = runAuthorityScan({
    cwd,
    home,
    applicationSupport: join(home, 'Library', 'Application Support'),
    managedCandidates: [],
  });
  const source = result.inventory.sources.find((entry) => (
    entry.scope === 'project' && entry.file === '~/project/.mcp.json'
  ));
  assert.equal(source?.status, 'symlink');
  assert.ok(!JSON.stringify(result).includes(secret));
  assert.ok(!result.inventory.servers.some((entry) => entry.name === 'unsafe'));
});

test('environment discovery reports when its bounded file limit is reached', () => {
  const { home, cwd } = fixture({});
  for (let index = 0; index < 201; index += 1) {
    writeFileSync(join(cwd, `.env.${index}`), `TOKEN=value-${index}\n`);
  }
  const result = runAuthorityScan({
    cwd,
    home,
    applicationSupport: join(home, 'Library', 'Application Support'),
    managedCandidates: [],
  });
  assert.ok(result.inventory.env_files.length <= 200);
  assert.ok(result.inventory.limitations.some((entry) => entry.includes('200-file limit')));
  assert.match(renderAuthorityText(result), /additional files may be omitted/);
});

test('CLI refuses a nonexistent working directory', () => {
  const root = mkdtempSync(join(tmpdir(), 'emilia-authority-invalid-cwd-'));
  const missing = join(root, 'missing');
  const result = spawnSync(process.execPath, [CLI, 'authority', '--cwd', missing], {
    encoding: 'utf8',
  });
  assert.equal(result.status, 64);
  assert.match(`${result.stdout}${result.stderr}`, /existing directory|ENOENT/i);
});

test('authority CLI requires values for every value-bearing option', () => {
  for (const [option, nextFlag] of [['--out', '--json'], ['--cwd', '-h']]) {
    const result = spawnSync(process.execPath, [CLI, 'authority', option, nextFlag], {
      encoding: 'utf8',
    });
    assert.equal(result.status, 64, `${option}\n${result.stdout}\n${result.stderr}`);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, new RegExp(`${option} requires a value`));
  }
});

test('authority CLI help publishes the complete exit-code contract', () => {
  const result = spawnSync(process.execPath, [CLI, 'authority', '--help'], {
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /\n\s+0\s+complete visible surface/);
  assert.match(result.stdout, /\n\s+1\s+signals present/);
  assert.match(result.stdout, /\n\s+2\s+malformed configuration source/);
  assert.match(result.stdout, /\n\s+3\s+operation surface not visible or not classifiable/);
  assert.match(result.stdout, /\n\s+64\s+usage, argument, or filesystem error/);
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
