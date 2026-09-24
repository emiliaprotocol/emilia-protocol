#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
/** Optional live smoke for Muse 1.3 required-server admission and failure. */
import { spawn } from 'node:child_process';
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { generateDemoConfig } from './demo-config.mjs';

const SERVER_NAME = 'emilia_payment_gate';
const RELEASE_TOOL_ID = 'mcp__emilia_payment_gate__release_payment';
const RECONCILIATION_TOOL_ID = 'mcp__emilia_payment_gate__reconcile_payment';
const PROMPT = 'Reply exactly MUSE_GATE_READY';
const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, '../..');
const SERVER_PATH = resolve(SCRIPT_DIRECTORY, 'server.mjs');

function run(command, args, { env = process.env, timeoutMs = 45_000 } = {}) {
  return new Promise((resolveRun, reject) => {
    const child = spawn(command, args, {
      cwd: REPOSITORY_ROOT,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
    }, timeoutMs);
    timer.unref();
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      resolveRun({ code, signal, stdout, stderr });
    });
  });
}

async function findFiles(root, predicate) {
  const found = [];
  async function visit(path) {
    let entries;
    try {
      entries = await readdir(path, { withFileTypes: true });
    } catch (error) {
      if (error?.code === 'ENOENT') return;
      throw error;
    }
    for (const entry of entries) {
      const entryPath = join(path, entry.name);
      if (entry.isDirectory()) await visit(entryPath);
      else if (entry.isFile() && predicate(entryPath)) found.push(entryPath);
    }
  }
  await visit(root);
  return found;
}

function jsonLines(text) {
  return text
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .flatMap((line) => {
      try {
        return [JSON.parse(line)];
      } catch {
        return [];
      }
    });
}

async function combinedText(paths) {
  return (await Promise.all(paths.map((path) => readFile(path, 'utf8')))).join('\n');
}

async function makeMuseHome(root, settings) {
  const configRoot = join(root, 'config');
  const dataRoot = join(root, 'data');
  const stateRoot = join(root, 'state');
  const runtimeRoot = join(root, 'runtime');
  await Promise.all([
    mkdir(join(configRoot, 'muse'), { recursive: true, mode: 0o700 }),
    mkdir(dataRoot, { recursive: true, mode: 0o700 }),
    mkdir(stateRoot, { recursive: true, mode: 0o700 }),
    mkdir(runtimeRoot, { recursive: true, mode: 0o700 }),
  ]);
  await writeFile(
    join(configRoot, 'muse', 'settings.json'),
    `${JSON.stringify(settings, null, 2)}\n`,
    { mode: 0o600 },
  );
  return {
    dataRoot,
    env: {
      ...process.env,
      XDG_CONFIG_HOME: configRoot,
      XDG_DATA_HOME: dataRoot,
      XDG_STATE_HOME: stateRoot,
      XDG_RUNTIME_DIR: runtimeRoot,
      MUSE_NO_AUTO_UPDATE: '1',
    },
  };
}

/** @param {{ command: string, args: string[], env?: Record<string, string> }} options */
function requiredServerSettings({ command, args, env }) {
  return {
    schema_version: 1,
    mcp_servers: {
      [SERVER_NAME]: {
        transport: 'stdio',
        command,
        args,
        ...(env ? { env } : {}),
        enabled: true,
        mode: 'required',
      },
    },
  };
}

const museArgs = (prompt) => [
  'exec',
  '--provider', 'echo',
  '--json',
  '--disable-web-tools',
  '--approval-mode', 'never',
  '--no-foreign-personal-context',
  prompt,
];

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

async function runReadyCase(museBinary, root) {
  const gate = await generateDemoConfig(join(root, 'gate'));
  const home = await makeMuseHome(root, requiredServerSettings({
    command: process.execPath,
    args: [SERVER_PATH],
    env: { EMILIA_MUSE_GATE_CONFIG: gate.configPath },
  }));
  const result = await run(museBinary, museArgs(PROMPT), { env: home.env });
  const tracePaths = await findFiles(home.dataRoot, (path) => path.endsWith('.log'));
  const sessionPaths = await findFiles(home.dataRoot, (path) => path.endsWith('session.jsonl'));
  const traces = await combinedText(tracePaths);
  const sessions = jsonLines(await combinedText(sessionPaths));
  const output = jsonLines(result.stdout);

  requireCondition(result.code === 0, `ready case exited ${result.code ?? result.signal}`);
  requireCondition(output.some((entry) => entry.payload_type === 'run.terminal.completed'),
    'ready case did not complete the echo session');
  requireCondition(new RegExp(`event="mcp\\.transport\\.startup".*server="${SERVER_NAME}".*mode="required".*outcome="ready"`).test(traces),
    'required MCP transport was not ready');
  requireCondition(new RegExp(`event="mcp\\.handshake".*server="${SERVER_NAME}".*mode="required".*outcome="ready"`).test(traces),
    'required MCP handshake was not ready');
  requireCondition(new RegExp(`event="mcp\\.capability\\.discovery".*server="${SERVER_NAME}".*outcome="ready".*tool_count=2`).test(traces),
    'required MCP tool discovery did not report both tools');
  requireCondition(sessions.some((entry) => entry.payload_type === 'runtime.mcp_tool_identity_catalog'
    && entry.payload?.entries?.some((tool) => tool.canonical_id === RELEASE_TOOL_ID)),
  `${RELEASE_TOOL_ID} was absent from the Muse tool identity catalog`);
  requireCondition(sessions.some((entry) => entry.payload_type === 'runtime.mcp_tool_identity_catalog'
    && entry.payload?.entries?.some((tool) => tool.canonical_id === RECONCILIATION_TOOL_ID)),
  `${RECONCILIATION_TOOL_ID} was absent from the Muse tool identity catalog`);
  return {
    exit: result.code,
    tools: [RELEASE_TOOL_ID, RECONCILIATION_TOOL_ID],
    traceFiles: tracePaths.length,
  };
}

async function runBrokenRequiredCase(museBinary, root) {
  const missingCommand = join(root, 'definitely-missing-mcp-server');
  const home = await makeMuseHome(root, requiredServerSettings({
    command: missingCommand,
    args: [],
  }));
  const result = await run(museBinary, museArgs(PROMPT), { env: home.env });
  const tracePaths = await findFiles(home.dataRoot, (path) => path.endsWith('.log'));
  const traces = await combinedText(tracePaths);
  const output = jsonLines(result.stdout);

  requireCondition(result.code !== 0, 'broken required server unexpectedly admitted the session');
  requireCondition(output.some((entry) => entry.payload_type === 'run.terminal.failed'
    && entry.payload?.reason?.includes(`Required MCP server \`${SERVER_NAME}\` failed during startup`)),
  'broken required server did not produce the expected terminal failure');
  requireCondition(!result.stdout.includes(`echo: ${PROMPT}`),
    'echo provider ran despite the broken required server');
  requireCondition(new RegExp(`event="mcp\\.transport\\.startup".*server="${SERVER_NAME}".*mode="required".*outcome="failed".*reason="command_unavailable"`).test(traces),
    'broken required server did not produce command_unavailable trace evidence');
  return { exit: result.code, reason: 'command_unavailable', traceFiles: tracePaths.length };
}

async function runDeterministicInvocationBoundaryCase(museBinary, root) {
  const gate = await generateDemoConfig(join(root, 'gate'));
  const home = await makeMuseHome(root, requiredServerSettings({
    command: process.execPath,
    args: [SERVER_PATH],
    env: { EMILIA_MUSE_GATE_CONFIG: gate.configPath },
  }));
  const prompt = `Call ${RELEASE_TOOL_ID} exactly once with the authorized arguments in ${gate.callPath}`;
  const result = await run(museBinary, museArgs(prompt), { env: home.env });
  const help = await run(museBinary, ['exec', '--help'], { env: home.env, timeoutMs: 10_000 });
  let providerLedger = null;
  try {
    providerLedger = await readFile(gate.config.provider_ledger_file, 'utf8');
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  requireCondition(result.code === 0, `echo limitation case exited ${result.code ?? result.signal}`);
  requireCondition(JSON.stringify(jsonLines(result.stdout)).includes(prompt),
    'echo provider did not return the submitted tool-call prompt as text');
  requireCondition(providerLedger === null,
    'echo provider unexpectedly invoked release_payment');
  requireCondition(!help.stdout.includes('--tool-call') && !help.stdout.includes('--force-tool'),
    'Muse exec unexpectedly exposes a deterministic forced-tool option; update the smoke to use it');
  return {
    provider: 'echo',
    attempted_prompt: true,
    release_payment_invoked: false,
    limitation: 'Muse Code 1.3 echo mode returns the prompt as text and muse exec exposes no forced or scripted tool-call option. A deterministic release_payment call therefore requires a direct MCP client; using a model would not be deterministic.',
  };
}

async function main() {
  const museBinary = process.argv[2] ?? process.env.MUSE_BIN ?? 'muse';
  let version;
  try {
    version = await run(museBinary, ['--version'], { timeoutMs: 10_000 });
  } catch (error) {
    throw new Error(`Muse binary unavailable (${museBinary}): ${error.message}`);
  }
  requireCondition(version.code === 0, `Muse version check exited ${version.code ?? version.signal}`);
  const versionText = `${version.stdout}\n${version.stderr}`.trim();
  requireCondition(/Muse Code 1\.3\./.test(versionText),
    `this smoke targets Muse Code 1.3.x; found: ${versionText || 'unknown version'}`);

  const smokeRoot = await mkdtemp(join(tmpdir(), 'emilia-muse-1.3-smoke-'));
  try {
    const ready = await runReadyCase(museBinary, join(smokeRoot, 'ready'));
    const brokenRequired = await runBrokenRequiredCase(museBinary, join(smokeRoot, 'broken-required'));
    const deterministicInvocation = await runDeterministicInvocationBoundaryCase(
      museBinary,
      join(smokeRoot, 'deterministic-invocation'),
    );
    process.stdout.write(`${JSON.stringify({
      ok: true,
      muse: versionText,
      settings_shape: 'mcp_servers/transport',
      ready,
      broken_required: brokenRequired,
      deterministic_invocation: deterministicInvocation,
    }, null, 2)}\n`);
  } finally {
    if (process.env.MUSE_SMOKE_KEEP === '1') {
      process.stderr.write(`Muse smoke artifacts kept at ${smokeRoot}\n`);
    } else {
      await rm(smokeRoot, { recursive: true, force: true });
    }
  }
}

main().catch((error) => {
  process.stderr.write(`Muse 1.3 smoke failed: ${error.message}\n`);
  process.exitCode = 1;
});
