// SPDX-License-Identifier: Apache-2.0
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const allowedConcurrency = new Set([1, 10, 100, 1000]);

function optionalArgument(name) {
  const index = process.argv.indexOf(name);
  return index < 0 ? null : process.argv[index + 1];
}

function parseConcurrency() {
  const raw = optionalArgument('--concurrency');
  if (raw === null) return [1, 10, 100, 1000];
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || !allowedConcurrency.has(value)) {
    throw new Error('--concurrency must be one of 1, 10, 100, or 1000');
  }
  return [value];
}

function parseSamples() {
  const raw = optionalArgument('--samples') ?? '200';
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1 || value > 100_000) {
    throw new Error('--samples must be an integer from 1 through 100000');
  }
  return value;
}

function execute(command, arguments_, options = {}) {
  const result = spawnSync(command, arguments_, { encoding: 'utf8', ...options });
  if (result.status !== 0) throw new Error(`${command} failed:\n${result.stderr || result.stdout}`);
  return result.stdout.trim();
}

function certificate(directory) {
  const key = path.join(directory, 'key.pem');
  const cert = path.join(directory, 'cert.pem');
  execute('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-keyout', key, '-out', cert, '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
  ]);
  return { cert, key };
}

function stackResult(command, arguments_) {
  return JSON.parse(execute(command, arguments_, { cwd: here }));
}

function main() {
  const requestedConcurrency = parseConcurrency();
  const requestedSamples = parseSamples();
  const output = optionalArgument('--output');
  if (process.argv.includes('--output') && !output) throw new Error('--output requires a path');
  const directory = mkdtempSync(path.join(tmpdir(), 'emilia-channel-binding-'));
  try {
    const credential = certificate(directory);
    const byStack = new Map([
      ['go-crypto-tls', { stack: 'go-crypto-tls', runtime: null, results: [] }],
      ['node-openssl', { stack: 'node-openssl', runtime: null, results: [] }],
    ]);
    for (const concurrency of requestedConcurrency) {
      const samples = Math.max(requestedSamples, concurrency);
      const common = ['--cert', credential.cert, '--key', credential.key, '--concurrency', String(concurrency), '--samples', String(samples)];
      const go = stackResult('go', ['run', './go-runner.go', ...common]);
      const node = stackResult(process.execPath, [path.join(here, 'node-runner.mjs'), ...common]);
      for (const measured of [go, node]) {
        const target = byStack.get(measured.stack);
        target.runtime = measured.runtime;
        target.results.push(...measured.results);
      }
    }
    const report = {
      schema_version: 'EP-CHANNEL-BINDING-BENCH-v1',
      generated_at: new Date().toISOString(),
      requested_concurrency: requestedConcurrency,
      requested_samples: requestedSamples,
      effective_sample_rule: 'max(requested_samples, concurrency)',
      host: { platform: process.platform, architecture: process.arch, cpu_count: globalThis.navigator?.hardwareConcurrency ?? null },
      claim_boundary: [
        'This is a local differential benchmark, not a security proof or conformance result.',
        'The RFC 9266 row measures one fresh TLS 1.3 connection and exporter call per authentication instance.',
        'The exporter-context row uses exporter output directly and does not add an HMAC.',
        'Allocation fields are runtime estimates; scoped lock-contention counters are unavailable.',
        'Node exporter and HMAC operations are synchronous; its reused-connection rows include event-loop queue delay within each requested logical-concurrency batch.',
      ],
      stacks: [...byStack.values()],
    };
    const serialized = `${JSON.stringify(report, null, 2)}\n`;
    if (output) writeFileSync(path.resolve(output), serialized, { mode: 0o600 });
    else process.stdout.write(serialized);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

try { main(); } catch (error) { process.stderr.write(`${error.stack || error}\n`); process.exitCode = 2; }
