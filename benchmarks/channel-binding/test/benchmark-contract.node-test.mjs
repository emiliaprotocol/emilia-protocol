// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { access, mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const runner = path.join(root, 'run.mjs');

test('two-stack runner emits closed, non-secret benchmark evidence', async () => {
  await access(runner);
  const outputDirectory = await mkdtemp(path.join(tmpdir(), 'emilia-channel-bench-test-'));
  const outputPath = path.join(outputDirectory, 'result.json');
  const result = spawnSync(process.execPath, [
    runner,
    '--concurrency', '1',
    '--samples', '3',
    '--output', outputPath,
  ], {
    cwd: root,
    encoding: 'utf8',
    timeout: 120_000,
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  const report = JSON.parse(await readFile(outputPath, 'utf8'));
  assert.equal(report.schema_version, 'EP-CHANNEL-BINDING-BENCH-v1');
  assert.deepEqual(report.requested_concurrency, [1]);
  assert.equal(report.requested_samples, 3);
  assert.deepEqual(report.stacks.map((stack) => stack.stack), [
    'go-crypto-tls',
    'node-openssl',
  ]);

  for (const stack of report.stacks) {
    assert.equal(stack.results.length, 3);
    assert.deepEqual(stack.results.map((entry) => entry.variant), [
      'rfc9266-connection-per-instance',
      'nonce-in-exporter-context',
      'nonce-in-message',
    ]);
    for (const entry of stack.results) {
      assert.equal(entry.concurrency, 1);
      assert.equal(entry.samples, 3);
      assert.ok(entry.latency_us.p50 >= 0);
      assert.ok(entry.latency_us.p95 >= entry.latency_us.p50);
      assert.ok(entry.latency_us.p99 >= entry.latency_us.p95);
      assert.ok(entry.cpu_us >= 0);
      assert.equal(typeof entry.allocated_bytes_estimate, 'number');
      assert.equal(entry.lock_contention.measurement, 'not_available');
    }
    const baseline = stack.results[0];
    const context = stack.results[1];
    const message = stack.results[2];
    assert.equal(baseline.operation_counts.tls_handshakes, 3);
    assert.equal(baseline.operation_counts.exporter_calls, 3);
    assert.equal(context.operation_counts.tls_handshakes, 1);
    assert.equal(context.operation_counts.exporter_calls, 3);
    assert.equal(context.operation_counts.hmacs, 0);
    assert.equal(message.operation_counts.tls_handshakes, 1);
    assert.equal(message.operation_counts.exporter_calls, 1);
    assert.equal(message.operation_counts.hmacs, 3);
    assert.equal(message.operation_counts.replay_store_inserts, 3);
  }

  const serialized = JSON.stringify(report);
  assert.doesNotMatch(serialized, /BEGIN (?:RSA |EC )?PRIVATE KEY/);
  assert.doesNotMatch(serialized, /exporter_key|k_bind/i);
});

test('runner rejects unsupported concurrency and sample values', async () => {
  for (const arguments_ of [
    ['--concurrency', '0'],
    ['--concurrency', '1,2'],
    ['--samples', '0'],
  ]) {
    const result = spawnSync(process.execPath, [runner, ...arguments_], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.notEqual(result.status, 0);
  }
});
