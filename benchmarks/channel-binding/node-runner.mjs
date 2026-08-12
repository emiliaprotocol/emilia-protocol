// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';
import fs from 'node:fs';
import tls from 'node:tls';

const VARIANTS = Object.freeze([
  'rfc9266-connection-per-instance',
  'nonce-in-exporter-context',
  'nonce-in-message',
]);
const LABEL = 'EXPERIMENTAL EMILIA channel binding benchmark v1';

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || index + 1 >= process.argv.length) throw new Error(`missing ${name}`);
  return process.argv[index + 1];
}

function positiveInteger(name) {
  const value = Number(argument(name));
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be a positive integer`);
  return value;
}

function percentile(values, fraction) {
  const sorted = [...values].sort((left, right) => left - right);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * fraction) - 1));
  return Number((sorted[index] / 1_000).toFixed(3));
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server.address().port;
}

async function connect(port) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: '127.0.0.1',
      port,
      rejectUnauthorized: false,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    });
    socket.once('secureConnect', () => resolve(socket));
    socket.once('error', reject);
  });
}

async function closeSocket(socket) {
  if (!socket || socket.destroyed) return;
  await new Promise((resolve) => {
    socket.once('close', resolve);
    socket.end();
  });
}

async function runBatches(samples, concurrency, operation) {
  const latencies = [];
  for (let offset = 0; offset < samples; offset += concurrency) {
    const batch = Math.min(concurrency, samples - offset);
    const scheduled = Array.from({ length: batch }, (_, index) => {
      const queuedAt = process.hrtime.bigint();
      return Promise.resolve().then(() => operation(offset + index, queuedAt));
    });
    const measured = await Promise.all(scheduled);
    latencies.push(...measured);
  }
  return latencies;
}

function metrics({ variant, concurrency, samples, latencies, beforeCpu, beforeHeap, counts }) {
  const cpu = process.cpuUsage(beforeCpu);
  const heapDelta = process.memoryUsage().heapUsed - beforeHeap;
  return {
    variant,
    concurrency,
    samples,
    latency_us: {
      p50: percentile(latencies, 0.50),
      p95: percentile(latencies, 0.95),
      p99: percentile(latencies, 0.99),
    },
    cpu_us: cpu.user + cpu.system,
    allocated_bytes_estimate: Math.max(0, heapDelta),
    allocation_measurement: 'managed_heap_delta_estimate',
    lock_contention: { measurement: 'not_available', reason: 'Node.js exposes no per-operation lock-contention counter.' },
    operation_counts: counts,
  };
}

async function benchmarkBaseline(port, concurrency, samples) {
  const beforeCpu = process.cpuUsage();
  const beforeHeap = process.memoryUsage().heapUsed;
  const latencies = await runBatches(samples, concurrency, async (index, queuedAt) => {
    const socket = await connect(port);
    socket.exportKeyingMaterial(32, LABEL, Buffer.alloc(32, index & 0xff));
    await closeSocket(socket);
    return Number(process.hrtime.bigint() - queuedAt);
  });
  return metrics({
    variant: VARIANTS[0], concurrency, samples, latencies, beforeCpu, beforeHeap,
    counts: { tls_handshakes: samples, exporter_calls: samples, hmacs: 0, replay_store_inserts: 0 },
  });
}

async function benchmarkContext(port, concurrency, samples) {
  const socket = await connect(port);
  const consumed = new Set();
  const beforeCpu = process.cpuUsage();
  const beforeHeap = process.memoryUsage().heapUsed;
  const latencies = await runBatches(samples, concurrency, async (index, queuedAt) => {
    const nonce = Buffer.alloc(32);
    nonce.writeUInt32BE(index >>> 0, 28);
    socket.exportKeyingMaterial(32, LABEL, nonce);
    consumed.add(index);
    return Number(process.hrtime.bigint() - queuedAt);
  });
  await closeSocket(socket);
  return metrics({
    variant: VARIANTS[1], concurrency, samples, latencies, beforeCpu, beforeHeap,
    counts: { tls_handshakes: 1, exporter_calls: samples, hmacs: 0, replay_store_inserts: samples },
  });
}

async function benchmarkMessage(port, concurrency, samples) {
  const socket = await connect(port);
  const key = socket.exportKeyingMaterial(32, LABEL, Buffer.alloc(0));
  const consumed = new Set();
  const beforeCpu = process.cpuUsage();
  const beforeHeap = process.memoryUsage().heapUsed;
  const latencies = await runBatches(samples, concurrency, async (index, queuedAt) => {
    const frame = Buffer.alloc(114);
    frame.writeUInt32BE(index >>> 0, 2);
    crypto.createHmac('sha256', key).update(frame).digest();
    consumed.add(index);
    return Number(process.hrtime.bigint() - queuedAt);
  });
  key.fill(0);
  await closeSocket(socket);
  return metrics({
    variant: VARIANTS[2], concurrency, samples, latencies, beforeCpu, beforeHeap,
    counts: { tls_handshakes: 1, exporter_calls: 1, hmacs: samples, replay_store_inserts: samples },
  });
}

async function main() {
  const concurrency = positiveInteger('--concurrency');
  const samples = positiveInteger('--samples');
  const cert = fs.readFileSync(argument('--cert'));
  const key = fs.readFileSync(argument('--key'));
  const sockets = new Set();
  const server = tls.createServer({ cert, key, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }, (socket) => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
  });
  const port = await listen(server);
  try {
    const results = [];
    results.push(await benchmarkBaseline(port, concurrency, samples));
    results.push(await benchmarkContext(port, concurrency, samples));
    results.push(await benchmarkMessage(port, concurrency, samples));
    process.stdout.write(`${JSON.stringify({ stack: 'node-openssl', runtime: `${process.version} / OpenSSL ${process.versions.openssl}`, results })}\n`);
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
  }
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 2;
});
