// SPDX-License-Identifier: Apache-2.0
import http from 'node:http';
import { pathToFileURL } from 'node:url';
import { loadGateServiceConfig } from './config.js';
import { createGateRuntime } from './runtime.js';
import { createRequestHandler } from './routes.js';

export function createHttpServer(runtime) {
  const server = http.createServer({ maxHeaderSize: runtime.limits.maxHeaderBytes }, createRequestHandler(runtime));
  server.headersTimeout = 10_000;
  server.requestTimeout = Math.max(30_000, (runtime.limits.connectorTimeoutMs * 2) + 5_000);
  server.on('clientError', (_error, socket) => {
    if (!socket.writable) return;
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
  });
  return server;
}

function listenSettings(environment) {
  const host = environment.HOST ?? '127.0.0.1';
  const rawPort = environment.PORT ?? '8787';
  const port = Number(rawPort);
  if (typeof host !== 'string' || host.length === 0 || host.length > 253 || /[\r\n]/.test(host)) {
    throw new Error('listen_host_invalid');
  }
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error('listen_port_invalid');
  }
  return { host, port };
}

export async function startGateService({ environment = process.env } = {}) {
  const config = await loadGateServiceConfig(environment.EMILIA_GATE_CONFIG);
  const runtime = createGateRuntime(config);
  const server = createHttpServer(runtime);
  const { host, port } = listenSettings(environment);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  return { server, host, port };
}

async function main() {
  try {
    const started = await startGateService();
    process.stdout.write(`EMILIA Gate service listening on http://${started.host}:${started.port}\n`);
  } catch {
    process.stderr.write('EMILIA Gate service failed to start (configuration or bind error).\n');
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
