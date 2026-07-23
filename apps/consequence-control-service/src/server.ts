// SPDX-License-Identifier: Apache-2.0
import http from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { createRequestHandler } from './routes.js';
import { createConsequenceControlRuntime } from './runtime.js';

const shutdowns = new WeakMap<object, Promise<{ ok: true; drained: boolean }>>();

export function createHttpServer(runtime: any) {
  const handleRequest = createRequestHandler(runtime);
  const server = http.createServer(
    { maxHeaderSize: runtime.limits.maxHeaderBytes },
    (request, response) => {
      void Promise.resolve(handleRequest(request, response)).catch(() => {
        if (!response.destroyed) response.destroy();
      });
    },
  );
  server.headersTimeout = 10_000;
  server.requestTimeout = runtime.limits.requestTimeoutMs;
  server.on('clientError', (_error, socket) => {
    if (socket.writable) {
      socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
    }
  });
  return server;
}

function listenSettings(environment: Record<string, any>) {
  const host = environment.HOST ?? '127.0.0.1';
  const port = Number(environment.PORT ?? '8788');
  if (typeof host !== 'string' || host.length === 0 || host.length > 253 || /[\r\n]/.test(host)) {
    throw new Error('listen_host_invalid');
  }
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error('listen_port_invalid');
  }
  return { host, port };
}

function shutdownGraceMs(environment: Record<string, any>): number {
  const value = Number(environment.EMILIA_CONSEQUENCE_SHUTDOWN_GRACE_MS ?? '15000');
  if (!Number.isSafeInteger(value) || value < 1 || value > 300_000) {
    throw new Error('shutdown_grace_invalid');
  }
  return value;
}

function waitForDeadline<T>(promise: Promise<T>, timeoutMs: number): Promise<boolean> {
  if (timeoutMs <= 0) return Promise.resolve(false);
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => finish(false), timeoutMs);
    promise.then(() => finish(true), () => finish(true));
  });
}

export async function shutdownConsequenceControlService(
  started: { server: any; runtime: any },
  { graceMs = 15_000 }: { graceMs?: number } = {},
) {
  if (!started?.server || !started?.runtime
      || typeof started.runtime.stopAdmission !== 'function'
      || typeof started.runtime.waitForIdle !== 'function'
      || typeof started.runtime.close !== 'function'
      || !Number.isSafeInteger(graceMs) || graceMs < 1 || graceMs > 300_000) {
    throw new TypeError('consequence_control_shutdown_invalid');
  }
  const existing = shutdowns.get(started.server);
  if (existing) return existing;

  const shutdown = (async () => {
    const deadline = Date.now() + graceMs;
    started.runtime.stopAdmission();
    const serverClosed = new Promise<void>((resolve) => {
      if (!started.server.listening) {
        resolve();
        return;
      }
      started.server.close(() => resolve());
      started.server.closeIdleConnections?.();
    });

    let drained = false;
    try {
      drained = await started.runtime.waitForIdle(Math.max(0, deadline - Date.now()));
      if (!drained) started.server.closeAllConnections?.();
      else started.server.closeIdleConnections?.();
      const serverDrained = await waitForDeadline(
        serverClosed,
        Math.max(0, deadline - Date.now()),
      );
      if (!serverDrained) started.server.closeAllConnections?.();
    } finally {
      await started.runtime.close({ graceMs: 0 });
    }
    return { ok: true as const, drained };
  })();
  shutdowns.set(started.server, shutdown);
  return shutdown;
}

export function installShutdownHandlers(
  started: { server: any; runtime: any },
  {
    processLike = process,
    graceMs = 15_000,
  }: { processLike?: any; graceMs?: number } = {},
) {
  if (!processLike || typeof processLike.once !== 'function'
      || typeof processLike.removeListener !== 'function') {
    throw new TypeError('consequence_control_signal_target_invalid');
  }
  let shutdown: Promise<unknown> | null = null;
  const handleSignal = () => {
    if (!shutdown) {
      shutdown = shutdownConsequenceControlService(started, { graceMs }).catch(() => {
        processLike.exitCode = 1;
        return { ok: false };
      });
    }
  };
  processLike.once('SIGTERM', handleSignal);
  processLike.once('SIGINT', handleSignal);
  return Object.freeze({
    done: () => shutdown ?? Promise.resolve(),
    dispose: () => {
      processLike.removeListener('SIGTERM', handleSignal);
      processLike.removeListener('SIGINT', handleSignal);
    },
  });
}

export async function loadRuntimeConfig(
  file: string | undefined,
  { environment = process.env }: { environment?: Record<string, any> } = {},
) {
  if (typeof file !== 'string' || file.length === 0 || file.includes('\0')) {
    throw new Error('EMILIA_CONSEQUENCE_CONFIG_required');
  }
  const moduleUrl = pathToFileURL(path.resolve(file)).href;
  const loaded = await import(moduleUrl);
  const candidate = typeof loaded.default === 'function'
    ? await loaded.default({ environment })
    : loaded.default;
  return candidate;
}

export async function startConsequenceControlService({
  environment = process.env,
  config,
}: { environment?: Record<string, any>; config?: any } = {}) {
  const selectedConfig = config ?? await loadRuntimeConfig(
    environment.EMILIA_CONSEQUENCE_CONFIG,
    { environment },
  );
  const runtime = createConsequenceControlRuntime(selectedConfig);
  let server: any;
  try {
    await runtime.initialize();
    server = createHttpServer(runtime);
    const { host, port } = listenSettings(environment);
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, host, resolve);
    });
    const started = { server, runtime, host, port };
    return Object.freeze({
      ...started,
      shutdown: (options?: { graceMs?: number }) => (
        shutdownConsequenceControlService(started, options)
      ),
    });
  } catch (error) {
    if (server?.listening) server.closeAllConnections?.();
    await runtime.close().catch(() => {});
    throw error;
  }
}

async function main() {
  try {
    const started = await startConsequenceControlService();
    installShutdownHandlers(started, {
      graceMs: shutdownGraceMs(process.env),
    });
    process.stdout.write(`EMILIA consequence-control service listening on http://${started.host}:${started.port}\n`);
  } catch {
    process.stderr.write('EMILIA consequence-control service failed to start.\n');
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}

export default Object.freeze({
  createHttpServer,
  installShutdownHandlers,
  loadRuntimeConfig,
  shutdownConsequenceControlService,
  startConsequenceControlService,
});
