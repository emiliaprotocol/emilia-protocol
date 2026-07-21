// SPDX-License-Identifier: Apache-2.0
// Generated from server.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
import http from 'node:http';
import { pathToFileURL } from 'node:url';
import { loadGateServiceConfig } from './config.js';
import { createGateRuntime } from './runtime.js';
import { createRequestHandler } from './routes.js';
const shutdowns = new WeakMap();
const serverLifecycles = new WeakMap();
export function createHttpServer(runtime) {
    const handleRequest = createRequestHandler(runtime);
    const lifecycle = { active: 0, waiters: new Set() };
    const server = http.createServer({ maxHeaderSize: runtime.limits.maxHeaderBytes }, (request, response) => {
        lifecycle.active += 1;
        const complete = () => {
            lifecycle.active -= 1;
            if (lifecycle.active === 0) {
                for (const resolve of lifecycle.waiters)
                    resolve();
                lifecycle.waiters.clear();
            }
        };
        void Promise.resolve(handleRequest(request, response))
            .catch(() => {
            if (!response.destroyed)
                response.destroy();
        })
            .finally(complete);
    });
    serverLifecycles.set(server, lifecycle);
    server.headersTimeout = 10_000;
    server.requestTimeout = runtime.limits.requestTimeoutMs;
    server.on('clientError', (_error, socket) => {
        if (!socket.writable)
            return;
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
function settleWithin(promise, milliseconds) {
    return new Promise((resolve) => {
        let settled = false;
        const timer = setTimeout(() => {
            if (settled)
                return;
            settled = true;
            resolve({ settled: false, value: null });
        }, milliseconds);
        promise.then((value) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            resolve({ settled: true, value });
        }, () => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            resolve({ settled: true, value: false });
        });
    });
}
function beginServerClose(server) {
    if (!server.listening)
        return;
    server.close(() => { });
    server.closeIdleConnections?.();
}
function activeRequestsDrained(server) {
    const lifecycle = serverLifecycles.get(server);
    if (!lifecycle || lifecycle.active === 0)
        return Promise.resolve(true);
    return new Promise((resolve) => lifecycle.waiters.add(() => resolve(true)));
}
export function shutdownGateService({ server, runtime }, { graceMs = server?.requestTimeout, adapterCloseTimeoutMs = runtime?.limits?.connectorTimeoutMs, } = {}) {
    if (!server || !runtime || typeof runtime.markUnready !== 'function'
        || typeof runtime.close !== 'function') {
        return Promise.reject(new TypeError('shutdown requires a server and runtime'));
    }
    if (!Number.isSafeInteger(graceMs) || graceMs < 0
        || !Number.isSafeInteger(adapterCloseTimeoutMs) || adapterCloseTimeoutMs < 0) {
        return Promise.reject(new TypeError('shutdown timeouts must be non-negative safe integers'));
    }
    const existing = shutdowns.get(server);
    if (existing)
        return existing;
    runtime.markUnready();
    const operation = (async () => {
        beginServerClose(server);
        const drain = await settleWithin(activeRequestsDrained(server), graceMs);
        const drained = drain.settled && drain.value === true;
        const forced = !drained;
        if (forced)
            server.closeAllConnections?.();
        else
            server.closeIdleConnections?.();
        const adapterClose = runtime.close();
        const adapters = await settleWithin(adapterClose, adapterCloseTimeoutMs);
        const adapterSummary = adapters.value;
        return {
            drained,
            forced,
            graceMs,
            adaptersClosed: adapters.settled
                && adapterSummary?.failed === 0,
        };
    })();
    shutdowns.set(server, operation);
    return operation;
}
/**
 * @param {Awaited<ReturnType<typeof startGateService>>} started
 * @param {{
 *   processLike?: NodeJS.Process,
 *   graceMs?: number,
 *   adapterCloseTimeoutMs?: number
 * }} [options]
 */
export function installShutdownHandlers(started, { processLike = process, graceMs, adapterCloseTimeoutMs, } = {}) {
    let shutdownPromise = null;
    const begin = () => {
        if (!shutdownPromise) {
            shutdownPromise = shutdownGateService(started, { graceMs, adapterCloseTimeoutMs })
                .then((result) => {
                processLike.exitCode = result.adaptersClosed ? 0 : 1;
                return result;
            })
                .catch((error) => {
                processLike.exitCode = 1;
                try {
                    processLike.stderr?.write?.('EMILIA Gate service shutdown failed.\n');
                }
                catch { /* no-op */ }
                throw error;
            });
        }
        return shutdownPromise;
    };
    processLike.once('SIGTERM', begin);
    processLike.once('SIGINT', begin);
    return {
        begin,
        dispose() {
            processLike.removeListener('SIGTERM', begin);
            processLike.removeListener('SIGINT', begin);
        },
        get shutdownPromise() { return shutdownPromise; },
    };
}
export async function startGateService({ environment = process.env } = {}) {
    const config = await loadGateServiceConfig(environment.EMILIA_GATE_CONFIG, { environment });
    const runtime = createGateRuntime(config);
    let server;
    try {
        await runtime.initialize();
        server = createHttpServer(runtime);
        const { host, port } = listenSettings(environment);
        await new Promise((resolve, reject) => {
            server.once('error', reject);
            server.listen(port, host, resolve);
        });
        return { server, runtime, host, port };
    }
    catch (error) {
        if (server?.listening)
            server.closeAllConnections?.();
        await runtime.close();
        throw error;
    }
}
async function main() {
    try {
        const started = await startGateService();
        installShutdownHandlers(started);
        process.stdout.write(`EMILIA Gate service listening on http://${started.host}:${started.port}\n`);
    }
    catch {
        process.stderr.write('EMILIA Gate service failed to start (configuration, reconciliation, or bind error).\n');
        process.exitCode = 1;
    }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    await main();
}
