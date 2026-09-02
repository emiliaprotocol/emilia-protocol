// SPDX-License-Identifier: Apache-2.0
import http from 'node:http';
import { pathToFileURL } from 'node:url';

import { createProductionConsequenceActuatorConfig } from './production-config.js';
import { createConsequenceActuatorRouteHandler } from './routes.js';
import { createConsequenceActuatorRuntime } from './runtime.js';

export function createHttpServer(runtime: any) {
  const handler = createConsequenceActuatorRouteHandler(runtime);
  return http.createServer({
    maxHeaderSize: 32 * 1024,
    requestTimeout: 30_000,
    headersTimeout: 15_000,
  }, (request, response) => {
    Promise.resolve(handler(request, response)).catch(() => {
      if (response.headersSent) {
        response.destroy();
        return;
      }
      const body = Buffer.from(JSON.stringify({
        status: 'refused',
        error: { code: 'execution_failed_closed' },
      }));
      response.writeHead(503, {
        'cache-control': 'no-store',
        'content-type': 'application/json; charset=utf-8',
        'content-length': body.byteLength,
        'x-content-type-options': 'nosniff',
      });
      response.end(body);
    });
  });
}

// Bind the loopback interface unless the operator names an interface, and
// validate what they name. `??` (not `||`) so an explicitly empty HOST is a
// configuration error rather than a silent widening to every interface: this
// service owns provider credentials, and a reachable-by-default bind is not a
// posture it should fall into by accident. Matches gate-service/src/server.ts
// and consequence-control-service/src/server.ts.
export function listenSettings(environment: NodeJS.ProcessEnv | Record<string, any>) {
  const host = (environment as Record<string, any>).HOST ?? '127.0.0.1';
  const port = Number((environment as Record<string, any>).PORT ?? '8080');
  if (typeof host !== 'string' || host.length === 0 || host.length > 253
      || /[\r\n]/.test(host)) {
    throw new Error('listen_host_invalid');
  }
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error('listen_port_invalid');
  }
  return { host, port };
}

export async function startServer({
  environment = process.env,
}: { environment?: NodeJS.ProcessEnv } = {}) {
  const config = await createProductionConsequenceActuatorConfig({ environment });
  const runtime = createConsequenceActuatorRuntime(config);
  const readiness = await runtime.ready();
  if (readiness.status !== 200) {
    await runtime.close().catch(() => {});
    throw new Error('consequence_actuator_startup_not_ready');
  }
  const server = createHttpServer(runtime);
  const { host, port } = listenSettings(environment);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  let closing = false;
  const shutdown = async () => {
    if (closing) return;
    closing = true;
    server.close();
    await runtime.close().catch(() => {});
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
  return { server, runtime };
}

if (process.argv[1]
    && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startServer().catch((error) => {
    process.stderr.write(`${error?.stack ?? error}\n`);
    process.exitCode = 1;
  });
}

export default Object.freeze({ createHttpServer, listenSettings, startServer });
