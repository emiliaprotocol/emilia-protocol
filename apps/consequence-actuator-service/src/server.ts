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
  const host = environment.HOST || '0.0.0.0';
  const port = Number(environment.PORT || 8080);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error('PORT_invalid');
  }
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

export default Object.freeze({ createHttpServer, startServer });
