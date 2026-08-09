// SPDX-License-Identifier: Apache-2.0
import http from 'node:http';

const DEFAULT_PATH = '/v1/github/deployment-protection';

class HttpBoundaryError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function send(response: http.ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}) {
  if (response.headersSent || response.destroyed) return;
  const bytes = Buffer.from(JSON.stringify(body), 'utf8');
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': String(bytes.byteLength),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    'Referrer-Policy': 'no-referrer',
    ...extra,
  });
  response.end(bytes);
}

function readRawBody(request: http.IncomingMessage, maxBodyBytes: number): Promise<Buffer> {
  const announced = Number(request.headers['content-length']);
  if (Number.isFinite(announced) && announced > maxBodyBytes) {
    request.resume();
    return Promise.reject(new HttpBoundaryError(413, 'webhook_body_too_large'));
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      request.removeListener('data', onData);
      request.removeListener('end', onEnd);
      request.resume();
      reject(error);
    };
    const onData = (chunk: Buffer) => {
      total += chunk.byteLength;
      if (total > maxBodyBytes) {
        fail(new HttpBoundaryError(413, 'webhook_body_too_large'));
        return;
      }
      chunks.push(Buffer.from(chunk));
    };
    const onEnd = () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks, total));
    };
    request.on('data', onData);
    request.on('end', onEnd);
    request.on('error', () => fail(new HttpBoundaryError(400, 'webhook_body_read_failed')));
  });
}

export function createGitHubDeploymentWebhookHttpServer({
  gate,
  path = DEFAULT_PATH,
  maxBodyBytes = 1024 * 1024,
  maxHeaderBytes = 32 * 1024,
  requestTimeoutMs = 10_000,
}: any = {}) {
  if (!gate || typeof gate.handle !== 'function'
      || typeof path !== 'string' || !path.startsWith('/') || path.includes('?')
      || !Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1 || maxBodyBytes > 25 * 1024 * 1024
      || !Number.isSafeInteger(maxHeaderBytes) || maxHeaderBytes < 1024 || maxHeaderBytes > 128 * 1024
      || !Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 100 || requestTimeoutMs > 120_000) {
    throw new TypeError('github_deployment_http_config_invalid');
  }
  const server = http.createServer({ maxHeaderSize: maxHeaderBytes }, async (request, response) => {
    try {
      let url: URL;
      try {
        url = new URL(request.url ?? '/', 'http://emilia-github-deployment.local');
      } catch {
        throw new HttpBoundaryError(400, 'request_target_invalid');
      }
      if (url.search) throw new HttpBoundaryError(400, 'query_parameters_forbidden');
      if (url.pathname !== path) {
        send(response, 404, { ok: false, status: 404, state: 'REFUSED', reason: 'route_not_found' });
        return;
      }
      if (request.method !== 'POST') {
        send(
          response,
          405,
          { ok: false, status: 405, state: 'REFUSED', reason: 'method_not_allowed' },
          { Allow: 'POST' },
        );
        return;
      }
      const body = await readRawBody(request, maxBodyBytes);
      const result = await gate.handle({ headers: request.headers, body });
      const status = Number.isSafeInteger(result?.status) && result.status >= 100 && result.status <= 599
        ? result.status
        : 500;
      send(response, status, result);
    } catch (error) {
      if (error instanceof HttpBoundaryError) {
        send(response, error.status, {
          ok: false,
          status: error.status,
          state: 'REFUSED',
          reason: error.message,
        });
        return;
      }
      send(response, 500, {
        ok: false,
        status: 500,
        state: 'INDETERMINATE',
        reason: 'webhook_internal_error',
      });
    }
  });
  server.requestTimeout = requestTimeoutMs;
  server.headersTimeout = Math.min(requestTimeoutMs, 10_000);
  return server;
}

export default Object.freeze({ createGitHubDeploymentWebhookHttpServer });
