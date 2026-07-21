// SPDX-License-Identifier: Apache-2.0
// Reference / experimental Envoy ext_authz + nginx auth_request HTTP service.
/// <reference path="./pg.d.ts" />

import { createServer, type IncomingHttpHeaders, type ServerResponse } from 'node:http';
import { Pool } from 'pg';
import { parseReceiptCarrier, verifyEmiliaReceipt } from '../../../packages/require-receipt/index.js';
import { createReceiptRequiredEdgeHandler, type EdgeRefusal } from '../../../packages/require-receipt/src/edge.js';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function jsonStringArray(value: string, name: string): string[] {
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw new Error(`${name} must be JSON`); }
  if (!Array.isArray(parsed) || parsed.length === 0
      || parsed.some((entry) => typeof entry !== 'string' || entry.length === 0)) {
    throw new Error(`${name} must be a non-empty JSON string array`);
  }
  return parsed;
}

function first(headers: IncomingHttpHeaders, name: string): string | undefined {
  const value = headers[name];
  return Array.isArray(value) ? value[0] : value;
}

function originalRequest(headers: IncomingHttpHeaders) {
  const method = first(headers, 'x-ep-original-method');
  const uri = first(headers, 'x-ep-original-uri');
  const host = first(headers, 'x-ep-original-host');
  const scheme = first(headers, 'x-ep-original-scheme') || 'https';
  const bodyLength = first(headers, 'x-ep-original-content-length') || '0';
  if (!method || !uri || !uri.startsWith('/') || uri.startsWith('//') || !host
      || !/^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$/.test(host) || !['http', 'https'].includes(scheme)
      || !/^(?:0|[1-9][0-9]*)$/.test(bodyLength)) {
    throw new Error('proxy_metadata_invalid');
  }
  return {
    method,
    url: `${scheme}://${host}${uri}`,
    headers,
    bodyByteLength: Number(bodyLength),
  };
}

function sendProblem(response: ServerResponse, refusal: EdgeRefusal) {
  response.writeHead(refusal.status, refusal.headers);
  response.end(JSON.stringify(refusal.body));
}

const action = required('EP_ACTION');
const trustedKeys = jsonStringArray(required('EP_TRUSTED_KEYS'), 'EP_TRUSTED_KEYS');
const requiredFields = jsonStringArray(required('EP_REQUIRED_FIELDS'), 'EP_REQUIRED_FIELDS');
const databaseUrl = required('DATABASE_URL');
const pool = new Pool({ connectionString: databaseUrl, max: 8 });

const authorize = createReceiptRequiredEdgeHandler({
  action,
  // ext_authz/auth_request do not receive authoritative request bodies in this
  // reference profile. Pin one immutable projected action hash. Variable-body
  // services need a server-owned projector such as the Worker reference.
  actionHash: required('EP_ACTION_HASH'),
  authorization: {
    authorization_endpoint: required('EP_AUTHORIZATION_ENDPOINT'),
    flow: 'EP-APPROVAL-v1',
  },
  requiredFields,
  ...(process.env.EP_CAID_SELECTOR_FIELD
    ? { caidSelector: { field: process.env.EP_CAID_SELECTOR_FIELD } }
    : {}),
  maxAgeSec: Number(process.env.EP_MAX_AGE_SEC || '900'),
  maxBodyBytes: Number(process.env.EP_MAX_BODY_BYTES || '1048576'),
  async verifyReceipt(carrier, context) {
    const document = parseReceiptCarrier(carrier);
    if (!document) return { ok: false, reason: 'malformed_receipt' };
    const verification = verifyEmiliaReceipt(document, {
      trustedKeys,
      allowInlineKey: false,
      action: context.action,
      actionHash: context.action_hash,
      requiredFields: context.required_fields,
      caidSelector: context.caid_selector,
      maxAgeSec: Number(process.env.EP_MAX_AGE_SEC || '900'),
    });
    return verification.ok
      ? { ok: true, receipt_id: verification.receipt_id, action: context.action }
      : { ok: false, reason: verification.reason };
  },
  async consume(receiptId, context) {
    const result = await pool.query(
      `INSERT INTO ep_edge_receipt_consumptions (action, receipt_id)
       VALUES ($1, $2)
       ON CONFLICT (action, receipt_id) DO NOTHING
       RETURNING receipt_id`,
      [context.action, receiptId],
    );
    return result.rowCount === 1;
  },
});

const server = createServer(async (request, response) => {
  try {
    const input = originalRequest(request.headers);
    const challengeOnly = first(request.headers, 'x-ep-challenge-only') === '1';
    if (challengeOnly) {
      input.headers = { ...input.headers };
      delete input.headers['x-emilia-receipt'];
    }
    const decision = await authorize(input);
    if (decision.ok) {
      response.writeHead(200, decision.upstream.set_headers);
      response.end();
      return;
    }

    // nginx auth_request recognizes only 2xx/401/403. Its public error_page
    // performs a second challenge-only request and returns the handler's 428.
    if (first(request.headers, 'x-ep-auth-request-mode') === 'nginx' && !challengeOnly) {
      response.writeHead(403, {
        'cache-control': 'no-store',
        'x-ep-refusal-reason': decision.body.rejected?.reason || 'receipt_required',
      });
      response.end();
      return;
    }
    sendProblem(response, decision);
  } catch {
    // Proxy metadata or database/verifier failures never reach the upstream.
    response.writeHead(503, { 'cache-control': 'no-store', 'content-type': 'text/plain; charset=utf-8' });
    response.end('receipt authorization unavailable');
  }
});

const port = Number(process.env.PORT || '8788');
server.listen(port, '0.0.0.0', () => {
  process.stdout.write(`experimental Receipt Required auth service listening on ${port}\n`);
});

async function shutdown() {
  server.close();
  await pool.end();
}
process.once('SIGTERM', () => { void shutdown(); });
process.once('SIGINT', () => { void shutdown(); });
