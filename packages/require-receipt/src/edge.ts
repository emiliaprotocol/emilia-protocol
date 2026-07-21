// SPDX-License-Identifier: Apache-2.0
//
// Runtime-neutral Receipt Required enforcement for edge proxies. This module
// deliberately depends only on Web Platform primitives. Cryptographic trust is
// injected by the relying party; this layer supplies bounded carrier handling,
// exact action context, optional one-time consumption, and a strict RFC 7807
// refusal. It never forwards the proof carrier to the protected upstream.

import { approvalActionHash } from './acquisition.js';

type JsonObject = Record<string, unknown>;
type HeaderValue = string | string[] | undefined;
type HeaderSource = Headers | Iterable<[string, string]> | Record<string, HeaderValue>;

export type EdgeRequestLike = {
  method?: unknown;
  url?: unknown;
  headers?: HeaderSource;
  body?: unknown;
  bodyByteLength?: unknown;
  clone?: () => { body?: ReadableStream<Uint8Array> | null };
};

export type EdgeVerificationContext = {
  action: string;
  action_hash?: string;
  required_fields: string[];
  caid_selector?: { field: string };
  observed_action?: JsonObject;
  request: {
    method: string;
    url: string;
    body_bytes: number;
  };
};

export type EdgeVerificationResult =
  | { ok: true; receipt_id?: string; receiptId?: string; action?: string; bound_action?: string }
  | { ok: false; reason?: string; [key: string]: unknown };

export type EdgeRefusal = {
  ok: false;
  status: 428;
  headers: Record<string, string>;
  body: {
    type: string;
    title: string;
    status: 428;
    detail: string;
    instance?: string;
    required: JsonObject;
    rejected?: { reason: string };
  };
};

export type EdgeAllow = {
  ok: true;
  status: 200;
  upstream: {
    method: string;
    url: string;
    redirect: 'manual';
    remove_headers: string[];
    set_headers: Record<string, string>;
  };
  authorization: {
    action: string;
    receipt_id: string;
    consumption: 'consumed' | 'not_configured';
  };
};

export type EdgeDecision = EdgeRefusal | EdgeAllow;

export type ReceiptRequiredEdgeOptions = {
  action: string | ((request: EdgeRequestLike) => string | Promise<string>);
  actionHash?: string | ((request: EdgeRequestLike) => string | undefined | Promise<string | undefined>);
  projectAction?: (request: EdgeRequestLike) => JsonObject | Promise<JsonObject>;
  authorization: {
    authorization_endpoint: string;
    flow: 'EP-APPROVAL-v1';
  };
  requiredFields: string[];
  caidSelector?: { field: string };
  manifestUrl?: string;
  assuranceClass?: 'software' | 'class_a' | 'quorum';
  maxAgeSec?: number;
  proofHeader?: string;
  maxHeaderBytes?: number;
  maxReceiptBytes?: number;
  maxBodyBytes?: number;
  verifyReceipt: (
    carrier: string,
    context: EdgeVerificationContext,
  ) => EdgeVerificationResult | Promise<EdgeVerificationResult>;
  consume?: (
    receiptId: string,
    context: EdgeVerificationContext,
  ) => boolean | Promise<boolean>;
};

const RECEIPT_REQUIRED_STATUS = 428 as const;
const RECEIPT_REQUIRED_HEADER = 'Receipt-Required';
const DEFAULT_PROOF_HEADER = 'X-EMILIA-Receipt';
const PROBLEM_TYPE = 'https://emiliaprotocol.ai/errors/emilia_receipt_required';
const ACTION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
const FIELD_PATTERN = /^[A-Za-z][A-Za-z0-9_]{0,127}$/;
const HEADER_NAME_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const RECEIPT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/;
const FORBIDDEN_HEADER_VALUE = /[\u0000-\u0008\u000a-\u001f\u007f]/;
const SAFE_VERIFIER_REASONS = new Set([
  'action_mismatch',
  'assurance_proof_required',
  'assurance_too_low',
  'bad_signature_encoding',
  'malformed_receipt',
  'no_trusted_keys_configured',
  'outcome_not_accepted',
  'payload_outside_ijson_profile',
  'action_hash_mismatch',
  'caid_binding_invalid',
  'receipt_expired',
  'receipt_not_yet_valid',
  'required_field_missing',
  'signed_action_hash_mismatch',
  'signed_action_invalid',
  'signed_action_required',
  'signature_invalid',
  'untrusted_or_invalid_signature',
]);
const UTF8 = new TextEncoder();

type NormalizedAuthorization = {
  authorization_endpoint: string;
  flow: 'EP-APPROVAL-v1';
};

type NormalizedHeaders = {
  values: Map<string, string[]>;
  bytes: number;
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function byteLength(value: string): number {
  return UTF8.encode(value).byteLength;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function normalizeAuthorization(value: unknown): NormalizedAuthorization {
  if (!isPlainObject(value) || !exactKeys(value, ['authorization_endpoint', 'flow'])) {
    throw new Error('authorization_not_closed');
  }
  if (value.flow !== 'EP-APPROVAL-v1' || typeof value.authorization_endpoint !== 'string') {
    throw new Error('authorization_invalid');
  }
  let endpoint: URL;
  try {
    endpoint = new URL(value.authorization_endpoint);
  } catch {
    throw new Error('authorization_endpoint_invalid');
  }
  if (endpoint.protocol !== 'https:' || endpoint.origin === 'null' || endpoint.username
      || endpoint.password || endpoint.search || endpoint.hash) {
    throw new Error('authorization_endpoint_unsafe');
  }
  return {
    authorization_endpoint: endpoint.toString(),
    flow: 'EP-APPROVAL-v1',
  };
}

function normalizeFields(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 64
      || value.some((field) => typeof field !== 'string' || !FIELD_PATTERN.test(field))
      || new Set(value).size !== value.length) {
    throw new Error('requiredFields_invalid');
  }
  return [...value];
}

function normalizeCaidSelector(value: unknown): { field: string } | undefined {
  if (value === undefined) return undefined;
  if (!isPlainObject(value) || !exactKeys(value, ['field'])
      || typeof value.field !== 'string' || !FIELD_PATTERN.test(value.field)) {
    throw new Error('caidSelector_invalid');
  }
  return { field: value.field };
}

function positiveSafeInteger(value: unknown, name: string, fallback: number): number {
  const normalized = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(normalized) || (normalized as number) <= 0) {
    throw new Error(`${name}_invalid`);
  }
  return normalized as number;
}

function addHeader(
  values: Map<string, string[]>,
  rawName: unknown,
  rawValue: unknown,
): number {
  if (typeof rawName !== 'string' || typeof rawValue !== 'string'
      || !HEADER_NAME_PATTERN.test(rawName) || FORBIDDEN_HEADER_VALUE.test(rawValue)) {
    throw new Error('request_header_invalid');
  }
  const name = rawName.toLowerCase();
  const existing = values.get(name) || [];
  existing.push(rawValue);
  values.set(name, existing);
  return byteLength(name) + 2 + byteLength(rawValue) + 2;
}

function normalizeHeaders(source: HeaderSource | undefined): NormalizedHeaders {
  const values = new Map<string, string[]>();
  let bytes = 0;
  if (source === undefined) return { values, bytes };

  if (isPlainObject(source)) {
    for (const [name, raw] of Object.entries(source)) {
      const entries = Array.isArray(raw) ? raw : [raw];
      for (const value of entries) bytes += addHeader(values, name, value);
    }
    return { values, bytes };
  }

  if (typeof (source as Iterable<[string, string]>)[Symbol.iterator] === 'function') {
    for (const pair of source as Iterable<[string, string]>) {
      if (!Array.isArray(pair) || pair.length !== 2) throw new Error('request_header_invalid');
      bytes += addHeader(values, pair[0], pair[1]);
    }
    return { values, bytes };
  }

  if (typeof (source as Headers).forEach === 'function') {
    (source as Headers).forEach((value, name) => {
      bytes += addHeader(values, name, value);
    });
    return { values, bytes };
  }
  throw new Error('request_header_invalid');
}

function oneHeader(headers: NormalizedHeaders, name: string): string | undefined {
  const values = headers.values.get(name.toLowerCase());
  if (!values || values.length === 0) return undefined;
  if (values.length !== 1 || values[0].includes(',')) throw new Error('ambiguous_proof_header');
  return values[0];
}

function parseContentLength(headers: NormalizedHeaders): number | undefined {
  const values = headers.values.get('content-length');
  if (!values) return undefined;
  if (values.length !== 1 || !/^(?:0|[1-9][0-9]*)$/.test(values[0])) {
    throw new Error('content_length_invalid');
  }
  const size = Number(values[0]);
  if (!Number.isSafeInteger(size)) throw new Error('content_length_invalid');
  return size;
}

function directBodyLength(body: unknown): number | undefined {
  if (body === null || body === undefined) return 0;
  if (typeof body === 'string') return byteLength(body);
  if (body instanceof ArrayBuffer) return body.byteLength;
  if (ArrayBuffer.isView(body)) return body.byteLength;
  return undefined;
}

async function streamLength(stream: ReadableStream<Uint8Array>, maximum: number): Promise<number> {
  const reader = stream.getReader();
  let total = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) return total;
      if (!(result.value instanceof Uint8Array)) throw new Error('request_body_unverifiable');
      total += result.value.byteLength;
      if (total > maximum) throw new Error('request_body_too_large');
    }
  } finally {
    // A cloned Request body is a tee. Awaiting cancellation can wait for the
    // untouched original branch and deadlock authorization. Start cleanup but
    // do not make the gate's decision depend on the sibling stream draining.
    void reader.cancel().catch(() => undefined);
  }
}

async function boundedBodyLength(
  request: EdgeRequestLike,
  headers: NormalizedHeaders,
  maximum: number,
): Promise<number> {
  const advertised = parseContentLength(headers);
  if (advertised !== undefined && advertised > maximum) throw new Error('request_body_too_large');

  let measured: number | undefined;
  if (request.bodyByteLength !== undefined) {
    if (!Number.isSafeInteger(request.bodyByteLength) || (request.bodyByteLength as number) < 0) {
      throw new Error('request_body_unverifiable');
    }
    measured = request.bodyByteLength as number;
  } else if (typeof request.clone === 'function') {
    let clone: { body?: ReadableStream<Uint8Array> | null };
    try { clone = request.clone(); } catch { throw new Error('request_body_unverifiable'); }
    measured = clone.body ? await streamLength(clone.body, maximum) : 0;
  } else {
    measured = directBodyLength(request.body);
  }

  if (measured === undefined) throw new Error('request_body_unverifiable');
  if (measured > maximum) throw new Error('request_body_too_large');
  if (advertised !== undefined && advertised !== measured) throw new Error('content_length_mismatch');
  return measured;
}

function quoteHeader(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function challengeHeader(config: {
  action: string;
  actionHash?: string;
  authorization: NormalizedAuthorization;
  requiredFields: string[];
  caidSelector?: { field: string };
  proofHeader: string;
  manifestUrl?: string;
  assuranceClass?: string;
  maxAgeSec?: number;
}): string {
  const params: Array<[string, string | undefined]> = [
    ['action', config.action],
    ['action_hash', config.actionHash],
    ['manifest', config.manifestUrl],
    ['proof', config.proofHeader],
    ['profile', 'EP-RECEIPT-v1'],
    ['assurance', config.assuranceClass],
    ['max_age', config.maxAgeSec === undefined ? undefined : String(config.maxAgeSec)],
    ['authorization_endpoint', config.authorization.authorization_endpoint],
    ['flow', config.authorization.flow],
    ['required_fields', JSON.stringify(config.requiredFields)],
    ['caid_selector', config.caidSelector ? JSON.stringify(config.caidSelector) : undefined],
  ];
  return params
    .filter((entry): entry is [string, string] => entry[1] !== undefined)
    .map(([name, value]) => `${name}="${quoteHeader(value)}"`)
    .join(', ');
}

function problemDetail(reason?: string): string {
  if (!reason) return 'This action requires an accountable, verifiable authorization receipt.';
  return 'The presented authorization receipt could not satisfy this action challenge.';
}

function safeVerifierReason(reason: unknown): string {
  return typeof reason === 'string' && SAFE_VERIFIER_REASONS.has(reason)
    ? reason
    : 'receipt_rejected';
}

function requestTarget(request: EdgeRequestLike): { method: string; url: string; instance?: string } {
  const method = typeof request.method === 'string' ? request.method.toUpperCase() : '';
  if (!/^[A-Z][A-Z0-9-]{0,31}$/.test(method)) throw new Error('request_method_invalid');
  if (typeof request.url !== 'string') throw new Error('request_target_invalid');
  let url: URL;
  try { url = new URL(request.url); } catch { throw new Error('request_target_invalid'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash) {
    throw new Error('request_target_invalid');
  }
  return { method, url: url.toString(), instance: url.pathname };
}

/**
 * Create a reference edge authorization handler.
 *
 * The injected verifier MUST authenticate the receipt under relying-party pins
 * and bind it to `context.action`. When `consume` is supplied it MUST perform a
 * durable atomic insert-if-absent and return exactly true only for the winner.
 * Omitting consumption is suitable for verification-only profiles, not for a
 * one-use irreversible consequence boundary.
 */
export function createReceiptRequiredEdgeHandler(options: ReceiptRequiredEdgeOptions) {
  if (!isPlainObject(options) || (typeof options.action !== 'string' && typeof options.action !== 'function')) {
    throw new Error('action_invalid');
  }
  if (typeof options.verifyReceipt !== 'function') throw new Error('verifyReceipt_required');
  if (options.consume !== undefined && typeof options.consume !== 'function') throw new Error('consume_invalid');
  const authorization = normalizeAuthorization(options.authorization);
  const requiredFields = normalizeFields(options.requiredFields);
  const caidSelector = normalizeCaidSelector(options.caidSelector);
  const proofHeader = options.proofHeader ?? DEFAULT_PROOF_HEADER;
  if (!HEADER_NAME_PATTERN.test(proofHeader)) throw new Error('proofHeader_invalid');
  const maxHeaderBytes = positiveSafeInteger(options.maxHeaderBytes, 'maxHeaderBytes', 128 * 1024);
  const maxReceiptBytes = positiveSafeInteger(options.maxReceiptBytes, 'maxReceiptBytes', 96 * 1024);
  const maxBodyBytes = positiveSafeInteger(options.maxBodyBytes, 'maxBodyBytes', 1024 * 1024);
  if (maxReceiptBytes > maxHeaderBytes) throw new Error('maxReceiptBytes_exceeds_header_limit');
  if (options.manifestUrl !== undefined) {
    let manifest: URL;
    try { manifest = new URL(options.manifestUrl); } catch { throw new Error('manifestUrl_invalid'); }
    if (manifest.protocol !== 'https:' || manifest.username || manifest.password || manifest.hash) {
      throw new Error('manifestUrl_unsafe');
    }
  }
  if (options.assuranceClass !== undefined
      && !['software', 'class_a', 'quorum'].includes(options.assuranceClass)) {
    throw new Error('assuranceClass_invalid');
  }
  if (options.maxAgeSec !== undefined
      && (!Number.isSafeInteger(options.maxAgeSec) || options.maxAgeSec <= 0)) {
    throw new Error('maxAgeSec_invalid');
  }
  if (typeof options.action === 'string' && !ACTION_PATTERN.test(options.action)) {
    throw new Error('action_invalid');
  }
  if (typeof options.actionHash === 'string' && !SHA256_PATTERN.test(options.actionHash)) {
    throw new Error('action_hash_invalid');
  }
  if (options.projectAction !== undefined && typeof options.projectAction !== 'function') {
    throw new Error('projectAction_invalid');
  }
  if (options.projectAction === undefined && options.actionHash === undefined) {
    throw new Error('projectAction_required_for_material_binding');
  }

  return async function authorize(request: EdgeRequestLike): Promise<EdgeDecision> {
    let target: { method: string; url: string; instance?: string } | undefined;
    let action = typeof options.action === 'string' ? options.action : '';
    let actionHash = typeof options.actionHash === 'string' ? options.actionHash : undefined;
    let observedAction: JsonObject | undefined;
    let headers: NormalizedHeaders | undefined;

    const refuse = (reason?: string): EdgeRefusal => {
      const header = challengeHeader({
        action,
        actionHash,
        authorization,
        requiredFields,
        caidSelector,
        proofHeader,
        manifestUrl: options.manifestUrl,
        assuranceClass: options.assuranceClass,
        maxAgeSec: options.maxAgeSec,
      });
      return {
        ok: false,
        status: RECEIPT_REQUIRED_STATUS,
        headers: {
          'cache-control': 'no-store',
          'content-type': 'application/problem+json',
          'receipt-required': header,
        },
        body: {
          type: PROBLEM_TYPE,
          title: 'EMILIA Receipt Required',
          status: RECEIPT_REQUIRED_STATUS,
          detail: problemDetail(reason),
          ...(target?.instance ? { instance: target.instance } : {}),
          required: {
            action,
            action_hash: actionHash ?? null,
            manifest: options.manifestUrl ?? null,
            status: RECEIPT_REQUIRED_STATUS,
            challenge_header: RECEIPT_REQUIRED_HEADER,
            proof_header: proofHeader,
            header: `${proofHeader}: base64(<EP-RECEIPT-v1 JSON>)`,
            assurance_class: options.assuranceClass ?? null,
            max_age_sec: options.maxAgeSec ?? null,
            authorization: { ...authorization },
            required_fields: [...requiredFields],
            caid_selector: caidSelector ? { ...caidSelector } : null,
            how: `POST the exact challenged action to the authorization endpoint using ${authorization.flow}, poll with the returned private token, then retry with the approved receipt.`,
          },
          ...(reason ? { rejected: { reason } } : {}),
        },
      };
    };

    try {
      target = requestTarget(request);
      action = typeof options.action === 'function' ? await options.action(request) : action;
      if (!ACTION_PATTERN.test(action)) throw new Error('action_invalid');
      actionHash = typeof options.actionHash === 'function'
        ? await options.actionHash(request)
        : actionHash;
      if (actionHash !== undefined && !SHA256_PATTERN.test(actionHash)) {
        throw new Error('action_hash_invalid');
      }
      headers = normalizeHeaders(request.headers);
      if (headers.bytes > maxHeaderBytes) throw new Error('request_headers_too_large');
      const bodyBytes = await boundedBodyLength(request, headers, maxBodyBytes);
      if (options.projectAction) {
        const projected = await options.projectAction(request);
        if (!isPlainObject(projected)) throw new Error('observed_action_invalid');
        for (const field of requiredFields) {
          if (!Object.prototype.hasOwnProperty.call(projected, field) || projected[field] === undefined) {
            throw new Error('observed_action_required_field_missing');
          }
        }
        if (caidSelector) {
          const caid = projected[caidSelector.field];
          if (typeof caid !== 'string'
              || !/^caid:1:[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)*\.[1-9][0-9]*:[a-z0-9]+(?:-[a-z0-9]+)*:[A-Za-z0-9_-]{43}$/.test(caid)) {
            throw new Error('observed_action_caid_invalid');
          }
        }
        const projectedHash = approvalActionHash(projected);
        if (actionHash && actionHash !== projectedHash) throw new Error('observed_action_hash_mismatch');
        actionHash = projectedHash;
        observedAction = projected;
      }
      const carrier = oneHeader(headers, proofHeader);
      if (carrier === undefined || carrier.length === 0) return refuse();
      if (byteLength(carrier) > maxReceiptBytes) throw new Error('receipt_header_too_large');

      const context: EdgeVerificationContext = {
        action,
        ...(actionHash ? { action_hash: actionHash } : {}),
        required_fields: [...requiredFields],
        ...(caidSelector ? { caid_selector: { ...caidSelector } } : {}),
        ...(observedAction ? { observed_action: observedAction } : {}),
        request: {
          method: target.method,
          url: target.url,
          body_bytes: bodyBytes,
        },
      };

      let verified: EdgeVerificationResult;
      try {
        verified = await options.verifyReceipt(carrier, context);
      } catch {
        return refuse('verifier_unavailable');
      }
      if (!isPlainObject(verified) || verified.ok !== true) {
        return refuse(safeVerifierReason(isPlainObject(verified) ? verified.reason : undefined));
      }
      const boundAction = typeof verified.action === 'string'
        ? verified.action
        : verified.bound_action;
      if (boundAction !== action) return refuse('action_binding_mismatch');
      const receiptId = typeof verified.receipt_id === 'string'
        ? verified.receipt_id
        : verified.receiptId;
      if (typeof receiptId !== 'string' || !RECEIPT_ID_PATTERN.test(receiptId)) {
        return refuse('missing_receipt_id');
      }

      if (options.consume) {
        let consumed: boolean;
        try { consumed = await options.consume(receiptId, context); } catch {
          return refuse('consumption_store_unavailable');
        }
        if (consumed !== true) return refuse('replay_refused');
      }

      return {
        ok: true,
        status: 200,
        upstream: {
          method: target.method,
          url: target.url,
          redirect: 'manual',
          remove_headers: [proofHeader.toLowerCase()],
          set_headers: {
            'x-emilia-verified-action': action,
            'x-emilia-verified-receipt-id': receiptId,
          },
        },
        authorization: {
          action,
          receipt_id: receiptId,
          consumption: options.consume ? 'consumed' : 'not_configured',
        },
      };
    } catch (error) {
      const reason = error instanceof Error ? error.message : 'edge_request_invalid';
      const allowed = new Set([
        'action_hash_invalid',
        'action_invalid',
        'ambiguous_proof_header',
        'content_length_invalid',
        'content_length_mismatch',
        'receipt_header_too_large',
        'request_body_too_large',
        'request_body_unverifiable',
        'request_header_invalid',
        'request_headers_too_large',
        'request_method_invalid',
        'request_target_invalid',
        'observed_action_caid_invalid',
        'observed_action_hash_mismatch',
        'observed_action_invalid',
        'observed_action_required_field_missing',
      ]);
      return refuse(allowed.has(reason) ? reason : 'edge_request_invalid');
    }
  };
}
