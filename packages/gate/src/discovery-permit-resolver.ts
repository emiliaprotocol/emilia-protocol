// SPDX-License-Identifier: Apache-2.0
/**
 * Address-pinned, manually redirected resolver for Discovery-to-Permit
 * Continuity. No global or plain fetch path exists.
 */

import {
  canonicalizeDiscoveryPermit,
  digestDiscoveryPermit,
  digestDiscoveryPermitRaw,
  evaluateDiscoveryPermitContinuity,
  pinDiscoveryPermitTrust,
  type DiscoveryPermitDocumentProvenance,
  type DiscoveryPermitDocumentRole,
  type DiscoveryPermitResolution,
  type DiscoveryPermitTrustPins,
  type DiscoveryPermitTrustPinsInput,
} from '../../verify/src/discovery-permit-contract.js';
import { strictJsonGate } from '../../verify/src/strict-json.js';

export interface AddressPinnedFetchContext {
  hostname: string;
  approvedAddresses: readonly string[];
}

export interface AddressPinnedFetchResult {
  response: any;
  connectedAddress: string;
}

export interface AddressPinnedTransport {
  resolveAddresses(
    hostname: string,
    context: { signal?: AbortSignal },
  ): readonly string[] | Promise<readonly string[]>;
  fetchPinned(
    url: string,
    init: RequestInit,
    context: AddressPinnedFetchContext,
  ): AddressPinnedFetchResult | Promise<AddressPinnedFetchResult>;
}

export interface DiscoveryPermitResolverOptions {
  pins: DiscoveryPermitTrustPins | DiscoveryPermitTrustPinsInput;
  transport: AddressPinnedTransport;
  clock?: () => number;
  timeout_ms?: number;
  max_body_bytes?: number;
  max_json_depth?: number;
}

export interface DiscoveryPermitResolveInput {
  caid: string;
  action: unknown;
}

interface RetrievedDocument {
  document: unknown;
  provenance: DiscoveryPermitDocumentProvenance;
}

export class DiscoveryPermitResolverError extends Error {
  readonly code: string;

  constructor(code: string, message = code) {
    super(message);
    this.name = 'DiscoveryPermitResolverError';
    this.code = code;
  }
}

const INPUT_KEYS = new Set(['caid', 'action']);
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const DEFAULT_MAX_JSON_DEPTH = 16;

function fail(code: string, message = code): never {
  throw new DiscoveryPermitResolverError(code, message);
}

function isObject(value: unknown): value is Record<string, any> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactInput(value: unknown): value is DiscoveryPermitResolveInput {
  if (!isObject(value)) return false;
  const keys = Object.keys(value);
  return keys.length === INPUT_KEYS.size
    && keys.every((key) => INPUT_KEYS.has(key))
    && typeof value.caid === 'string';
}

function header(response: any, name: string): string | null {
  const headers = response?.headers;
  if (headers && typeof headers.get === 'function') {
    const value = headers.get(name);
    return typeof value === 'string' ? value : null;
  }
  if (isObject(headers)) {
    const entry = Object.entries(headers)
      .find(([key]) => key.toLowerCase() === name.toLowerCase());
    return typeof entry?.[1] === 'string' ? entry[1] : null;
  }
  return null;
}

function normalizeHost(value: unknown): string {
  return typeof value === 'string'
    ? value.trim().toLowerCase().replace(/\.$/, '').replace(/^\[|\]$/g, '')
    : '';
}

function isIPv4(value: string): boolean {
  const parts = value.split('.');
  return parts.length === 4
    && parts.every((part) => /^\d{1,3}$/.test(part)
      && Number(part) >= 0
      && Number(part) <= 255);
}

function normalizeIpAddress(value: unknown): string | null {
  const raw = normalizeHost(value);
  if (isIPv4(raw)) {
    return raw.split('.').map((part) => String(Number(part))).join('.');
  }
  if (!raw.includes(':')) return null;
  try {
    const parsed = new URL(`https://[${raw}]/`);
    const normalized = normalizeHost(parsed.hostname);
    return normalized.includes(':') ? normalized : null;
  } catch {
    return null;
  }
}

function isPrivateIPv4(host: string): boolean {
  const [a, b, c] = host.split('.').map(Number);
  return a === 0
    || a === 10
    || a === 127
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168)
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 192 && b === 0)
    || (a === 192 && b === 88 && c === 99)
    || (a === 198 && (b === 18 || b === 19))
    || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113)
    || a >= 224;
}

function isPrivateIPv6(host: string): boolean {
  const normalized = normalizeIpAddress(host);
  if (!normalized || !normalized.includes(':')) return true;
  if (normalized === '::' || normalized === '::1') return true;

  const mappedDotted = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mappedDotted && isIPv4(mappedDotted[1])) return isPrivateIPv4(mappedDotted[1]);
  const mappedHex = normalized.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mappedHex) {
    const high = Number.parseInt(mappedHex[1], 16);
    const low = Number.parseInt(mappedHex[2], 16);
    return isPrivateIPv4(`${high >> 8}.${high & 0xff}.${low >> 8}.${low & 0xff}`);
  }

  const first = Number.parseInt(normalized.split(':', 1)[0] || '0', 16);
  if ((first & 0xe000) !== 0x2000) return true;
  return normalized === '2001::'
    || normalized.startsWith('2001::')
    || normalized.startsWith('2001:0:')
    || normalized.startsWith('2001:2:')
    || normalized.startsWith('2001:10:')
    || normalized.startsWith('2001:20:')
    || normalized === '2001:db8::'
    || normalized.startsWith('2001:db8:')
    || normalized === '2002::'
    || normalized.startsWith('2002:')
    || normalized.startsWith('3fff:');
}

function validateAddresses(values: unknown): readonly string[] {
  if (!Array.isArray(values) || values.length === 0) fail('address_resolution_empty');
  const approved: string[] = [];
  for (const raw of values) {
    const address = normalizeIpAddress(raw);
    if (!address) fail('address_invalid');
    const blocked = isIPv4(address)
      ? isPrivateIPv4(address)
      : isPrivateIPv6(address);
    if (blocked) fail('address_not_public');
    if (!approved.includes(address)) approved.push(address);
  }
  return Object.freeze(approved);
}

function jsonDepth(value: unknown): number {
  if (value === null || typeof value !== 'object') return 0;
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 1 }];
  let maximum = 0;
  while (stack.length > 0) {
    const current = stack.pop()!;
    maximum = Math.max(maximum, current.depth);
    if (current.value !== null && typeof current.value === 'object') {
      const children = Array.isArray(current.value)
        ? current.value
        : Object.values(current.value as Record<string, unknown>);
      for (const child of children) {
        if (child !== null && typeof child === 'object') {
          stack.push({ value: child, depth: current.depth + 1 });
        }
      }
    }
  }
  return maximum;
}

async function readBoundedBody(response: any, maximum: number): Promise<Uint8Array> {
  const contentLength = header(response, 'content-length');
  if (contentLength !== null) {
    const parsed = Number(contentLength);
    if (!Number.isSafeInteger(parsed) || parsed < 0) fail('content_length_invalid');
    if (parsed > maximum) fail('body_too_large');
  }

  const body = response?.body;
  if (typeof body === 'string') {
    const bytes = Buffer.from(body, 'utf8');
    if (bytes.byteLength > maximum) fail('body_too_large');
    return bytes;
  }
  if (body instanceof Uint8Array) {
    if (body.byteLength > maximum) fail('body_too_large');
    return new Uint8Array(body);
  }
  if (body && typeof body.getReader === 'function') {
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      while (true) {
        const result = await reader.read();
        if (result.done) break;
        if (!(result.value instanceof Uint8Array)) fail('body_chunk_invalid');
        total += result.value.byteLength;
        if (total > maximum) {
          await reader.cancel();
          fail('body_too_large');
        }
        chunks.push(result.value);
      }
    } finally {
      try {
        reader.releaseLock();
      } catch {
        // The response stream may already be closed or cancelled.
      }
    }
    const combined = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return combined;
  }
  if (typeof response?.arrayBuffer === 'function') {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > maximum) fail('body_too_large');
    return bytes;
  }
  fail('response_body_unavailable');
}

function timeoutController(timeoutMs: number): {
  signal?: AbortSignal;
  clear: () => void;
} {
  if (typeof AbortController === 'undefined') return { clear: () => {} };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return {
    signal: controller.signal,
    clear: () => clearTimeout(timer),
  };
}

function boundedInteger(
  value: unknown,
  fallback: number,
  minimum: number,
  maximum: number,
  code: string,
): number {
  const selected = value === undefined ? fallback : value;
  if (!Number.isSafeInteger(selected)
    || (selected as number) < minimum
    || (selected as number) > maximum) fail(code);
  return selected as number;
}

export class DiscoveryPermitResolver {
  readonly pins: DiscoveryPermitTrustPins;
  readonly timeout_ms: number;
  readonly max_body_bytes: number;
  readonly max_json_depth: number;

  readonly #resolveAddresses: AddressPinnedTransport['resolveAddresses'];
  readonly #fetchPinned: AddressPinnedTransport['fetchPinned'];
  readonly #clock: () => number;

  constructor(options: DiscoveryPermitResolverOptions) {
    if (!isObject(options)) fail('resolver_options_invalid');
    this.pins = pinDiscoveryPermitTrust(options.pins);
    if (!isObject(options.transport)
      || typeof options.transport.resolveAddresses !== 'function'
      || typeof options.transport.fetchPinned !== 'function') {
      fail('address_pinned_transport_required');
    }
    this.#resolveAddresses = options.transport.resolveAddresses.bind(options.transport);
    this.#fetchPinned = options.transport.fetchPinned.bind(options.transport);
    this.#clock = typeof options.clock === 'function' ? options.clock : Date.now;
    this.timeout_ms = boundedInteger(
      options.timeout_ms,
      DEFAULT_TIMEOUT_MS,
      1,
      60_000,
      'timeout_invalid',
    );
    this.max_body_bytes = boundedInteger(
      options.max_body_bytes,
      DEFAULT_MAX_BODY_BYTES,
      128,
      4 * 1024 * 1024,
      'max_body_bytes_invalid',
    );
    this.max_json_depth = boundedInteger(
      options.max_json_depth,
      DEFAULT_MAX_JSON_DEPTH,
      1,
      64,
      'max_json_depth_invalid',
    );
    Object.freeze(this);
  }

  async #retrieve(
    initialUrl: string,
    role: DiscoveryPermitDocumentRole,
  ): Promise<RetrievedDocument> {
    let currentUrl = initialUrl;
    const redirectChain = [initialUrl];
    const visited = new Set<string>();

    for (let hop = 0; hop <= Object.keys(this.pins.redirect_map).length; hop += 1) {
      if (visited.has(currentUrl)) fail('redirect_cycle');
      visited.add(currentUrl);
      const parsed = new URL(currentUrl);
      const timer = timeoutController(this.timeout_ms);
      try {
        const addresses = await this.#resolveAddresses(parsed.hostname, {
          signal: timer.signal,
        });
        if (timer.signal?.aborted) fail('transport_timeout');
        const approvedAddresses = validateAddresses(addresses);
        const init: RequestInit = {
          method: 'GET',
          redirect: 'manual',
          headers: { accept: 'application/json' },
        };
        if (timer.signal) init.signal = timer.signal;
        const result = await this.#fetchPinned(currentUrl, init, {
          hostname: parsed.hostname,
          approvedAddresses,
        });
        if (!isObject(result) || !Object.hasOwn(result, 'response')) {
          fail('pinned_transport_result_invalid');
        }
        const connectedAddress = normalizeIpAddress(result.connectedAddress);
        if (!connectedAddress || !approvedAddresses.includes(connectedAddress)) {
          fail('connected_address_not_approved');
        }
        const response = result.response;
        if (!response || response.redirected === true || response.type === 'opaqueredirect') {
          fail('redirect_followed_by_transport');
        }
        const status = response.status;
        if (!Number.isSafeInteger(status)) fail('http_status_invalid');

        if (status >= 300 && status < 400) {
          const expectedTarget = this.pins.redirect_map[currentUrl];
          if (!expectedTarget) fail('redirect_not_pinned');
          const location = header(response, 'location');
          if (!location) fail('redirect_location_missing');
          let actualTarget: string;
          try {
            actualTarget = new URL(location, currentUrl).href;
          } catch {
            fail('redirect_location_invalid');
          }
          if (actualTarget !== expectedTarget) fail('redirect_target_mismatch');
          currentUrl = actualTarget;
          redirectChain.push(currentUrl);
          continue;
        }
        if (status < 200 || status >= 300) fail('http_error', `HTTP ${status}`);

        const contentType = header(response, 'content-type');
        const mediaType = contentType?.split(';', 1)[0].trim().toLowerCase();
        if (mediaType !== 'application/json') fail('content_type_invalid');
        const rawBytes = await readBoundedBody(response, this.max_body_bytes);
        let raw: string;
        try {
          raw = new TextDecoder('utf-8', { fatal: true }).decode(rawBytes);
        } catch {
          fail('utf8_invalid');
        }
        const strict = strictJsonGate(raw);
        if (!strict.ok) fail('json_not_strict', strict.reason);
        let document: unknown;
        try {
          document = JSON.parse(raw);
        } catch {
          fail('json_invalid');
        }
        if (!isObject(document)) fail('document_type_invalid');
        if (jsonDepth(document) > this.max_json_depth) fail('json_depth_exceeded');

        let canonicalDigest;
        try {
          canonicalDigest = digestDiscoveryPermit(document);
        } catch {
          fail('document_not_canonicalizable');
        }
        return {
          document,
          provenance: Object.freeze({
            role,
            requested_url: initialUrl,
            resolved_url: currentUrl,
            connected_address: connectedAddress,
            media_type: 'application/json' as const,
            byte_length: rawBytes.byteLength,
            raw_digest: digestDiscoveryPermitRaw(rawBytes),
            canonical_digest: canonicalDigest,
            redirect_chain: Object.freeze([...redirectChain]),
          }),
        };
      } catch (error) {
        if (error instanceof DiscoveryPermitResolverError) throw error;
        const code = timer.signal?.aborted ? 'transport_timeout' : 'transport_failure';
        fail(code, error instanceof Error ? error.message : code);
      } finally {
        timer.clear();
      }
    }
    fail('redirect_limit_exceeded');
  }

  async resolve(input: DiscoveryPermitResolveInput): Promise<DiscoveryPermitResolution> {
    if (!exactInput(input)) fail('transaction_fields_not_allowed');
    const caid = input.caid;
    let action: unknown;
    try {
      // Snapshot into plain JSON before the first await. This prevents caller
      // mutation, accessors, or prototype state from changing the bound action
      // while address resolution and retrieval are in flight.
      action = JSON.parse(canonicalizeDiscoveryPermit(input.action));
    } catch {
      fail('action_not_canonicalizable');
    }
    const now = this.#clock();
    if (!Number.isFinite(now)) fail('clock_invalid');

    const discovery = await this.#retrieve(this.pins.discovery_url, 'discovery');
    const permit = await this.#retrieve(this.pins.permit_url, 'permit');
    return evaluateDiscoveryPermitContinuity({
      pins: this.pins,
      discovery: discovery.document,
      binding: permit.document,
      caid,
      action,
      now,
      provenance: {
        discovery: discovery.provenance,
        permit: permit.provenance,
      },
    });
  }
}

export function createDiscoveryPermitResolver(
  options: DiscoveryPermitResolverOptions,
): DiscoveryPermitResolver {
  return new DiscoveryPermitResolver(options);
}
