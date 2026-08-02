// SPDX-License-Identifier: Apache-2.0
//
// Tamper-evident security event ledger.
//
// This complements audit_events/protocol_events with a narrow incident-response
// stream: receipt challenges, verification failures, replay refusals, authority
// revocations, key rotations, and admin/security actions. Each row carries a
// payload hash and a chain hash over the prior event hash.

import crypto from 'node:crypto';
import type { PostgrestError } from '@supabase/supabase-js';
import { getServiceClient } from './supabase.js';
import { siemEvent } from './siem.js';
import { logger } from './logger.js';
import { canonicalize as canonicalizeProtocol } from './canonical-json.js';

const SECRET_KEY_RE = /(password|secret|token|api[_-]?key|authorization|private[_-]?key|seed)/i;

export function canonicalize(value) {
  return canonicalizeProtocol(value);
}

export function sha256hex(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function unsafeSecurityPayload(reason: string): never {
  throw new TypeError(`value is outside the EP canonicalization profile: ${reason}`);
}

function sanitizeSecurityValue(value, ancestors) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) unsafeSecurityPayload('numbers must be safe integers');
    return value;
  }
  if (!value || typeof value !== 'object') unsafeSecurityPayload(`${typeof value} is not JSON`);
  if (ancestors.has(value)) unsafeSecurityPayload('cyclic reference');
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) unsafeSecurityPayload('unsafe array prototype');
      const ownKeys = Reflect.ownKeys(value);
      const expected = new Set(['length', ...Array.from({ length: value.length }, (_, index) => String(index))]);
      if (ownKeys.some((key) => typeof key !== 'string' || !expected.has(key)) || ownKeys.length !== expected.size) {
        unsafeSecurityPayload('sparse or extended array');
      }
      return Array.from({ length: value.length }, (_, index) => {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !('value' in descriptor)) unsafeSecurityPayload('array accessor');
        return sanitizeSecurityValue(descriptor.value, ancestors);
      });
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) unsafeSecurityPayload('non-plain object');
    const out: Record<string, unknown> = {};
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== 'string') unsafeSecurityPayload('symbol member');
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || descriptor.enumerable !== true || !('value' in descriptor)) {
        unsafeSecurityPayload('hidden or accessor member');
      }
      out[key] = SECRET_KEY_RE.test(key)
        ? '[redacted]'
        : sanitizeSecurityValue(descriptor.value, ancestors);
    }
    return out;
  } finally {
    ancestors.delete(value);
  }
}

export function sanitizeSecurityPayload(value) {
  const sanitized = sanitizeSecurityValue(value, new Set());
  canonicalizeProtocol(sanitized);
  return sanitized;
}

type SecurityEventInput = {
  eventType?: string;
  severity?: string;
  actorId?: string | null;
  tenantId?: string | null;
  targetType?: string | null;
  targetId?: string | null;
  correlationId?: string | null;
  payload?: Record<string, any>;
  previousHash?: string | null;
  createdAt?: string;
};

/**
 * @param {{
 *   eventType?: string,
 *   severity?: string,
 *   actorId?: *,
 *   tenantId?: *,
 *   targetType?: *,
 *   targetId?: *,
 *   correlationId?: *,
 *   payload?: *,
 *   previousHash?: *,
 *   createdAt?: string,
 * }} [options]
 */
export function buildSecurityEvent({
  eventType,
  severity = 'medium',
  actorId = null,
  tenantId = null,
  targetType = null,
  targetId = null,
  correlationId = null,
  payload = {},
  previousHash = null,
  createdAt = new Date().toISOString(),
}: SecurityEventInput = {}) {
  if (!eventType || typeof eventType !== 'string') {
    throw new Error('security event requires eventType');
  }
  const payloadJson = sanitizeSecurityPayload(payload);
  const payloadHash = sha256hex(canonicalize(payloadJson));
  const chainMaterial = {
    event_type: eventType,
    severity,
    actor_id: actorId,
    tenant_id: tenantId,
    target_type: targetType,
    target_id: targetId,
    correlation_id: correlationId,
    previous_hash: previousHash,
    payload_hash: payloadHash,
    created_at: createdAt,
  };
  return {
    event_type: eventType,
    severity,
    actor_id: actorId,
    tenant_id: tenantId,
    target_type: targetType,
    target_id: targetId,
    correlation_id: correlationId,
    previous_hash: previousHash,
    payload_json: payloadJson,
    payload_hash: payloadHash,
    event_hash: sha256hex(canonicalize(chainMaterial)),
    created_at: createdAt,
  };
}

export function verifySecurityEventChain(events) {
  let previousHash = null;
  const errors: string[] = [];
  for (const [i, event] of events.entries()) {
    const expected = buildSecurityEvent({
      eventType: event.event_type,
      severity: event.severity,
      actorId: event.actor_id,
      tenantId: event.tenant_id,
      targetType: event.target_type,
      targetId: event.target_id,
      correlationId: event.correlation_id,
      payload: event.payload_json,
      previousHash,
      createdAt: event.created_at,
    });
    if (event.previous_hash !== previousHash) errors.push(`event ${i} previous_hash mismatch`);
    if (event.payload_hash !== expected.payload_hash) errors.push(`event ${i} payload_hash mismatch`);
    if (event.event_hash !== expected.event_hash) errors.push(`event ${i} event_hash mismatch`);
    previousHash = event.event_hash;
  }
  return { ok: errors.length === 0, errors };
}

export async function appendSecurityEvent(event, { supabase = getServiceClient(), forwardSiem = true } = {}) {
  const tenantId = event.tenantId ?? event.tenant_id ?? null;
  let lastError: PostgrestError | null = null;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    let previousHash = null;
    try {
      const q = supabase
        .from('security_events')
        .select('event_hash')
        .order('created_at', { ascending: false })
        .limit(1);
      const scoped = tenantId ? q.eq('tenant_id', tenantId) : q.is('tenant_id', null);
      const { data, error } = await scoped;
      if (error) throw error;
      previousHash = data?.[0]?.event_hash || null;
    } catch (e) {
      logger.warn('[security-events] previous hash lookup failed:', e?.message);
    }

    const row = buildSecurityEvent({ ...event, previousHash, createdAt: new Date().toISOString() });
    const { error } = await supabase.from('security_events').insert(row);
    if (!error) {
      if (forwardSiem) {
        siemEvent(row.event_type, {
          severity: row.severity,
          actor_id: row.actor_id,
          tenant_id: row.tenant_id,
          target_type: row.target_type,
          target_id: row.target_id,
          event_hash: row.event_hash,
          payload_hash: row.payload_hash,
        });
      }
      return row;
    }
    lastError = error;
    if (error.code !== '23505') break;
    logger.warn('[security-events] chain race detected, retrying append', { attempt: attempt + 1, tenantId });
  }
  throw lastError;
}
