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

const SECRET_KEY_RE = /(password|secret|token|api[_-]?key|authorization|private[_-]?key|seed)/i;

export function canonicalize(value) {
  if (value === null || value === undefined) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (typeof value === 'object') {
    return `{${Object.keys(value).sort().map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function sha256hex(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

export function sanitizeSecurityPayload(value) {
  if (Array.isArray(value)) return value.map(sanitizeSecurityPayload);
  if (!value || typeof value !== 'object') return value;
  const out = {};
  for (const [key, inner] of Object.entries(value)) {
    out[key] = SECRET_KEY_RE.test(key) ? '[redacted]' : sanitizeSecurityPayload(inner);
  }
  return out;
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
