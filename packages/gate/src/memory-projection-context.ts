// SPDX-License-Identifier: Apache-2.0

/**
 * Provider-neutral Trusted Context Pack adapter for
 * MEMORY-PROJECTION-RECORD-v1.
 *
 * This verifies only the signed projection envelope at the Gate boundary.
 * Native source bytes are rechecked by the full Memory Projection verifier
 * before an adapter signs the record. An adapter signature authenticates the
 * adapter's assertion. It does not make the underlying source true.
 */
import {
  MemoryProjectionVerificationError,
  verifyMemoryProjectionRecordV1Envelope,
  type MemoryProjectionAdapterKey,
} from '@emilia-protocol/verify/memory-projection';

import {
  canonicalContextRecordDigest,
  type ContextEvidenceProvider,
  type ContextProviderVerification,
} from './trusted-context.js';

type RecordLike = Record<string, any>;

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;

export interface MemoryProjectionContextProviderOptions {
  adapterKeys: Record<string, MemoryProjectionAdapterKey>;
  statusCheckedAt: string | (() => string);
  providerId: string;
  profileId: string;
  contextFrameProfile: string;
  maxDeliveredEntries?: number;
}

function isDataRecord(value: unknown): value is RecordLike {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}

function boundedString(value: unknown, maximum: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function instant(value: unknown): string | null {
  if (typeof value !== 'string' || !RFC3339.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null;
}

function resolveInstant(value: string | (() => string)): string | null {
  try {
    return instant(typeof value === 'function' ? value() : value);
  } catch {
    return null;
  }
}

function safeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function result(
  state: 'NOT_VERIFIED' | 'INDETERMINATE',
  reason: string,
): ContextProviderVerification {
  return Object.freeze({ state, reason });
}

function mapFailure(error: unknown): ContextProviderVerification {
  if (!(error instanceof MemoryProjectionVerificationError)) {
    return result('INDETERMINATE', 'projection_verification_unavailable');
  }
  if (error.code === 'adapter_key_revoked') return result('NOT_VERIFIED', 'adapter_key_revoked');
  if (error.code === 'adapter_key_inactive') return result('NOT_VERIFIED', 'adapter_key_inactive');
  if (error.code === 'adapter_key_not_pinned') return result('NOT_VERIFIED', 'adapter_key_not_pinned');
  if (error.code === 'signature_invalid') return result('NOT_VERIFIED', 'projection_signature_invalid');
  if (error.code === 'projection_stale' || error.code === 'projection_from_future') {
    return result('INDETERMINATE', 'projection_stale');
  }
  if (error.code === 'trust_snapshot_stale' || error.code === 'trust_snapshot_from_future') {
    return result('INDETERMINATE', 'keyring_status_stale');
  }
  return result('NOT_VERIFIED', 'projection_record_invalid');
}

function copyAdapterKeys(
  value: unknown,
): Readonly<Record<string, MemoryProjectionAdapterKey>> {
  if (!isDataRecord(value)) throw new TypeError('memory projection adapter keys required');
  const copy: Record<string, MemoryProjectionAdapterKey> = {};
  for (const [keyId, candidate] of Object.entries(value)) {
    if (!boundedString(keyId, 512) || !isDataRecord(candidate)) {
      throw new TypeError('memory projection adapter key invalid');
    }
    copy[keyId] = Object.freeze({
      public_key_spki_b64u: candidate.public_key_spki_b64u,
      status: candidate.status,
      valid_from: candidate.valid_from,
      valid_to: candidate.valid_to,
      revoked_at: candidate.revoked_at,
    }) as MemoryProjectionAdapterKey;
  }
  if (Object.keys(copy).length === 0) {
    throw new TypeError('memory projection adapter key required');
  }
  return Object.freeze(copy);
}

/** Create one relying-party-pinned Memory Projection provider. */
export function createMemoryProjectionContextProvider(
  options: MemoryProjectionContextProviderOptions,
): ContextEvidenceProvider {
  if (!boundedString(options?.providerId, 128)
      || !boundedString(options?.profileId, 512)
      || !boundedString(options?.contextFrameProfile, 512)) {
    throw new TypeError('memory projection provider identity invalid');
  }
  const maximum = options.maxDeliveredEntries ?? 256;
  if (!safeInteger(maximum) || maximum < 1 || maximum > 4096) {
    throw new TypeError('memory projection delivered-entry limit invalid');
  }
  const adapterKeys = copyAdapterKeys(options.adapterKeys);
  const statusCheckedAtSource = options.statusCheckedAt;
  const providerId = options.providerId;
  const profileId = options.profileId;
  const contextFrameProfile = options.contextFrameProfile;

  return Object.freeze({
    providerId,
    profileId,
    verifyProjection(record: unknown, context: {
      verificationTime: string;
      maxSignerStatusAgeSec: number;
      maxProjectionAgeSec: number;
      maxTrustAgeSec: number;
    }): ContextProviderVerification {
      const verificationTime = instant(context?.verificationTime);
      const statusCheckedAt = resolveInstant(statusCheckedAtSource);
      if (!verificationTime || !statusCheckedAt
          || !safeInteger(context?.maxSignerStatusAgeSec)
          || !safeInteger(context?.maxProjectionAgeSec)
          || !safeInteger(context?.maxTrustAgeSec)) {
        return result('INDETERMINATE', 'adapter_status_unavailable');
      }
      const statusAge = (Date.parse(verificationTime) - Date.parse(statusCheckedAt)) / 1000;
      if (statusAge < 0 || statusAge > context.maxSignerStatusAgeSec) {
        return result('INDETERMINATE', 'adapter_status_stale');
      }
      if (!isDataRecord(record)
          || !Array.isArray(record.delivered)
          || record.delivered.length === 0
          || record.delivered.length > maximum) {
        return result('NOT_VERIFIED', 'projection_record_invalid');
      }
      try {
        const verified = verifyMemoryProjectionRecordV1Envelope(record, {
          adapterKeys,
          verificationTime,
          maxProjectionAgeSec: context.maxProjectionAgeSec,
          maxTrustAgeSec: context.maxTrustAgeSec,
          expectedSourceProfile: profileId,
          expectedContextFrameProfile: contextFrameProfile,
        });
        return Object.freeze({
          state: 'VERIFIED' as const,
          reason: null,
          claims: Object.freeze({
            projection_id: verified.projection_id,
            projection_record_digest: canonicalContextRecordDigest(record),
            projection_digest: verified.projection_digest,
            created_at: verified.created_at,
            trust_evaluated_at: verified.trust_evaluated_at,
            adapter_status_checked_at: statusCheckedAt,
            adapter_id: record.adapter.id,
            adapter_key_id: record.adapter.key_id,
            delivered_trust: Object.freeze(
              record.delivered.map((entry: RecordLike) => entry.derived_trust),
            ),
            excluded_by_reason: Object.freeze({ ...record.exclusions.by_reason }),
          }),
        });
      } catch (error) {
        return mapFailure(error);
      }
    },
  });
}

export default Object.freeze({ createMemoryProjectionContextProvider });
