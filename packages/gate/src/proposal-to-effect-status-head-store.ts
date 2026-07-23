// SPDX-License-Identifier: Apache-2.0
/**
 * Durable relying-party custody for accepted EP-STATUS-v1 heads.
 *
 * The presenter supplies only a candidate status artifact. The store loads the
 * authenticated predecessor, passes that predecessor to trusted verification
 * code, and advances the exact tenant/relying-party/target head only when one
 * database-side compare-and-advance still observes that predecessor. This
 * keeps cryptographic work outside database transactions without opening a
 * time-of-check/time-of-use acceptance race.
 */

import {
  statusArtifactDigest,
  type StatusTarget,
  type StatusVerification,
} from '@emilia-protocol/verify/status';

export const PROPOSAL_TO_EFFECT_STATUS_HEAD_STORE_VERSION =
  'EP-GATE-PTE-STATUS-HEAD-PG-v1';
export const PROPOSAL_TO_EFFECT_STATUS_HEAD_TABLE = 'ep_aeb_status_heads';

export const PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL = Object.freeze({
  get: `SELECT status_digest, sequence, status_state, previous_status_digest,
  issued_at, next_update, status_json, predecessor_status_json
FROM ep_aeb_private.get_status_head(
  $1::text, $2::text, $3::text, $4::text, $5::text, $6::text
)`,
  compareAndAdvance: `SELECT accepted, reason
FROM ep_aeb_private.compare_and_advance_status_head(
  $1::text, $2::text, $3::text, $4::text, $5::text, $6::text,
  $7::text, $8::text, $9::bigint, $10::text, $11::text,
  $12::timestamptz, $13::timestamptz, $14::text
)`,
});

type MaybePromise<T> = T | Promise<T>;

type QueryResult = {
  rowCount: number | null;
  rows?: Record<string, unknown>[];
};

export type ProposalToEffectStatusHeadPgClient = {
  query: (text: string, params?: any[]) => Promise<QueryResult>;
  release: () => void;
};

export type ProposalToEffectStatusHeadPgPool = {
  connect: () => Promise<ProposalToEffectStatusHeadPgClient>;
};

export interface ProposalToEffectStatusHeadAcceptance {
  accepted: boolean;
  source: 'advanced' | 'existing' | null;
  reason: string | null;
  verification: StatusVerification;
}

export interface ProposalToEffectStatusHeadAcceptanceInput {
  target: Readonly<StatusTarget>;
  status: unknown;
  /**
   * Trusted verification callback. Its argument is loaded from durable
   * relying-party custody; no presenter-provided predecessor is accepted.
   */
  verify(previousStatus: unknown | undefined): MaybePromise<StatusVerification>;
}

export interface ProposalToEffectStatusHeadStore {
  durable: true;
  readonly tenantId: string;
  readonly relyingPartyId: string;
  accept(
    input: ProposalToEffectStatusHeadAcceptanceInput,
  ): Promise<ProposalToEffectStatusHeadAcceptance>;
}

export interface PostgresProposalToEffectStatusHeadStoreOptions {
  /** Pool authenticated as a tenant-bound member of ep_aeb_executor. */
  pool?: ProposalToEffectStatusHeadPgPool;
  tenantId?: string;
  relyingPartyId?: string;
}

interface StoredHead {
  statusDigest: string;
  sequence: number;
  statusState: 'not_revoked' | 'revoked';
  previousStatusDigest: string | null;
  issuedAt: string;
  nextUpdate: string | null;
  status: unknown;
  predecessorStatus: unknown | undefined;
}

const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/;
const TARGET_TYPES = new Set(['receipt', 'commit', 'delegation']);
const TARGET_USAGES = new Set(['authorization', 'execution', 'delegation']);

function dataRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return false;
  return Reflect.ownKeys(value).every((key) => {
    if (typeof key !== 'string') return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return Boolean(descriptor?.enumerable && Object.hasOwn(descriptor, 'value'));
  });
}

function denseDataArray(value: unknown): value is unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return false;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes('length')) return false;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return false;
  }
  return true;
}

function snapshotJson(value: unknown, seen = new WeakSet<object>()): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (Number.isFinite(value)) return value;
    throw new TypeError('status head contains a non-finite JSON number');
  }
  if (typeof value !== 'object' || seen.has(value)) {
    throw new TypeError('status head is outside the JSON data model');
  }
  seen.add(value);
  if (denseDataArray(value)) {
    return value.map((member) => snapshotJson(member, seen));
  }
  if (!dataRecord(value)) throw new TypeError('status head is not a plain data object');
  const snapshot: Record<string, unknown> = {};
  for (const key of Object.keys(value)) snapshot[key] = snapshotJson(value[key], seen);
  return snapshot;
}

function assertText(
  value: unknown,
  label: string,
  maximumBytes: number,
): asserts value is string {
  if (typeof value !== 'string'
      || Buffer.byteLength(value, 'utf8') < 1
      || Buffer.byteLength(value, 'utf8') > maximumBytes
      || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new TypeError(`proposal-to-effect status head ${label} is invalid`);
  }
}

function digest(value: unknown): value is string {
  return typeof value === 'string' && DIGEST_PATTERN.test(value);
}

function normalizedInstant(value: unknown, nullable = false): string | null {
  if (nullable && value === null) return null;
  if (typeof value !== 'string') return null;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) return null;
  return new Date(milliseconds).toISOString();
}

function safeInteger(value: unknown): number | null {
  const parsed = typeof value === 'string' && /^[0-9]+$/.test(value)
    ? Number(value) : value;
  return Number.isSafeInteger(parsed) && (parsed as number) >= 0
    ? parsed as number : null;
}

function targetSnapshot(value: unknown): Readonly<StatusTarget> {
  if (!dataRecord(value)
      || Reflect.ownKeys(value).length !== 4
      || !Object.hasOwn(value, 'type')
      || !Object.hasOwn(value, 'id')
      || !Object.hasOwn(value, 'digest')
      || !Object.hasOwn(value, 'usage')
      || !TARGET_TYPES.has(value.type as string)
      || !TARGET_USAGES.has(value.usage as string)
      || typeof value.id !== 'string'
      || Buffer.byteLength(value.id, 'utf8') < 1
      || Buffer.byteLength(value.id, 'utf8') > 512
      || /[\u0000-\u001f\u007f]/.test(value.id)
      || !digest(value.digest)) {
    throw new TypeError('proposal-to-effect status head target is invalid');
  }
  return Object.freeze({
    type: value.type as StatusTarget['type'],
    id: value.id,
    digest: value.digest,
    usage: value.usage as StatusTarget['usage'],
  });
}

function exactRowCount(result: QueryResult, operation: string): number {
  if (!result || !Number.isSafeInteger(result.rowCount) || (result.rowCount as number) < 0) {
    throw new Error(`${operation}: malformed PostgreSQL result`);
  }
  return result.rowCount as number;
}

function parseJsonText(value: unknown, label: string): unknown {
  if (typeof value !== 'string'
      || Buffer.byteLength(value, 'utf8') < 2
      || Buffer.byteLength(value, 'utf8') > 1_048_576) {
    throw new Error(`malformed PostgreSQL status head: ${label}`);
  }
  try {
    return snapshotJson(JSON.parse(value));
  } catch {
    throw new Error(`malformed PostgreSQL status head: ${label}`);
  }
}

function storedHead(result: QueryResult): StoredHead | null {
  const rows = exactRowCount(result, 'load status head');
  if (rows === 0 && (!result.rows || result.rows.length === 0)) return null;
  if (rows !== 1 || result.rows?.length !== 1 || !dataRecord(result.rows[0])) {
    throw new Error('malformed PostgreSQL status head: row cardinality');
  }
  const row = result.rows[0];
  const sequence = safeInteger(row.sequence);
  const issuedAt = normalizedInstant(row.issued_at);
  const nextUpdate = normalizedInstant(row.next_update, true);
  const statusState = row.status_state;
  const previousStatusDigest = row.previous_status_digest;
  if (!digest(row.status_digest)
      || sequence === null
      || (statusState !== 'not_revoked' && statusState !== 'revoked')
      || (previousStatusDigest !== null && !digest(previousStatusDigest))
      || !issuedAt
      || (statusState === 'not_revoked' && !nextUpdate)
      || (statusState === 'revoked' && nextUpdate !== null)) {
    throw new Error('malformed PostgreSQL status head: metadata');
  }
  const status = parseJsonText(row.status_json, 'status_json');
  const predecessorStatus = row.predecessor_status_json === null
    ? undefined : parseJsonText(row.predecessor_status_json, 'predecessor_status_json');
  if (statusArtifactDigest(status) !== row.status_digest
      || (sequence === 0
        && (previousStatusDigest !== null || predecessorStatus !== undefined))
      || (sequence > 0
        && (previousStatusDigest === null
          || predecessorStatus === undefined
          || statusArtifactDigest(predecessorStatus) !== previousStatusDigest))) {
    throw new Error('malformed PostgreSQL status head: chain');
  }
  return {
    statusDigest: row.status_digest,
    sequence,
    statusState,
    previousStatusDigest,
    issuedAt,
    nextUpdate,
    status,
    predecessorStatus,
  };
}

function candidateMetadata(
  status: unknown,
  verification: StatusVerification,
) {
  if (!dataRecord(status)
      || !digest(verification.status_digest)
      || !Number.isSafeInteger(verification.sequence)
      || verification.sequence === null
      || verification.sequence < 0
      || verification.status_digest !== statusArtifactDigest(status)
      || status.sequence !== verification.sequence
      || (status.status !== 'not_revoked' && status.status !== 'revoked')
      || (status.previous_status_digest !== null
        && !digest(status.previous_status_digest))) {
    throw new Error('verified status head metadata is inconsistent');
  }
  const issuedAt = normalizedInstant(status.issued_at);
  const nextUpdate = normalizedInstant(status.next_update, true);
  const verificationNextUpdate = normalizedInstant(verification.next_update, true);
  if (!issuedAt
      || nextUpdate !== verificationNextUpdate
      || (status.status === 'not_revoked' && !nextUpdate)
      || (status.status === 'revoked' && nextUpdate !== null)) {
    throw new Error('verified status head timing is inconsistent');
  }
  return {
    statusDigest: verification.status_digest,
    sequence: verification.sequence,
    statusState: status.status,
    previousStatusDigest: status.previous_status_digest,
    issuedAt,
    nextUpdate,
  };
}

function verificationRefusal(
  verification: StatusVerification,
): ProposalToEffectStatusHeadAcceptance {
  return {
    accepted: false,
    source: null,
    reason: verification.reasons[0] ?? 'status_verification_failed',
    verification,
  };
}

/**
 * Create a durable accepted-head store. The PostgreSQL principal must be bound
 * to tenantId in ep_aeb_private.tenant_principals and inherit ep_aeb_executor.
 */
export function createPostgresProposalToEffectStatusHeadStore({
  pool,
  tenantId,
  relyingPartyId,
}: PostgresProposalToEffectStatusHeadStoreOptions = {}): ProposalToEffectStatusHeadStore {
  if (!pool || typeof pool.connect !== 'function') {
    throw new TypeError(
      'createPostgresProposalToEffectStatusHeadStore requires an ep_aeb_executor pg pool',
    );
  }
  assertText(tenantId, 'tenantId', 512);
  assertText(relyingPartyId, 'relyingPartyId', 512);

  const store: ProposalToEffectStatusHeadStore = {
    durable: true,
    tenantId,
    relyingPartyId,

    async accept(input): Promise<ProposalToEffectStatusHeadAcceptance> {
      const target = targetSnapshot(input?.target);
      const candidate = snapshotJson(input?.status);
      if (typeof input?.verify !== 'function') {
        throw new TypeError('proposal-to-effect status head verify callback is required');
      }
      const candidateDigest = statusArtifactDigest(candidate);
      if (!digest(candidateDigest)) {
        throw new TypeError('proposal-to-effect status head digest is invalid');
      }

      const client = await pool.connect();
      if (!client || typeof client.query !== 'function' || typeof client.release !== 'function') {
        throw new TypeError('status head pg pool returned an invalid client');
      }
      try {
        const current = storedHead(await client.query(
          PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL.get,
          [tenantId, relyingPartyId, target.type, target.id, target.digest, target.usage],
        ));
        const exactReplay = current?.statusDigest === candidateDigest;
        const statusForVerification = exactReplay ? current.status : candidate;
        const previousForVerification = exactReplay
          ? current.predecessorStatus
          : current?.status;
        const verification = await input.verify(previousForVerification);
        if (!dataRecord(verification)
            || typeof verification.valid !== 'boolean'
            || !Array.isArray(verification.reasons)) {
          throw new Error('status head verifier returned a malformed result');
        }
        if (!verification.valid || verification.outcome === 'indeterminate') {
          return verificationRefusal(verification);
        }

        const metadata = candidateMetadata(statusForVerification, verification);
        if (exactReplay) {
          if (metadata.statusDigest !== current.statusDigest
              || metadata.sequence !== current.sequence
              || metadata.statusState !== current.statusState
              || metadata.previousStatusDigest !== current.previousStatusDigest
              || metadata.issuedAt !== current.issuedAt
              || metadata.nextUpdate !== current.nextUpdate) {
            throw new Error('authenticated status head replay metadata mismatch');
          }
        }

        if (!exactReplay && ((!current
          && (metadata.sequence !== 0 || metadata.previousStatusDigest !== null))
          || (current
            && (current.statusState === 'revoked'
              || metadata.sequence !== current.sequence + 1
              || metadata.previousStatusDigest !== current.statusDigest)))) {
          return {
            accepted: false,
            source: null,
            reason: 'status_head_conflict',
            verification,
          };
        }

        const result = await client.query(
          PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL.compareAndAdvance,
          [
            tenantId,
            relyingPartyId,
            target.type,
            target.id,
            target.digest,
            target.usage,
            current?.statusDigest ?? null,
            metadata.statusDigest,
            metadata.sequence,
            metadata.statusState,
            metadata.previousStatusDigest,
            metadata.issuedAt,
            metadata.nextUpdate,
            JSON.stringify(exactReplay ? current.status : candidate),
          ],
        );
        const rows = exactRowCount(result, 'advance status head');
        const accepted = result.rows?.[0]?.accepted;
        const reason = result.rows?.[0]?.reason;
        if (rows !== 1
            || result.rows?.length !== 1
            || typeof accepted !== 'boolean'
            || (reason !== null && typeof reason !== 'string')
            || (accepted && reason !== null)) {
          throw new Error('advance status head: malformed PostgreSQL result');
        }
        if (!accepted) {
          return {
            accepted: false,
            source: null,
            reason: 'status_head_conflict',
            verification,
          };
        }
        return {
          accepted: true,
          source: exactReplay ? 'existing' : 'advanced',
          reason: null,
          verification,
        };
      } finally {
        client.release();
      }
    },
  };

  return Object.freeze(store);
}

export default {
  PROPOSAL_TO_EFFECT_STATUS_HEAD_STORE_VERSION,
  PROPOSAL_TO_EFFECT_STATUS_HEAD_TABLE,
  PROPOSAL_TO_EFFECT_STATUS_HEAD_SQL,
  createPostgresProposalToEffectStatusHeadStore,
};
