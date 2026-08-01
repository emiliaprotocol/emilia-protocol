// SPDX-License-Identifier: Apache-2.0
/**
 * Tenant-scoped Postgres sequence store for EP-GATE-NETWORK-WITNESS-v1.
 *
 * The migration owns synchronization and authorization. Runtime callers get
 * EXECUTE on one SECURITY DEFINER function, not INSERT/UPDATE privileges on the
 * checkpoint table. Database ambiguity is allowed to throw so the witness
 * ingestion kernel can fail closed as `sequence_store_unavailable`.
 */
export const PG_WITNESS_SEQUENCE_VERSION = 'EP-GATE-PG-WITNESS-SEQUENCE-v1';
export const WITNESS_CHECKPOINT_FUNCTION = 'emilia_gate_evidence.advance_network_witness_checkpoint';
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/;
const CLOSED_REASONS = new Set(['statement_replay', 'sequence_rollback', 'sequence_equivocation']);
export const WITNESS_SEQUENCE_SQL = Object.freeze({
    advance: `SELECT accepted, reason
FROM ${WITNESS_CHECKPOINT_FUNCTION}($1, $2, $3::bytea, $4::bigint, $5)`,
});
function scopedId(value, label) {
    if (typeof value !== 'string' || value.length === 0 || value.length > 256
        || /[\u0000-\u001f\u007f]/.test(value)) {
        throw new Error(`${label} must be a non-empty control-free string of at most 256 characters`);
    }
    return value;
}
function streamBytes(value) {
    if (typeof value !== 'string' || value.length > 513) {
        throw new Error('witness streamId is invalid');
    }
    const parts = value.split('\0');
    if (parts.length !== 2 || parts.some((part) => part.length === 0 || part.length > 256
        || /[\u0000-\u001f\u007f]/.test(part))) {
        throw new Error('witness streamId must contain one witness-id/capture-point separator');
    }
    return Buffer.from(value, 'utf8');
}
function definitiveRow(result) {
    if (!result || result.rowCount !== 1 || !Array.isArray(result.rows)
        || result.rows.length !== 1 || typeof result.rows[0]?.accepted !== 'boolean') {
        throw new Error('witness checkpoint outcome is unproven');
    }
    const { accepted, reason } = result.rows[0];
    if (accepted) {
        if (reason !== null && reason !== undefined && reason !== '') {
            throw new Error('accepted witness checkpoint carried a refusal reason');
        }
        return { accepted: true, reason: null };
    }
    if (!CLOSED_REASONS.has(reason)) {
        throw new Error('witness checkpoint returned an unknown refusal reason');
    }
    return { accepted: false, reason };
}
/**
 * Create the durable store expected by acceptNetworkWitnessStatement().
 * `query` is a node-postgres style function such as pool.query.bind(pool).
 * @param {{ query?: Function, tenantId?: string|number, gateId?: string|number }} [o]
 */
export function createPostgresWitnessSequenceStore({ query, tenantId, gateId, } = {}) {
    if (typeof query !== 'function') {
        throw new Error('createPostgresWitnessSequenceStore: query must be an async pg-style function');
    }
    const tenant = scopedId(tenantId, 'tenantId');
    const gate = scopedId(gateId, 'gateId');
    return Object.freeze({
        durable: true,
        scope: Object.freeze({ tenantId: tenant, gateId: gate }),
        async advance(streamId, sequence, statementDigest) {
            if (!Number.isSafeInteger(sequence) || sequence < 0) {
                throw new Error('witness sequence must be a non-negative safe integer');
            }
            if (typeof statementDigest !== 'string' || !DIGEST_RE.test(statementDigest)) {
                throw new Error('witness statement digest is invalid');
            }
            const result = await query(WITNESS_SEQUENCE_SQL.advance, [
                tenant,
                gate,
                streamBytes(streamId),
                sequence,
                statementDigest,
            ]);
            return definitiveRow(result);
        },
    });
}
export default {
    PG_WITNESS_SEQUENCE_VERSION,
    WITNESS_CHECKPOINT_FUNCTION,
    WITNESS_SEQUENCE_SQL,
    createPostgresWitnessSequenceStore,
};
//# sourceMappingURL=witness-postgres.js.map