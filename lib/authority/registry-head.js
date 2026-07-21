// SPDX-License-Identifier: Apache-2.0
// Generated from registry-head.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * EP-AUTHORITY-REGISTRY-v1 — registry epoch + head commitment.
 *
 * The receipt binds `authority_registry_epoch` (a monotonic counter of the
 * org's registry state) and `authority_registry_head` (a sha256 commitment to
 * the org's authority set AT that epoch). Together they let an offline relying
 * party say two things it otherwise cannot:
 *   - STALE: "I will not rely on a registry older than epoch N" (a pin).
 *   - EQUIVOCATION: "the head I recompute from the registry snapshot I hold
 *     must equal the head this receipt committed to."
 *
 * The head is scoped to an organization: relying parties pin authority per org,
 * and hashing one org's handful of authority rows is cheap on the mint path.
 * The commitment format here is the single source of truth — the live store,
 * the snapshot store, the portable proof, and every conformance vector compute
 * the head with THIS function, so the bytes are identical everywhere.
 */
import crypto from 'node:crypto';
import { canonicalize } from '../canonical-json.js';
export const AUTHORITY_REGISTRY_VERSION = 'EP-AUTHORITY-REGISTRY-v1';
function sha256hex(bytes) {
    return crypto.createHash('sha256').update(bytes).digest('hex');
}
/**
 * The canonical, hash-stable projection of one authority row. Only the fields
 * that DEFINE the grant are committed; volatile/audit columns (created_at,
 * metadata) are excluded so an unrelated metadata edit does not churn the head.
 */
export function canonicalAuthorityEntry(row) {
    return {
        action_scopes: Array.isArray(row.action_scopes) ? [...row.action_scopes].sort() : (row.action_scopes ?? null),
        assurance_class: row.assurance_class ?? null,
        authority_id: row.authority_id ?? null,
        currency: row.currency ?? 'USD',
        delegation_parent: row.delegation_parent ?? null,
        max_amount_usd: typeof row.max_amount_usd === 'number' ? row.max_amount_usd : (row.max_amount_usd == null ? null : Number(row.max_amount_usd)),
        organization_id: row.organization_id ?? null,
        policy_hash: row.policy_hash ?? null,
        revoked_at: row.revoked_at ?? null,
        role: row.role ?? null,
        status: row.status ?? 'active',
        subject_ref: row.subject_ref ?? null,
        subject_type: row.subject_type ?? null,
        valid_from: row.valid_from ?? null,
        valid_to: row.valid_to ?? null,
    };
}
/**
 * Compute the registry head over a set of authority rows at a given epoch.
 * Order-independent: entries are sorted by authority_id before hashing so the
 * head depends only on the SET of grants, not row-return order.
 *
 * @param {number} epoch  a safe integer
 * @param {object[]} entries  authority rows (any order)
 * @returns {string} 'sha256:<hex>'
 */
export function computeRegistryHead(epoch, entries) {
    const canonEntries = (Array.isArray(entries) ? entries : [])
        .map(canonicalAuthorityEntry)
        .sort((a, b) => String(a.authority_id).localeCompare(String(b.authority_id)));
    const commitment = {
        '@version': AUTHORITY_REGISTRY_VERSION,
        epoch: Number.isSafeInteger(epoch) ? epoch : 0,
        authorities: canonEntries,
    };
    return `sha256:${sha256hex(canonicalize(commitment))}`;
}
/**
 * Build a full snapshot commitment from raw rows: { epoch, head, entries }.
 * Used by the snapshot store (vectors/offline) and the portable proof issuer.
 */
export function buildRegistrySnapshot(epoch, entries) {
    const list = Array.isArray(entries) ? entries : [];
    return Object.freeze({
        epoch: Number.isSafeInteger(epoch) ? epoch : 0,
        head: computeRegistryHead(epoch, list),
        entries: list,
    });
}
const registryHeadApi = {
    AUTHORITY_REGISTRY_VERSION,
    canonicalAuthorityEntry,
    computeRegistryHead,
    buildRegistrySnapshot,
};
export default registryHeadApi;
