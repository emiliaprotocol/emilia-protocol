// SPDX-License-Identifier: Apache-2.0
/**
 * EP-AUTHORITY-REGISTRY-v1 — resolution context providers (stores).
 *
 * A store turns an org + subject into a resolution CONTEXT the pure resolver
 * consumes: { record, resolveParent, snapshot, unavailable }. All I/O and all
 * failure handling lives here. The contract is fail-closed: any inability to
 * read the registry (missing table, query error, absent epoch) surfaces as
 * `{ unavailable: true }`, which the resolver turns into `registry_unavailable`
 * — never a silent allow.
 *
 * Two implementations, one commitment format:
 *   - snapshotStore   pure, in-memory, deterministic; the store the conformance
 *                     vectors, the portable proof, and offline verification use.
 *   - supabaseAuthorityStore  the live mint/consume path; reads the org's
 *                     authority rows + registry epoch in one query each.
 */
import { buildRegistrySnapshot, computeRegistryHead } from './registry-head.js';
import { evaluateAuthorityVerdict } from './resolver.js';

/** Raw authority row shape as read from the registry (Supabase row or snapshot entry). */
export interface AuthorityRecord {
  authority_id?: string;
  organization_id?: string;
  subject_type?: string;
  subject_ref?: string;
  role?: string;
  assurance_class?: string;
  status?: string;
  valid_from?: string | null;
  valid_to?: string | null;
  revoked_at?: string | null;
  action_scopes?: unknown;
  max_amount_usd?: number | null;
  currency?: string;
  delegation_parent?: string | null;
  policy_hash?: string | null;
  [key: string]: unknown;
}

/** Any object naming the subject to resolve authority for, plus resolver input fields. */
export interface AuthorityResolveInput {
  organization_id?: string;
  approver_id?: string;
  principal_id?: string;
  [key: string]: unknown;
}

export interface AuthorityRegistrySnapshotInput {
  epoch?: number;
  entries?: AuthorityRecord[];
  head?: string;
}

export interface AuthorityResolveContext {
  record: AuthorityRecord | null;
  resolveParent?: (id: string) => AuthorityRecord | null;
  snapshot: { epoch: number; head: string } | null;
  unavailable: boolean;
}

export interface AuthorityStore {
  resolveContext(input: AuthorityResolveInput): Promise<AuthorityResolveContext>;
  snapshot?: unknown;
}

function subjectOf(input: AuthorityResolveInput): string | null {
  return input.approver_id || input.principal_id || null;
}

function pickRecord(
  entries: AuthorityRecord[] | null | undefined,
  organizationId: string | undefined,
  subjectRef: string | null,
): AuthorityRecord | null {
  const rows = (entries || []).filter(
    (r) => r.organization_id === organizationId && r.subject_ref === subjectRef,
  );
  if (rows.length === 0) return null;
  // Prefer a human_approver row; then the most-assured; deterministic tiebreak
  // by authority_id so resolution is stable across equal candidates.
  const rank: Record<string, number> = { A: 3, B: 2, C: 1 };
  return rows
    .slice()
    .sort((a, b) => {
      const ht = (b.subject_type === 'human_approver' ? 1 : 0) - (a.subject_type === 'human_approver' ? 1 : 0);
      if (ht) return ht;
      const ra = (rank[b.assurance_class as string] || 0) - (rank[a.assurance_class as string] || 0);
      if (ra) return ra;
      return String(a.authority_id).localeCompare(String(b.authority_id));
    })[0];
}

function parentResolver(entries: AuthorityRecord[] | null | undefined): (id: string) => AuthorityRecord | null {
  const byId = new Map((entries || []).map((r) => [r.authority_id, r]));
  return (id: string) => byId.get(id) || null;
}

/**
 * A pure store over an in-memory registry snapshot.
 *
 * @param snapshot  { epoch:int, entries:object[], head?:'sha256:...' }
 *   If head is omitted it is computed from entries+epoch (the normal case). A
 *   caller MAY pass an explicit head to model a specific commitment.
 */
export function snapshotStore(snapshot: AuthorityRegistrySnapshotInput): AuthorityStore {
  const epoch = Number.isSafeInteger(snapshot?.epoch) ? (snapshot.epoch as number) : 0;
  const entries = Array.isArray(snapshot?.entries) ? snapshot.entries : [];
  const head = snapshot?.head || computeRegistryHead(epoch, entries);
  const resolveParent = parentResolver(entries);
  return {
    async resolveContext(input: AuthorityResolveInput): Promise<AuthorityResolveContext> {
      const subjectRef = subjectOf(input);
      return {
        record: pickRecord(entries, input.organization_id, subjectRef),
        resolveParent,
        snapshot: { epoch, head },
        unavailable: false,
      };
    },
    // Expose the full snapshot for the portable-proof issuer.
    snapshot: buildRegistrySnapshot(epoch, entries),
  };
}

const AUTHORITY_COLUMNS = [
  'authority_id', 'subject_type', 'subject_ref', 'organization_id', 'role',
  'assurance_class', 'status', 'valid_from', 'valid_to', 'revoked_at',
  'action_scopes', 'max_amount_usd', 'currency', 'delegation_parent', 'policy_hash',
].join(', ');

/**
 * Live store over Supabase. Reads the org's authority rows and the org's
 * registry epoch. Fail-closed: any error, or an absent epoch row (registry not
 * yet migrated/initialized for this org), returns unavailable.
 *
 * @param supabase  a query client (service or guarded)
 */
export function supabaseAuthorityStore(supabase: any): AuthorityStore {
  return {
    async resolveContext(input: AuthorityResolveInput): Promise<AuthorityResolveContext> {
      const organizationId = input.organization_id;
      if (!organizationId) return { unavailable: true, record: null, snapshot: null };

      let rows: AuthorityRecord[];
      try {
        const { data, error } = await supabase
          .from('authorities')
          .select(AUTHORITY_COLUMNS)
          .eq('organization_id', organizationId);
        if (error) return { unavailable: true, record: null, snapshot: null };
        rows = data || [];
      } catch {
        return { unavailable: true, record: null, snapshot: null };
      }

      // Epoch: the monotonic registry version for this org. Absent row => the
      // registry is not initialized for this org => unavailable (fail closed).
      let epoch: number;
      try {
        const { data, error } = await supabase
          .from('authority_registry_epoch')
          .select('epoch')
          .eq('organization_id', organizationId)
          .limit(1);
        if (error) return { unavailable: true, record: null, snapshot: null };
        const row = (data || [])[0];
        if (!row || !Number.isFinite(Number(row.epoch))) {
          return { unavailable: true, record: null, snapshot: null };
        }
        epoch = Number(row.epoch);
      } catch {
        return { unavailable: true, record: null, snapshot: null };
      }

      const head = computeRegistryHead(epoch, rows);
      return {
        record: pickRecord(rows, organizationId, subjectOf(input)),
        resolveParent: parentResolver(rows),
        snapshot: { epoch, head },
        unavailable: false,
      };
    },
  };
}

/**
 * Resolve authority against a store and return the pure verdict. This is the
 * one call the mint/consume paths make.
 *
 * @param store  a store (snapshotStore | supabaseAuthorityStore)
 * @param input  the resolver input (see evaluateAuthorityVerdict)
 */
export async function resolveAuthority(store: AuthorityStore, input: AuthorityResolveInput): Promise<any> {
  let ctx: AuthorityResolveContext;
  try {
    ctx = await store.resolveContext(input);
  } catch {
    ctx = { unavailable: true, record: null, snapshot: null };
  }
  return evaluateAuthorityVerdict(ctx, input);
}

const storeApi = { snapshotStore, supabaseAuthorityStore, resolveAuthority };
export default storeApi;
