/**
 * Cloud Control Plane — Event Explorer
 *
 * Unified query, timeline, search, and integrity verification across
 * all EP event tables (protocol_events, handshake_events, signoff_events).
 *
 * All reads go through getGuardedClient() to enforce write discipline.
 *
 * @license Apache-2.0
 */

import { getGuardedClient } from '@/lib/write-guard';

/** Escape LIKE metacharacters to prevent pattern injection. */
function escapeLike(str) {
  return str.replace(/[%_\\]/g, '\\$&');
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Normalize an event row from any source table into the unified shape.
 */
function normalizeEvent(row, source) {
  return {
    event_id: row.event_id || row.id,
    source_table: source,
    handshake_id: row.handshake_id || null,
    challenge_id: row.challenge_id || null,
    signoff_id: row.signoff_id || null,
    event_type: row.event_type,
    actor_entity_ref: row.actor_entity_ref || row.actor_id || 'system',
    detail: row.detail || row.event_payload || {},
    created_at: row.created_at,
  };
}

/**
 * Apply common filters to a Supabase query builder.
 */
function applyFilters(query, filters) {
  if (filters.handshake_id) {
    query = query.eq('handshake_id', filters.handshake_id);
  }
  if (filters.event_type) {
    query = query.eq('event_type', filters.event_type);
  }
  if (filters.actor_entity_ref) {
    query = query.eq('actor_entity_ref', filters.actor_entity_ref);
  }
  if (filters.date_from) {
    query = query.gte('created_at', filters.date_from);
  }
  if (filters.date_to) {
    query = query.lte('created_at', filters.date_to);
  }
  return query;
}

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Query events across all event tables with unified filtering.
 *
 * @param {object} filters
 * @param {string} [filters.handshake_id]
 * @param {string} [filters.event_type]
 * @param {string} [filters.actor_entity_ref]
 * @param {string} [filters.date_from] - ISO 8601 lower bound
 * @param {string} [filters.date_to] - ISO 8601 upper bound
 * @param {number} [filters.limit=50]
 * @param {number} [filters.offset=0]
 * @returns {Promise<{ events: object[], total: number }>}
 */
export async function queryEvents(filters = {}) {
  const supabase = getGuardedClient();
  const limit = Math.min(Math.max(parseInt(filters.limit, 10) || 50, 1), 500);
  const offset = Math.max(parseInt(filters.offset, 10) || 0, 0);

  // Query all three tables in parallel
  const tables = [
    { name: 'protocol_events', selectCols: '*' },
    { name: 'handshake_events', selectCols: '*' },
    { name: 'signoff_events', selectCols: '*' },
  ];

  const queries = tables.map(async ({ name, selectCols }) => {
    try {
      let q = supabase.from(name).select(selectCols, { count: 'exact' });
      q = applyFilters(q, filters);
      q = q.order('created_at', { ascending: false });

      const { data, count, error } = await q;
      if (error) {
        // Table may not exist yet — degrade gracefully
        if (error.message?.includes('does not exist') || error.message?.includes('relation')) {
          return { rows: [], count: 0 };
        }
        throw error;
      }
      return {
        rows: (data || []).map(row => normalizeEvent(row, name)),
        count: count || 0,
      };
    } catch (e) {
      console.warn(`[event-explorer] Query on ${name} failed:`, e.message);
      return { rows: [], count: 0 };
    }
  });

  const results = await Promise.all(queries);

  // Merge and sort all events by created_at descending
  const allEvents = results.flatMap(r => r.rows);
  allEvents.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  const total = results.reduce((sum, r) => sum + r.count, 0);

  // Apply pagination to the merged result
  const paginated = allEvents.slice(offset, offset + limit);

  return { events: paginated, total };
}

/**
 * Build a complete chronological timeline for a single handshake.
 *
 * Joins handshake_events and signoff_events sharing the same handshake_id,
 * returning them in ascending created_at order.
 *
 * @param {string} handshakeId
 * @param {string} tenantId - Required for tenant isolation. The caller must
 *   pass the authenticated tenant's ID so we can verify the handshake belongs
 *   to this tenant before returning events.
 * @returns {Promise<object[]>} Chronologically ordered events
 */
export async function getTimeline(handshakeId, tenantId) {
  if (!handshakeId) {
    throw new Error('handshakeId is required');
  }
  if (!tenantId) {
    throw new Error('tenantId is required for tenant isolation');
  }

  const supabase = getGuardedClient();

  // ── Tenant isolation: verify the handshake belongs to this tenant ──
  // NOTE: If handshake_bindings / handshakes tables don't have a tenant_id
  // column, tenant isolation for protocol tables requires migration 054
  // (to be created separately). For now we check handshake_bindings first.
  const { data: binding } = await supabase
    .from('handshake_bindings')
    .select('tenant_id')
    .eq('handshake_id', handshakeId)
    .maybeSingle();

  if (binding && binding.tenant_id && binding.tenant_id !== tenantId) {
    throw new Error('Handshake does not belong to this tenant');
  }

  const [handshakeRes, signoffRes] = await Promise.all([
    supabase
      .from('handshake_events')
      .select('*')
      .eq('handshake_id', handshakeId)
      .order('created_at', { ascending: true })
      .then(r => r)
      .catch(() => ({ data: [], error: null })),
    supabase
      .from('signoff_events')
      .select('*')
      .eq('handshake_id', handshakeId)
      .order('created_at', { ascending: true })
      .then(r => r)
      .catch(() => ({ data: [], error: null })),
  ]);

  const events = [
    ...(handshakeRes.data || []).map(r => normalizeEvent(r, 'handshake_events')),
    ...(signoffRes.data || []).map(r => normalizeEvent(r, 'signoff_events')),
  ];

  events.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));

  return events;
}

/**
 * Full-text search across event JSONB detail fields.
 *
 * @param {string} query - Text to search for in detail fields
 * @param {object} [filters]
 * @param {string[]} [filters.event_types] - Filter to specific event types
 * @param {object} [filters.date_range] - { from, to } ISO timestamps
 * @returns {Promise<object[]>} Matching events with source context
 */
export async function searchEvents(query, filters = {}) {
  if (!query || typeof query !== 'string' || query.trim().length === 0) {
    throw new Error('query is required and must be a non-empty string');
  }

  const supabase = getGuardedClient();
  const searchTerm = query.trim();

  const tables = ['handshake_events', 'signoff_events', 'protocol_events'];

  const searches = tables.map(async (table) => {
    try {
      let q = supabase
        .from(table)
        .select('*')
        .textSearch('detail', searchTerm, { type: 'plain' });

      if (filters.event_types?.length) {
        q = q.in('event_type', filters.event_types);
      }
      if (filters.date_range?.from) {
        q = q.gte('created_at', filters.date_range.from);
      }
      if (filters.date_range?.to) {
        q = q.lte('created_at', filters.date_range.to);
      }

      q = q.order('created_at', { ascending: false }).limit(100);

      const { data, error } = await q;

      if (error) {
        // textSearch may not work on JSONB in all configs — fallback to cast
        if (error.message?.includes('text search') || error.message?.includes('does not exist')) {
          // Fallback: filter with ilike on detail::text
          let fallback = supabase
            .from(table)
            .select('*')
            .ilike('detail::text', `%${escapeLike(searchTerm)}%`);

          if (filters.event_types?.length) {
            fallback = fallback.in('event_type', filters.event_types);
          }
          if (filters.date_range?.from) {
            fallback = fallback.gte('created_at', filters.date_range.from);
          }
          if (filters.date_range?.to) {
            fallback = fallback.lte('created_at', filters.date_range.to);
          }

          fallback = fallback.order('created_at', { ascending: false }).limit(100);

          const fallbackRes = await fallback;
          return (fallbackRes.data || []).map(r => normalizeEvent(r, table));
        }
        return [];
      }

      return (data || []).map(r => normalizeEvent(r, table));
    } catch (e) {
      console.warn(`[event-explorer] Search on ${table} failed:`, e.message);
      return [];
    }
  });

  const results = await Promise.all(searches);
  const allMatches = results.flat();
  allMatches.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  return allMatches;
}

/**
 * Verify event integrity across a date range.
 *
 * Checks:
 * 1. No gaps in handshake event sequences (every handshake with events
 *    should have a creation event as first).
 * 2. All handshakes with a terminal status have a matching terminal event.
 * 3. Event sequences are monotonically ordered by created_at.
 *
 * @param {object} [dateRange] - { from, to } ISO timestamps
 * @returns {Promise<{ score: number, total_events: number, anomalies: object[] }>}
 */
export async function verifyIntegrity(dateRange = {}) {
  const supabase = getGuardedClient();
  const anomalies = [];

  // ── 1. Fetch handshake events ──
  let heQuery = supabase
    .from('handshake_events')
    .select('*')
    .order('created_at', { ascending: true });

  if (dateRange.from) heQuery = heQuery.gte('created_at', dateRange.from);
  if (dateRange.to) heQuery = heQuery.lte('created_at', dateRange.to);

  const { data: hEvents, error: heError } = await heQuery;
  if (heError && !heError.message?.includes('does not exist')) {
    throw new Error(`Integrity check failed on handshake_events: ${heError.message}`);
  }
  const handshakeEvents = hEvents || [];

  // ── 2. Fetch signoff events ──
  let seQuery = supabase
    .from('signoff_events')
    .select('*')
    .order('created_at', { ascending: true });

  if (dateRange.from) seQuery = seQuery.gte('created_at', dateRange.from);
  if (dateRange.to) seQuery = seQuery.lte('created_at', dateRange.to);

  const { data: sEvents, error: seError } = await seQuery;
  if (seError && !seError.message?.includes('does not exist')) {
    throw new Error(`Integrity check failed on signoff_events: ${seError.message}`);
  }
  const signoffEvents = sEvents || [];

  const totalEvents = handshakeEvents.length + signoffEvents.length;

  // ── 3. Group handshake events by handshake_id and check sequences ──
  const byHandshake = new Map();
  for (const ev of handshakeEvents) {
    if (!byHandshake.has(ev.handshake_id)) {
      byHandshake.set(ev.handshake_id, []);
    }
    byHandshake.get(ev.handshake_id).push(ev);
  }

  for (const [hsId, events] of byHandshake) {
    // Check chronological ordering (no timestamp inversions)
    for (let i = 1; i < events.length; i++) {
      if (new Date(events[i].created_at) < new Date(events[i - 1].created_at)) {
        anomalies.push({
          type: 'timestamp_inversion',
          table: 'handshake_events',
          handshake_id: hsId,
          detail: `Event at index ${i} precedes event at index ${i - 1}`,
        });
      }
    }

    // Check that a creation event exists as first event
    const firstType = events[0]?.event_type;
    const creationTypes = ['handshake_created', 'initiated'];
    if (!creationTypes.includes(firstType)) {
      anomalies.push({
        type: 'missing_creation_event',
        table: 'handshake_events',
        handshake_id: hsId,
        detail: `First event is "${firstType}" instead of a creation event`,
      });
    }
  }

  // ── 4. Check handshakes in terminal states have matching terminal events ──
  const terminalStates = ['verified', 'rejected', 'expired', 'cancelled', 'revoked'];
  const terminalEventTypes = [
    'handshake_verified', 'verified',
    'handshake_rejected', 'rejected',
    'handshake_expired', 'expired',
    'handshake_cancelled', 'cancelled',
    'handshake_revoked', 'revoked',
  ];

  let hsQuery = supabase
    .from('handshakes')
    .select('id, status')
    .in('status', terminalStates);

  if (dateRange.from) hsQuery = hsQuery.gte('created_at', dateRange.from);
  if (dateRange.to) hsQuery = hsQuery.lte('created_at', dateRange.to);

  const { data: terminalHandshakes } = await hsQuery;

  for (const hs of (terminalHandshakes || [])) {
    const events = byHandshake.get(hs.id) || [];
    const hasTerminalEvent = events.some(e => terminalEventTypes.includes(e.event_type));
    if (!hasTerminalEvent) {
      anomalies.push({
        type: 'missing_terminal_event',
        table: 'handshake_events',
        handshake_id: hs.id,
        detail: `Handshake in "${hs.status}" state but no matching terminal event found`,
      });
    }
  }

  // ── 5. Compute integrity score ──
  // 100 = perfect, penalize each anomaly
  const maxPenalty = totalEvents > 0 ? 100 : 0;
  const penaltyPerAnomaly = totalEvents > 0 ? Math.min(10, 100 / totalEvents) : 0;
  const score = Math.max(0, maxPenalty - anomalies.length * penaltyPerAnomaly);

  return {
    score: Math.round(score * 100) / 100,
    total_events: totalEvents,
    handshake_event_count: handshakeEvents.length,
    signoff_event_count: signoffEvents.length,
    handshakes_checked: byHandshake.size,
    terminal_handshakes_checked: (terminalHandshakes || []).length,
    anomalies,
  };
}
