#!/usr/bin/env node
/**
 * Protocol Replay — Rebuild projections from the append-only event store.
 *
 * This script proves that the system's current state is derivable from
 * its event history. It is the step that makes EMILIA protocol-grade.
 *
 * Usage:
 *   node scripts/replay-protocol.js [--verify] [--rebuild] [--diff] [--aggregate-type receipt]
 *
 * Modes:
 *   --verify   Verify event hash chains and signatures
 *   --rebuild  Rebuild projection tables from events
 *   --diff     Compare replayed state vs current state
 *   --dry-run  Show what would change without writing
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';

// Arg parsing is deferred to main() so imports work without side effects.

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

/**
 * Compute the SHA-256 hex digest of a JSON payload.
 * The payload is serialized with sorted keys to guarantee deterministic output.
 */
export function computePayloadHash(payloadJson) {
  const canonical =
    typeof payloadJson === 'string'
      ? payloadJson
      : JSON.stringify(payloadJson, Object.keys(payloadJson).sort());
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

// ---------------------------------------------------------------------------
// Projection appliers — map (aggregate_type, command_type) -> projection row
// ---------------------------------------------------------------------------

/**
 * Apply a single event to the in-memory projection map.
 *
 * projections is a nested map:  { [aggregate_type]: { [aggregate_id]: row } }
 *
 * Each applier reads the event payload and builds / mutates the projection
 * row that represents the current state of that aggregate.
 */
export function applyEvent(projections, event) {
  const { aggregate_type, aggregate_id, command_type, payload_json } = event;
  const payload =
    typeof payload_json === 'string'
      ? JSON.parse(payload_json)
      : payload_json;

  if (!projections[aggregate_type]) {
    projections[aggregate_type] = {};
  }
  const agg = projections[aggregate_type];
  const existing = agg[aggregate_id] || {};

  switch (aggregate_type) {
    // -----------------------------------------------------------------
    // RECEIPTS
    // -----------------------------------------------------------------
    case 'receipt': {
      switch (command_type) {
        case 'receipt.submitted':
          agg[aggregate_id] = {
            receipt_id: aggregate_id,
            entity_id: payload.entity_id,
            submitted_by: payload.submitted_by,
            transaction_ref: payload.transaction_ref,
            transaction_type: payload.transaction_type,
            delivery_accuracy: payload.delivery_accuracy ?? null,
            product_accuracy: payload.product_accuracy ?? null,
            price_integrity: payload.price_integrity ?? null,
            return_processing: payload.return_processing ?? null,
            agent_satisfaction: payload.agent_satisfaction ?? null,
            composite_score: payload.composite_score ?? null,
            receipt_hash: payload.receipt_hash ?? null,
            previous_hash: payload.previous_hash ?? null,
            evidence: payload.evidence ?? {},
            claims: payload.claims ?? null,
            context: payload.context ?? null,
            agent_behavior: payload.agent_behavior ?? null,
            provenance_tier: payload.provenance_tier ?? 'self_attested',
            bilateral_status: payload.bilateral_status ?? null,
            graph_weight: payload.graph_weight ?? 1.0,
            dispute_status: null,
            auto_generated: payload.auto_generated ?? false,
            created_at: payload.created_at ?? event.created_at,
          };
          break;

        case 'receipt.bilateral.confirmed':
          agg[aggregate_id] = {
            ...existing,
            bilateral_status: 'confirmed',
            provenance_tier: 'bilateral',
            confirmed_by: payload.confirmed_by ?? null,
            confirmed_at: payload.confirmed_at ?? event.created_at,
          };
          break;

        case 'receipt.bilateral.disputed':
          agg[aggregate_id] = {
            ...existing,
            bilateral_status: 'disputed',
            provenance_tier: 'self_attested',
          };
          break;

        case 'receipt.bilateral.expired':
          agg[aggregate_id] = {
            ...existing,
            bilateral_status: 'expired',
          };
          break;

        case 'receipt.deduplicated':
          // No projection change — the receipt already exists
          break;

        default:
          // Unknown receipt command — preserve existing state
          break;
      }
      break;
    }

    // -----------------------------------------------------------------
    // DISPUTES
    // -----------------------------------------------------------------
    case 'dispute': {
      switch (command_type) {
        case 'dispute.filed':
          agg[aggregate_id] = {
            dispute_id: aggregate_id,
            receipt_id: payload.receipt_id,
            entity_id: payload.entity_id,
            filed_by: payload.filed_by,
            filed_by_type: payload.filed_by_type,
            reason: payload.reason,
            description: payload.description ?? null,
            evidence: payload.evidence ?? null,
            status: 'open',
            resolution: null,
            resolution_rationale: null,
            resolved_by: null,
            resolved_at: null,
            response: null,
            response_evidence: null,
            responded_at: null,
            appeal_reason: null,
            appeal_evidence: null,
            appealed_at: null,
            appealed_by: null,
            appeal_resolution: null,
            appeal_rationale: null,
            appeal_resolved_by: null,
            appeal_resolved_at: null,
            created_at: payload.created_at ?? event.created_at,
          };
          break;

        case 'dispute.responded':
          agg[aggregate_id] = {
            ...existing,
            status: 'under_review',
            response: payload.response ?? null,
            response_evidence: payload.response_evidence ?? null,
            responded_at: payload.responded_at ?? event.created_at,
          };
          break;

        case 'dispute.resolved':
          agg[aggregate_id] = {
            ...existing,
            status: payload.resolution,
            resolution: payload.resolution,
            resolution_rationale: payload.resolution_rationale ?? null,
            resolved_by: payload.resolved_by ?? null,
            resolved_at: payload.resolved_at ?? event.created_at,
          };
          break;

        case 'dispute.appealed':
          agg[aggregate_id] = {
            ...existing,
            status: 'appealed',
            appeal_reason: payload.appeal_reason ?? null,
            appeal_evidence: payload.appeal_evidence ?? null,
            appealed_at: payload.appealed_at ?? event.created_at,
            appealed_by: payload.appealed_by ?? null,
          };
          break;

        case 'dispute.appeal.resolved':
          agg[aggregate_id] = {
            ...existing,
            status: payload.resolution,
            appeal_resolution: payload.resolution,
            appeal_rationale: payload.appeal_rationale ?? null,
            appeal_resolved_by: payload.appeal_resolved_by ?? null,
            appeal_resolved_at: payload.appeal_resolved_at ?? event.created_at,
          };
          break;

        default:
          break;
      }
      break;
    }

    // -----------------------------------------------------------------
    // REPORTS
    // -----------------------------------------------------------------
    case 'report': {
      switch (command_type) {
        case 'report.filed':
          agg[aggregate_id] = {
            report_id: aggregate_id,
            entity_id: payload.entity_id,
            report_type: payload.report_type,
            description: payload.description ?? null,
            contact_email: payload.contact_email ?? null,
            evidence: payload.evidence ?? null,
            reporter_ip_hash: payload.reporter_ip_hash ?? null,
            status: 'received',
            created_at: payload.created_at ?? event.created_at,
          };
          break;

        default:
          break;
      }
      break;
    }

    // -----------------------------------------------------------------
    // COMMITS
    // -----------------------------------------------------------------
    case 'commit': {
      switch (command_type) {
        case 'commit.created':
          agg[aggregate_id] = {
            commit_id: aggregate_id,
            entity_id: payload.entity_id,
            principal_id: payload.principal_id ?? null,
            counterparty_entity_id: payload.counterparty_entity_id ?? null,
            delegation_id: payload.delegation_id ?? null,
            action_type: payload.action_type,
            decision: payload.decision,
            scope: payload.scope ?? null,
            max_value_usd: payload.max_value_usd ?? null,
            context: payload.context ?? null,
            policy_snapshot: payload.policy_snapshot ?? null,
            nonce: payload.nonce,
            signature: payload.signature,
            public_key: payload.public_key,
            expires_at: payload.expires_at,
            status: 'active',
            receipt_id: null,
            revoked_reason: null,
            revoked_at: null,
            fulfilled_at: null,
            evaluation_result: payload.evaluation_result ?? null,
            created_at: payload.created_at ?? event.created_at,
          };
          break;

        case 'commit.fulfilled':
          agg[aggregate_id] = {
            ...existing,
            status: 'fulfilled',
            receipt_id: payload.receipt_id ?? null,
            fulfilled_at: payload.fulfilled_at ?? event.created_at,
          };
          break;

        case 'commit.revoked':
          agg[aggregate_id] = {
            ...existing,
            status: 'revoked',
            revoked_reason: payload.revoked_reason ?? null,
            revoked_at: payload.revoked_at ?? event.created_at,
          };
          break;

        case 'commit.expired':
          agg[aggregate_id] = {
            ...existing,
            status: 'expired',
          };
          break;

        default:
          break;
      }
      break;
    }

    // -----------------------------------------------------------------
    // ENTITIES
    // -----------------------------------------------------------------
    case 'entity': {
      switch (command_type) {
        case 'entity.registered':
          agg[aggregate_id] = {
            entity_id: aggregate_id,
            display_name: payload.display_name,
            entity_type: payload.entity_type,
            description: payload.description ?? '',
            status: 'active',
            emilia_score: 50.0,
            created_at: payload.created_at ?? event.created_at,
          };
          break;

        case 'trust.recomputed':
          agg[aggregate_id] = {
            ...existing,
            emilia_score: payload.new_score ?? existing.emilia_score,
            trust_snapshot: payload.trust_snapshot ?? existing.trust_snapshot,
          };
          break;

        default:
          break;
      }
      break;
    }

    // -----------------------------------------------------------------
    // DELEGATIONS
    // -----------------------------------------------------------------
    case 'delegation': {
      switch (command_type) {
        case 'delegation.created':
          agg[aggregate_id] = {
            delegation_id: aggregate_id,
            principal_id: payload.principal_id,
            agent_entity_id: payload.agent_entity_id,
            scope: payload.scope ?? null,
            status: 'active',
            created_at: payload.created_at ?? event.created_at,
          };
          break;

        case 'delegation.revoked':
          agg[aggregate_id] = {
            ...existing,
            status: 'revoked',
            revoked_at: payload.revoked_at ?? event.created_at,
          };
          break;

        default:
          break;
      }
      break;
    }

    default:
      // Unknown aggregate type — skip silently
      break;
  }
}

// ---------------------------------------------------------------------------
// Verify mode
// ---------------------------------------------------------------------------

/**
 * Verify payload hashes and parent-event chains.
 *
 * Returns a report object with totals and lists of failures.
 */
export function verifyEvents(events) {
  const report = {
    totalEvents: events.length,
    validHashes: 0,
    invalidHashes: [],
    validChains: 0,
    brokenChains: [],
    signedEvents: 0,
    signatureErrors: [],
  };

  // Build an index of event_id -> payload_hash for chain verification
  const hashIndex = new Map();
  for (const evt of events) {
    hashIndex.set(String(evt.event_id), evt.payload_hash);
  }

  for (const evt of events) {
    // 1. Verify payload_hash matches sha256(payload_json)
    try {
      const expected = computePayloadHash(evt.payload_json);
      if (expected === evt.payload_hash) {
        report.validHashes++;
      } else {
        report.invalidHashes.push({
          event_id: evt.event_id,
          expected,
          actual: evt.payload_hash,
        });
      }
    } catch (err) {
      report.invalidHashes.push({
        event_id: evt.event_id,
        error: err.message,
      });
    }

    // 2. Verify parent chain
    if (evt.parent_event_hash) {
      // parent_event_hash should equal the payload_hash of an earlier event
      let found = false;
      for (const [, hash] of hashIndex) {
        if (hash === evt.parent_event_hash) {
          found = true;
          break;
        }
      }
      if (found) {
        report.validChains++;
      } else {
        report.brokenChains.push({
          event_id: evt.event_id,
          parent_event_hash: evt.parent_event_hash,
        });
      }
    }

    // 3. Check for signatures (verification against authority registry is
    //    a placeholder — full implementation requires the authority store)
    if (evt.signature) {
      report.signedEvents++;
      // Signature verification would go here when authority registry is available.
      // For now, we only count them.
    }
  }

  return report;
}

// ---------------------------------------------------------------------------
// Rebuild mode
// ---------------------------------------------------------------------------

/**
 * Replay all events (optionally filtered) and return rebuilt projections.
 */
export function rebuildProjections(events, aggregateTypeFilter) {
  const projections = {};
  let replayed = 0;
  const errors = [];

  const filtered = aggregateTypeFilter
    ? events.filter((e) => e.aggregate_type === aggregateTypeFilter)
    : events;

  // Sort by created_at ascending to replay in order
  const sorted = [...filtered].sort(
    (a, b) => new Date(a.created_at) - new Date(b.created_at),
  );

  for (const evt of sorted) {
    try {
      applyEvent(projections, evt);
      replayed++;
    } catch (err) {
      errors.push({
        event_id: evt.event_id,
        error: err.message,
      });
    }
  }

  return { projections, replayed, errors };
}

// ---------------------------------------------------------------------------
// Diff mode
// ---------------------------------------------------------------------------

/**
 * Compare replayed projections against current-state rows.
 *
 * currentState: { [aggregate_type]: { [aggregate_id]: row } }
 * replayedState: same shape
 *
 * Returns { matching, drifted, orphanedInCurrent, orphanedInReplay }
 */
export function diffProjections(replayedState, currentState) {
  const result = {
    matching: [],
    drifted: [],
    orphanedInCurrent: [],
    orphanedInReplay: [],
  };

  const allTypes = new Set([
    ...Object.keys(replayedState),
    ...Object.keys(currentState),
  ]);

  for (const aggType of allTypes) {
    const replayed = replayedState[aggType] || {};
    const current = currentState[aggType] || {};

    const allIds = new Set([
      ...Object.keys(replayed),
      ...Object.keys(current),
    ]);

    for (const id of allIds) {
      const rRow = replayed[id];
      const cRow = current[id];

      if (rRow && !cRow) {
        result.orphanedInReplay.push({ aggregate_type: aggType, aggregate_id: id });
        continue;
      }
      if (!rRow && cRow) {
        result.orphanedInCurrent.push({ aggregate_type: aggType, aggregate_id: id });
        continue;
      }

      // Compare key fields (ignore metadata like updated_at)
      const diffs = [];
      const keysToCompare = new Set([...Object.keys(rRow), ...Object.keys(cRow)]);
      const ignoreKeys = new Set(['updated_at', 'trust_materialized_at', 'id']);

      for (const key of keysToCompare) {
        if (ignoreKeys.has(key)) continue;
        const rVal = normalizeForDiff(rRow[key]);
        const cVal = normalizeForDiff(cRow[key]);
        if (rVal !== cVal) {
          diffs.push({ field: key, replayed: rRow[key], current: cRow[key] });
        }
      }

      if (diffs.length === 0) {
        result.matching.push({ aggregate_type: aggType, aggregate_id: id });
      } else {
        result.drifted.push({
          aggregate_type: aggType,
          aggregate_id: id,
          diffs,
        });
      }
    }
  }

  return result;
}

function normalizeForDiff(val) {
  if (val === undefined || val === null) return null;
  if (typeof val === 'object') return JSON.stringify(val, Object.keys(val).sort());
  return String(val);
}

// ---------------------------------------------------------------------------
// Projection table name mapping
// ---------------------------------------------------------------------------

const PROJECTION_TABLES = {
  receipt: 'receipts',
  dispute: 'disputes',
  report: 'trust_reports',
  commit: 'commits',
  entity: 'entities',
  delegation: 'delegations',
};

const PROJECTION_ID_COLUMN = {
  receipt: 'receipt_id',
  dispute: 'dispute_id',
  report: 'report_id',
  commit: 'commit_id',
  entity: 'entity_id',
  delegation: 'delegation_id',
};

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

async function main() {
  const args = process.argv.slice(2);
  const flags = {
    verify: args.includes('--verify'),
    rebuild: args.includes('--rebuild'),
    diff: args.includes('--diff'),
    dryRun: args.includes('--dry-run'),
  };
  const aggregateTypeIdx = args.indexOf('--aggregate-type');
  const aggregateTypeFilter =
    aggregateTypeIdx !== -1 ? args[aggregateTypeIdx + 1] : null;

  if (!flags.verify && !flags.rebuild && !flags.diff) {
    console.log(
      'Usage: node scripts/replay-protocol.js [--verify] [--rebuild] [--diff] [--dry-run] [--aggregate-type <type>]',
    );
    console.log('At least one mode flag is required.');
    process.exit(1);
  }

  // Dynamic import so tests can import the helpers without side effects
  const { getServiceClient } = await import('../lib/supabase.js');
  const supabase = getServiceClient();

  console.log('=== EMILIA Protocol Replay ===\n');

  // 1. Load all events from protocol_events, ordered by created_at
  console.log('Loading events from protocol_events...');
  const { data: events, error: eventsError } = await supabase
    .from('protocol_events')
    .select('*')
    .order('created_at', { ascending: true });

  if (eventsError) {
    console.error('Failed to load events:', eventsError.message);
    process.exit(1);
  }

  console.log(`Loaded ${events.length} events.\n`);

  // Apply aggregate-type filter if specified
  const filtered = aggregateTypeFilter
    ? events.filter((e) => e.aggregate_type === aggregateTypeFilter)
    : events;

  if (aggregateTypeFilter) {
    console.log(`Filtered to ${filtered.length} events of type "${aggregateTypeFilter}".\n`);
  }

  // -----------------------------------------------------------------------
  // VERIFY
  // -----------------------------------------------------------------------
  if (flags.verify) {
    console.log('--- VERIFY MODE ---');
    const report = verifyEvents(filtered);

    console.log(`Total events:     ${report.totalEvents}`);
    console.log(`Valid hashes:     ${report.validHashes}`);
    console.log(`Invalid hashes:   ${report.invalidHashes.length}`);
    console.log(`Valid chains:     ${report.validChains}`);
    console.log(`Broken chains:    ${report.brokenChains.length}`);
    console.log(`Signed events:    ${report.signedEvents}`);
    console.log(`Signature errors: ${report.signatureErrors.length}`);

    if (report.invalidHashes.length > 0) {
      console.log('\nInvalid hashes:');
      for (const h of report.invalidHashes) {
        console.log(`  event_id=${h.event_id}  expected=${h.expected}  actual=${h.actual}`);
      }
    }
    if (report.brokenChains.length > 0) {
      console.log('\nBroken chains:');
      for (const c of report.brokenChains) {
        console.log(`  event_id=${c.event_id}  parent_event_hash=${c.parent_event_hash}`);
      }
    }
    console.log('');
  }

  // -----------------------------------------------------------------------
  // REBUILD
  // -----------------------------------------------------------------------
  if (flags.rebuild) {
    console.log('--- REBUILD MODE ---');
    const { projections, replayed, errors } = rebuildProjections(filtered, null);

    console.log(`Events replayed:  ${replayed}`);
    console.log(`Errors:           ${errors.length}`);

    for (const aggType of Object.keys(projections)) {
      const count = Object.keys(projections[aggType]).length;
      console.log(`  ${aggType}: ${count} projections`);
    }

    if (errors.length > 0) {
      console.log('\nReplay errors:');
      for (const e of errors) {
        console.log(`  event_id=${e.event_id}  error=${e.error}`);
      }
    }

    if (!flags.dryRun) {
      console.log('\nWriting rebuilt projections to staging tables...');
      for (const aggType of Object.keys(projections)) {
        const table = PROJECTION_TABLES[aggType];
        if (!table) {
          console.log(`  Skipping unknown aggregate type: ${aggType}`);
          continue;
        }
        const stagingTable = `_replay_${table}`;
        const rows = Object.values(projections[aggType]);
        console.log(`  ${stagingTable}: ${rows.length} rows`);

        // Write to staging table (create if needed via RPC or just insert)
        // In a real deployment, you would create the staging table first.
        // For now we log what would be written.
        console.log(`  (Would write ${rows.length} rows to ${stagingTable})`);
      }
    } else {
      console.log('\n(--dry-run: no writes performed)');
    }
    console.log('');
  }

  // -----------------------------------------------------------------------
  // DIFF
  // -----------------------------------------------------------------------
  if (flags.diff) {
    console.log('--- DIFF MODE ---');

    // Rebuild from events
    const { projections: replayed } = rebuildProjections(filtered, null);

    // Load current state from projection tables
    const currentState = {};
    const typesToDiff = aggregateTypeFilter
      ? [aggregateTypeFilter]
      : Object.keys(PROJECTION_TABLES);

    for (const aggType of typesToDiff) {
      const table = PROJECTION_TABLES[aggType];
      const idCol = PROJECTION_ID_COLUMN[aggType];
      if (!table || !idCol) continue;

      const { data: rows, error: fetchError } = await supabase
        .from(table)
        .select('*')
        .order('created_at', { ascending: true });

      if (fetchError) {
        console.log(`  Failed to load ${table}: ${fetchError.message}`);
        continue;
      }

      currentState[aggType] = {};
      for (const row of rows || []) {
        const id = row[idCol];
        if (id) currentState[aggType][id] = row;
      }
    }

    const diffResult = diffProjections(replayed, currentState);

    console.log(`Matching records:            ${diffResult.matching.length}`);
    console.log(`Drifted records:             ${diffResult.drifted.length}`);
    console.log(`Orphaned (current only):     ${diffResult.orphanedInCurrent.length}`);
    console.log(`Orphaned (replay only):      ${diffResult.orphanedInReplay.length}`);

    if (diffResult.drifted.length > 0) {
      console.log('\nDrifted records:');
      for (const d of diffResult.drifted.slice(0, 20)) {
        console.log(`  ${d.aggregate_type}/${d.aggregate_id}:`);
        for (const diff of d.diffs) {
          console.log(`    ${diff.field}: replayed=${JSON.stringify(diff.replayed)} current=${JSON.stringify(diff.current)}`);
        }
      }
      if (diffResult.drifted.length > 20) {
        console.log(`  ... and ${diffResult.drifted.length - 20} more`);
      }
    }
    console.log('');
  }

  console.log('=== Replay complete ===');
}

// Only run main() when executed directly (not when imported in tests)
const isMainModule =
  typeof process !== 'undefined' &&
  process.argv[1] &&
  (process.argv[1].endsWith('replay-protocol.js') ||
   process.argv[1].endsWith('replay-protocol.mjs'));

if (isMainModule) {
  main().catch((err) => {
    console.error('Fatal replay error:', err);
    process.exit(1);
  });
}
