#!/usr/bin/env node
/**
 * Post-Load-Test DB Reconciliation Script
 *
 * Queries the Supabase database after a k6 load test run and proves correctness
 * by running 11 invariant checks across handshake, signoff, and protocol_events tables.
 *
 * Usage:
 *   node scripts/reconcile-load-test.js
 *   node scripts/reconcile-load-test.js --since 30m
 *   node scripts/reconcile-load-test.js --since 2h
 *
 * Requires NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in .env.local
 * or as environment variables.
 *
 * Exit codes:
 *   0 — all checks passed
 *   1 — one or more checks failed
 *
 * @license Apache-2.0
 */

import { createClient } from '@supabase/supabase-js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// ---------------------------------------------------------------------------
// ENV loading — parse .env.local as fallback when env vars are not set
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

function loadEnvFile() {
  const envPath = path.join(ROOT, '.env.local');
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, 'utf-8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx);
    let value = trimmed.slice(eqIdx + 1);
    // Strip surrounding quotes
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!process.env[key]) {
      process.env[key] = value;
    }
  }
}

loadEnvFile();

// ---------------------------------------------------------------------------
// Supabase client
// ---------------------------------------------------------------------------

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('ERROR: Missing NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
  console.error('Set them in .env.local or as environment variables.');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ---------------------------------------------------------------------------
// CLI args — --since <duration>  (default: 1h)
// ---------------------------------------------------------------------------

function parseSinceArg() {
  const args = process.argv.slice(2);
  let sinceRaw = '1h';
  const idx = args.indexOf('--since');
  if (idx !== -1 && args[idx + 1]) {
    sinceRaw = args[idx + 1];
  }

  const match = sinceRaw.match(/^(\d+)(m|h|d)$/);
  if (!match) {
    console.error(`Invalid --since value: "${sinceRaw}". Use e.g. 30m, 1h, 2d`);
    process.exit(1);
  }
  const num = parseInt(match[1], 10);
  const unit = match[2];
  const ms = num * (unit === 'm' ? 60_000 : unit === 'h' ? 3_600_000 : 86_400_000);
  return new Date(Date.now() - ms).toISOString();
}

const SINCE = parseSinceArg();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Count rows in a table, optionally filtering by a column/value and a time range.
 */
async function countRows(table, { column, value, timeColumn = 'created_at', since = SINCE } = {}) {
  let query = supabase
    .from(table)
    .select('*', { count: 'exact', head: true })
    .gte(timeColumn, since);
  if (column && value !== undefined) {
    query = query.eq(column, value);
  }
  const { count, error } = await query;
  if (error) throw new Error(`countRows(${table}): ${error.message}`);
  return count ?? 0;
}

/**
 * Run a raw SQL query via Supabase RPC (uses the sql extension).
 * Falls back to counting via REST if RPC is unavailable.
 */
async function rawCount(sql) {
  // Use supabase.rpc to run raw SQL is not available by default.
  // Instead we use the REST API with select and count.
  // This function exists as a template — individual checks use countRows or
  // custom queries below.
  throw new Error('rawCount is not used — see individual check implementations');
}

// ---------------------------------------------------------------------------
// Check definitions
// ---------------------------------------------------------------------------

const results = [];

function record(name, pass, detail) {
  results.push({ name, status: pass ? 'PASS' : 'FAIL', detail });
}

async function check1_handshakeVsCreatedEvents() {
  const [handshakes, events] = await Promise.all([
    countRows('handshakes'),
    countRows('handshake_events', { column: 'event_type', value: 'handshake_created' }),
  ]);
  const pass = handshakes === events;
  record(
    '1. Handshakes vs handshake_created events',
    pass,
    `handshakes=${handshakes}, handshake_created events=${events}`,
  );
}

async function check2_bindingsVsHandshakes() {
  const [bindings, handshakes] = await Promise.all([
    countRows('handshake_bindings', { timeColumn: 'bound_at' }),
    countRows('handshakes'),
  ]);
  const pass = bindings === handshakes;
  record(
    '2. Handshake bindings vs handshakes (1:1)',
    pass,
    `bindings=${bindings}, handshakes=${handshakes}`,
  );
}

async function check3_partiesVsHandshakes() {
  // For mutual mode, expect 2x parties per handshake.
  // handshake_parties lacks created_at, so we filter via recent handshake IDs.
  const [mutualCount, totalHandshakes] = await Promise.all([
    countRows('handshakes', { column: 'mode', value: 'mutual' }),
    countRows('handshakes'),
  ]);

  const expectedMutualParties = mutualCount * 2;
  const nonMutual = totalHandshakes - mutualCount;
  const expectedMin = expectedMutualParties + nonMutual; // at least 1 party per non-mutual

  // Get recent handshake IDs, then count their parties.
  const { data: recentHandshakeIds, error: hsErr } = await supabase
    .from('handshakes')
    .select('handshake_id')
    .gte('created_at', SINCE);
  if (hsErr) throw new Error(`check3: ${hsErr.message}`);
  const ids = (recentHandshakeIds || []).map(r => r.handshake_id);

  let partyCount = 0;
  if (ids.length > 0) {
    // Batch in chunks of 500 to stay within query limits
    for (let i = 0; i < ids.length; i += 500) {
      const chunk = ids.slice(i, i + 500);
      const { count, error } = await supabase
        .from('handshake_parties')
        .select('*', { count: 'exact', head: true })
        .in('handshake_id', chunk);
      if (error) throw new Error(`check3 parties: ${error.message}`);
      partyCount += count ?? 0;
    }
  }

  const pass = partyCount >= expectedMin && (mutualCount === 0 || partyCount === expectedMutualParties + nonMutual);
  record(
    '3. Handshake parties (2x for mutual)',
    pass,
    `parties=${partyCount}, mutual_hs=${mutualCount}, non_mutual=${nonMutual}, expected_min=${expectedMin}`,
  );
}

async function check4_verifiedVsAcceptedResults() {
  const [verified, accepted] = await Promise.all([
    countRows('handshakes', { column: 'status', value: 'verified' }),
    countRows('handshake_results', { timeColumn: 'evaluated_at', column: 'outcome', value: 'accepted' }),
  ]);
  const pass = verified === accepted;
  record(
    '4. Verified handshakes vs accepted results',
    pass,
    `verified_hs=${verified}, accepted_results=${accepted}`,
  );
}

async function check5_challengesVsChallengeEvents() {
  const [challenges, events] = await Promise.all([
    countRows('signoff_challenges', { timeColumn: 'issued_at' }),
    countRows('signoff_events', { column: 'event_type', value: 'challenge_issued' }),
  ]);
  const pass = challenges === events;
  record(
    '5. Signoff challenges vs challenge_issued events',
    pass,
    `challenges=${challenges}, challenge_issued_events=${events}`,
  );
}

async function check6_attestationsVsApprovedEvents() {
  const [attestations, events] = await Promise.all([
    countRows('signoff_attestations', { timeColumn: 'approved_at' }),
    countRows('signoff_events', { column: 'event_type', value: 'signoff_approved' }),
  ]);
  const pass = attestations === events;
  record(
    '6. Signoff attestations vs signoff_approved events',
    pass,
    `attestations=${attestations}, approved_events=${events}`,
  );
}

async function check7_noDuplicateConsumptions() {
  // signoff_consumptions has UNIQUE on signoff_id, so duplicates should be
  // impossible at the DB level. We verify by grouping.
  const { data, error } = await supabase.rpc('check_signoff_consumption_dupes', {
    p_since: SINCE,
  }).maybeSingle();

  // If the RPC doesn't exist, fall back to counting total vs distinct
  if (error) {
    const { count: total, error: e1 } = await supabase
      .from('signoff_consumptions')
      .select('*', { count: 'exact', head: true })
      .gte('consumed_at', SINCE);
    if (e1) throw new Error(`check7: ${e1.message}`);

    // With UNIQUE constraint, total === distinct by definition.
    // But let's fetch signoff_ids and check for duplicates in-app.
    const { data: rows, error: e2 } = await supabase
      .from('signoff_consumptions')
      .select('signoff_id')
      .gte('consumed_at', SINCE);
    if (e2) throw new Error(`check7 fetch: ${e2.message}`);

    const seen = new Set();
    const dupes = [];
    for (const r of rows || []) {
      if (seen.has(r.signoff_id)) dupes.push(r.signoff_id);
      seen.add(r.signoff_id);
    }

    const pass = dupes.length === 0;
    record(
      '7. No duplicate signoff consumptions',
      pass,
      pass
        ? `total_consumptions=${total}, duplicates=0`
        : `VIOLATION: ${dupes.length} duplicate signoff_ids: ${dupes.slice(0, 5).join(', ')}`,
    );
    return;
  }

  // RPC path
  const dupeCount = data?.dupe_count ?? 0;
  const pass = dupeCount === 0;
  record(
    '7. No duplicate signoff consumptions',
    pass,
    pass ? `duplicates=0` : `VIOLATION: ${dupeCount} duplicate signoff_ids`,
  );
}

async function check8_orphanedBindings() {
  // Bindings that reference a handshake_id which doesn't exist in handshakes.
  // handshake_bindings.handshake_id references handshakes(handshake_id) via FK,
  // so orphans should be impossible. But let's verify.
  const { data: orphans, error } = await supabase
    .from('handshake_bindings')
    .select('id, handshake_id')
    .gte('bound_at', SINCE);
  if (error) throw new Error(`check8: ${error.message}`);

  // For each binding, check if the handshake exists
  let orphanCount = 0;
  const bindingHsIds = (orphans || []).map(b => b.handshake_id);
  if (bindingHsIds.length > 0) {
    const uniqueIds = [...new Set(bindingHsIds)];
    for (let i = 0; i < uniqueIds.length; i += 500) {
      const chunk = uniqueIds.slice(i, i + 500);
      const { data: found, error: fErr } = await supabase
        .from('handshakes')
        .select('handshake_id')
        .in('handshake_id', chunk);
      if (fErr) throw new Error(`check8 lookup: ${fErr.message}`);
      const foundSet = new Set((found || []).map(r => r.handshake_id));
      for (const id of chunk) {
        if (!foundSet.has(id)) orphanCount++;
      }
    }
  }

  const pass = orphanCount === 0;
  record(
    '8. No orphaned bindings',
    pass,
    pass
      ? `bindings_checked=${bindingHsIds.length}, orphans=0`
      : `VIOLATION: ${orphanCount} orphaned bindings found`,
  );
}

async function check9_partialTerminalStates() {
  // Handshake is verified but has no result record
  const { data: verifiedHs, error: vErr } = await supabase
    .from('handshakes')
    .select('handshake_id')
    .eq('status', 'verified')
    .gte('created_at', SINCE);
  if (vErr) throw new Error(`check9: ${vErr.message}`);

  const verifiedIds = (verifiedHs || []).map(r => r.handshake_id);
  let missingResults = 0;

  if (verifiedIds.length > 0) {
    for (let i = 0; i < verifiedIds.length; i += 500) {
      const chunk = verifiedIds.slice(i, i + 500);
      const { data: resultRows, error: rErr } = await supabase
        .from('handshake_results')
        .select('handshake_id')
        .in('handshake_id', chunk);
      if (rErr) throw new Error(`check9 results: ${rErr.message}`);
      const resultSet = new Set((resultRows || []).map(r => r.handshake_id));
      for (const id of chunk) {
        if (!resultSet.has(id)) missingResults++;
      }
    }
  }

  const pass = missingResults === 0;
  record(
    '9. No partial terminal states (verified without result)',
    pass,
    pass
      ? `verified_handshakes=${verifiedIds.length}, all have results`
      : `VIOLATION: ${missingResults} verified handshakes have no result record`,
  );
}

async function check10_missingRequiredEvents() {
  // Handshakes in terminal states (verified, rejected, expired, revoked)
  // must have a matching event.
  const terminalStatuses = ['verified', 'rejected', 'expired', 'revoked'];
  const eventTypeMap = {
    verified: 'handshake_verified',
    rejected: 'handshake_rejected',
    expired: 'handshake_expired',
    revoked: 'handshake_revoked',
  };

  let totalMissing = 0;
  const details = [];

  for (const status of terminalStatuses) {
    const { data: hsRows, error: hsErr } = await supabase
      .from('handshakes')
      .select('handshake_id')
      .eq('status', status)
      .gte('created_at', SINCE);
    if (hsErr) throw new Error(`check10 (${status}): ${hsErr.message}`);

    const hsIds = (hsRows || []).map(r => r.handshake_id);
    if (hsIds.length === 0) continue;

    let missingCount = 0;
    for (let i = 0; i < hsIds.length; i += 500) {
      const chunk = hsIds.slice(i, i + 500);
      const { data: eventRows, error: evErr } = await supabase
        .from('handshake_events')
        .select('handshake_id')
        .eq('event_type', eventTypeMap[status])
        .in('handshake_id', chunk);
      if (evErr) throw new Error(`check10 events (${status}): ${evErr.message}`);
      const eventSet = new Set((eventRows || []).map(r => r.handshake_id));
      for (const id of chunk) {
        if (!eventSet.has(id)) missingCount++;
      }
    }
    if (missingCount > 0) {
      totalMissing += missingCount;
      details.push(`${status}: ${missingCount} missing`);
    } else {
      details.push(`${status}: ${hsIds.length} OK`);
    }
  }

  const pass = totalMissing === 0;
  record(
    '10. No missing required events for terminal states',
    pass,
    details.join(', '),
  );
}

async function check11_protocolEventsCount() {
  const count = await countRows('protocol_events');
  // This check is informational — we report the count.
  // A zero count during a load test window would be suspicious.
  const pass = count > 0;
  record(
    '11. Protocol events count (sanity)',
    pass,
    `protocol_events=${count} (since ${SINCE})`,
  );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('=== EP Post-Load-Test DB Reconciliation ===');
  console.log(`Since: ${SINCE}`);
  console.log(`Supabase: ${SUPABASE_URL}`);
  console.log('');

  const checks = [
    check1_handshakeVsCreatedEvents,
    check2_bindingsVsHandshakes,
    check3_partiesVsHandshakes,
    check4_verifiedVsAcceptedResults,
    check5_challengesVsChallengeEvents,
    check6_attestationsVsApprovedEvents,
    check7_noDuplicateConsumptions,
    check8_orphanedBindings,
    check9_partialTerminalStates,
    check10_missingRequiredEvents,
    check11_protocolEventsCount,
  ];

  for (const check of checks) {
    try {
      await check();
    } catch (err) {
      const name = check.name.replace(/^check\d+_/, '').replace(/_/g, ' ');
      record(name, false, `ERROR: ${err.message}`);
    }
  }

  // ---------------------------------------------------------------------------
  // Summary table
  // ---------------------------------------------------------------------------

  console.log('');
  console.log('┌──────┬──────────────────────────────────────────────────────────┬────────────────────────────────────────────────────────────────┐');
  console.log('│ STAT │ CHECK                                                    │ DETAIL                                                         │');
  console.log('├──────┼──────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────────────┤');

  for (const r of results) {
    const stat = r.status === 'PASS' ? ' PASS' : ' FAIL';
    const check = r.name.padEnd(56).slice(0, 56);
    const detail = r.detail.padEnd(62).slice(0, 62);
    console.log(`│ ${stat} │ ${check} │ ${detail} │`);
  }

  console.log('└──────┴──────────────────────────────────────────────────────────┴────────────────────────────────────────────────────────────────┘');

  const passed = results.filter(r => r.status === 'PASS').length;
  const failed = results.filter(r => r.status === 'FAIL').length;
  console.log('');
  console.log(`Results: ${passed} passed, ${failed} failed out of ${results.length} checks`);

  if (failed > 0) {
    console.log('');
    console.log('FAILED CHECKS:');
    for (const r of results.filter(r => r.status === 'FAIL')) {
      console.log(`  ✗ ${r.name}`);
      console.log(`    ${r.detail}`);
    }
  }

  console.log('');
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
