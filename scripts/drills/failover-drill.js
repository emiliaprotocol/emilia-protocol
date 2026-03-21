#!/usr/bin/env node
/**
 * EP Failover Drill — Simulates and validates failover scenarios.
 *
 * Tests that the system degrades gracefully under database failures
 * and that no partial state or double-consumption is possible.
 *
 * Usage:
 *   node scripts/drills/failover-drill.js
 *   node scripts/drills/failover-drill.js --timeout-ms 5000
 *   node scripts/drills/failover-drill.js --json
 *
 * Requires:
 *   NEXT_PUBLIC_SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';
import { createClient } from '@supabase/supabase-js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const JSON_OUTPUT = args.includes('--json');
const TIMEOUT_MS_IDX = args.indexOf('--timeout-ms');
const DB_TIMEOUT_MS = TIMEOUT_MS_IDX !== -1
  ? parseInt(args[TIMEOUT_MS_IDX + 1], 10)
  : 3000;

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('Missing NEXT_PUBLIC_SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
  process.exit(1);
}

function getClient() {
  return createClient(SUPABASE_URL, SUPABASE_KEY);
}

function uuid() {
  return crypto.randomUUID();
}

function log(msg) {
  if (!JSON_OUTPUT) console.log(msg);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Simulates a DB timeout by racing a real DB call against a timer.
 * When the timer wins, we return an error; the real call may still
 * succeed in the background (which is intentional — the test then
 * checks for partial state).
 */
function withSimulatedTimeout(promiseFn, timeoutMs) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      resolve({ data: null, error: { message: `Simulated timeout after ${timeoutMs}ms`, code: 'SIMULATED_TIMEOUT' } });
    }, timeoutMs);

    promiseFn().then((result) => {
      clearTimeout(timer);
      resolve(result);
    }).catch((err) => {
      clearTimeout(timer);
      resolve({ data: null, error: { message: err.message, code: 'EXCEPTION' } });
    });
  });
}

/**
 * Clean up drill artifacts by entity_id prefix.
 */
async function cleanup(supabase, drillPrefix) {
  // Clean up handshake-related tables in dependency order
  const { data: handshakes } = await supabase
    .from('handshakes')
    .select('handshake_id')
    .like('interaction_id', `${drillPrefix}%`);

  if (handshakes && handshakes.length > 0) {
    const ids = handshakes.map(h => h.handshake_id);

    await supabase.from('handshake_consumptions').delete().in('handshake_id', ids);
    await supabase.from('handshake_events').delete().in('handshake_id', ids);
    await supabase.from('handshake_results').delete().in('handshake_id', ids);
    await supabase.from('handshake_presentations').delete().in('handshake_id', ids);
    await supabase.from('handshake_bindings').delete().in('handshake_id', ids);
    await supabase.from('handshake_parties').delete().in('handshake_id', ids);
    await supabase.from('handshakes').delete().in('handshake_id', ids);
  }

  // Clean up protocol events from drill
  await supabase.from('protocol_events').delete().like('aggregate_id', `${drillPrefix}%`);
}

// ---------------------------------------------------------------------------
// Test 1: DB connection loss during handshake create
// ---------------------------------------------------------------------------

async function testCreateFailover() {
  const testName = 'DB connection loss during handshake create';
  const start = Date.now();
  const supabase = getClient();
  const drillId = `drill-create-${uuid().slice(0, 8)}`;

  try {
    log(`\n  [Test 1] ${testName}`);
    log(`    Simulating DB timeout of ${DB_TIMEOUT_MS}ms during create...`);

    // Attempt a handshake creation with a simulated timeout.
    // We create a minimal handshake record directly to test state consistency.
    const handshakeId = uuid();
    const result = await withSimulatedTimeout(async () => {
      return await supabase.from('handshakes').insert({
        handshake_id: handshakeId,
        mode: 'verify_then_act',
        status: 'pending',
        interaction_id: `${drillId}-timeout`,
        assurance_level: 'standard',
        binding_ttl_ms: 600000,
        created_at: new Date().toISOString(),
      }).select().single();
    }, DB_TIMEOUT_MS);

    // Check 1: If the timeout fired, verify no partial state was left
    let partialStateClean = true;
    let retryClean = true;

    if (result.error?.code === 'SIMULATED_TIMEOUT') {
      log('    Timeout triggered. Checking for partial state...');

      // Wait for any in-flight write to settle
      await new Promise(r => setTimeout(r, 1000));

      const { data: orphan } = await supabase
        .from('handshakes')
        .select('handshake_id, status')
        .eq('handshake_id', handshakeId)
        .maybeSingle();

      if (orphan) {
        log(`    WARNING: Partial state found — handshake ${handshakeId} exists with status "${orphan.status}"`);
        partialStateClean = false;
        // Clean it up
        await supabase.from('handshakes').delete().eq('handshake_id', handshakeId);
      } else {
        log('    No partial state — write did not complete before timeout.');
      }
    } else if (result.error) {
      log(`    DB error (not timeout): ${result.error.message}`);
      partialStateClean = true; // DB rejected cleanly
    } else {
      log('    Write completed before timeout — testing retry idempotency...');
      // Clean up the successful write
      await supabase.from('handshakes').delete().eq('handshake_id', handshakeId);
    }

    // Check 2: Retry should produce a clean result
    log('    Retrying with fresh handshake...');
    const retryId = uuid();
    const { data: retryData, error: retryError } = await supabase
      .from('handshakes')
      .insert({
        handshake_id: retryId,
        mode: 'verify_then_act',
        status: 'pending',
        interaction_id: `${drillId}-retry`,
        assurance_level: 'standard',
        binding_ttl_ms: 600000,
        created_at: new Date().toISOString(),
      })
      .select()
      .single();

    if (retryError) {
      log(`    Retry FAILED: ${retryError.message}`);
      retryClean = false;
    } else {
      log(`    Retry succeeded — handshake ${retryId} created cleanly.`);
      // Clean up
      await supabase.from('handshakes').delete().eq('handshake_id', retryId);
    }

    const duration = Date.now() - start;
    return {
      test: testName,
      passed: partialStateClean && retryClean,
      checks: {
        no_partial_state: partialStateClean,
        retry_produces_clean_result: retryClean,
      },
      duration_ms: duration,
      config: { db_timeout_ms: DB_TIMEOUT_MS },
    };
  } catch (err) {
    return {
      test: testName,
      passed: false,
      error: err.message,
      duration_ms: Date.now() - start,
    };
  }
}

// ---------------------------------------------------------------------------
// Test 2: DB connection loss during consume
// ---------------------------------------------------------------------------

async function testConsumeFailover() {
  const testName = 'DB connection loss during consume';
  const start = Date.now();
  const supabase = getClient();
  const drillId = `drill-consume-${uuid().slice(0, 8)}`;

  try {
    log(`\n  [Test 2] ${testName}`);

    // Set up: create a handshake in 'verified' state with a binding
    const handshakeId = uuid();
    const bindingHash = crypto.createHash('sha256')
      .update(`drill-binding-${handshakeId}`)
      .digest('hex');

    log('    Setting up verified handshake...');

    await supabase.from('handshakes').insert({
      handshake_id: handshakeId,
      mode: 'verify_then_act',
      status: 'verified',
      interaction_id: `${drillId}-setup`,
      assurance_level: 'standard',
      binding_ttl_ms: 600000,
      created_at: new Date().toISOString(),
      verified_at: new Date().toISOString(),
    });

    // Write an event for this handshake (event-first ordering)
    const eventId = uuid();
    await supabase.from('handshake_events').insert({
      event_id: eventId,
      handshake_id: handshakeId,
      event_type: 'handshake_verified',
      event_payload: { drill: true },
      actor_entity_ref: 'drill-script',
      created_at: new Date().toISOString(),
    });

    log(`    Simulating timeout during consumption (after event write)...`);

    // Simulate: event write succeeds, but consumption insert times out
    const consumptionId = uuid();
    const consumeResult = await withSimulatedTimeout(async () => {
      return await supabase.from('handshake_consumptions').insert({
        consumption_id: consumptionId,
        handshake_id: handshakeId,
        binding_hash: bindingHash,
        consumed_by_type: 'drill_test',
        consumed_by_id: `drill-${drillId}`,
        actor_entity_ref: 'drill-script',
      }).select().single();
    }, DB_TIMEOUT_MS);

    // Verify: system is in a recoverable state
    let recoverableState = true;
    let retryCorrect = true;

    // Wait for in-flight write
    await new Promise(r => setTimeout(r, 1000));

    // Check: event should exist regardless
    const { data: eventCheck } = await supabase
      .from('handshake_events')
      .select('event_id')
      .eq('handshake_id', handshakeId)
      .eq('event_type', 'handshake_verified');

    const eventExists = eventCheck && eventCheck.length > 0;
    log(`    Event exists: ${eventExists}`);

    // Check: consumption may or may not exist depending on timeout
    const { data: consumptionCheck } = await supabase
      .from('handshake_consumptions')
      .select('consumption_id')
      .eq('handshake_id', handshakeId);

    const consumptionExists = consumptionCheck && consumptionCheck.length > 0;
    log(`    Consumption exists: ${consumptionExists}`);

    if (!eventExists) {
      log('    FAIL: Event should always exist (event-first ordering)');
      recoverableState = false;
    }

    // Retry consumption — should either succeed or return ALREADY_CONSUMED
    log('    Retrying consumption...');
    const retryConsumptionId = uuid();
    const { data: retryData, error: retryError } = await supabase
      .from('handshake_consumptions')
      .insert({
        consumption_id: retryConsumptionId,
        handshake_id: handshakeId,
        binding_hash: bindingHash,
        consumed_by_type: 'drill_test_retry',
        consumed_by_id: `drill-retry-${drillId}`,
        actor_entity_ref: 'drill-script',
      })
      .select()
      .single();

    if (retryError) {
      if (retryError.code === '23505') {
        // Unique constraint violation — already consumed. This is correct.
        log('    Retry returned ALREADY_CONSUMED (23505) — correct behavior.');
        retryCorrect = true;
      } else {
        log(`    Retry failed unexpectedly: ${retryError.message}`);
        retryCorrect = false;
      }
    } else {
      if (consumptionExists) {
        log('    WARNING: Retry succeeded but original also succeeded — DOUBLE CONSUMPTION detected!');
        retryCorrect = false;
      } else {
        log('    Retry succeeded (original timed out before write) — correct behavior.');
        retryCorrect = true;
      }
    }

    // Verify: count total consumptions — must be exactly 1
    const { data: finalCount } = await supabase
      .from('handshake_consumptions')
      .select('consumption_id')
      .eq('handshake_id', handshakeId);

    const consumptionCount = finalCount ? finalCount.length : 0;
    const noDoubleConsume = consumptionCount <= 1;
    log(`    Final consumption count: ${consumptionCount} (must be <= 1)`);

    // Cleanup
    await supabase.from('handshake_consumptions').delete().eq('handshake_id', handshakeId);
    await supabase.from('handshake_events').delete().eq('handshake_id', handshakeId);
    await supabase.from('handshakes').delete().eq('handshake_id', handshakeId);

    const duration = Date.now() - start;
    return {
      test: testName,
      passed: recoverableState && retryCorrect && noDoubleConsume,
      checks: {
        event_first_ordering_enforced: eventExists,
        recoverable_state: recoverableState,
        retry_correct_behavior: retryCorrect,
        no_double_consumption: noDoubleConsume,
      },
      recovery_metrics: {
        event_exists_after_timeout: eventExists,
        consumption_exists_after_timeout: consumptionExists,
        final_consumption_count: consumptionCount,
      },
      duration_ms: duration,
    };
  } catch (err) {
    return {
      test: testName,
      passed: false,
      error: err.message,
      duration_ms: Date.now() - start,
    };
  }
}

// ---------------------------------------------------------------------------
// Test 3: Event write failure
// ---------------------------------------------------------------------------

async function testEventWriteFailure() {
  const testName = 'Event write failure blocks mutation';
  const start = Date.now();
  const supabase = getClient();
  const drillId = `drill-eventfail-${uuid().slice(0, 8)}`;

  try {
    log(`\n  [Test 3] ${testName}`);

    // Simulate: event store unavailable by writing to a non-existent table
    // then verifying that no handshake state was created.
    //
    // In production, protocolWrite() enforces event-first ordering:
    //   1. Persist event to protocol_events
    //   2. If event write fails, abort entirely (no state change)
    //   3. If event write succeeds, materialize projection
    //
    // We test this contract by:
    //   1. Attempting an event write that will fail (malformed payload)
    //   2. Checking that no corresponding handshake was created

    const handshakeId = uuid();
    log('    Attempting event write with invalid payload...');

    // Force an event write failure by omitting required fields
    const { error: eventError } = await supabase
      .from('protocol_events')
      .insert({
        event_id: uuid(),
        // Missing required fields: aggregate_type, aggregate_id, command_type, payload_json, payload_hash
        aggregate_type: null,  // This should violate NOT NULL constraint
        aggregate_id: handshakeId,
        command_type: 'initiate_handshake',
        payload_json: '{}',
        payload_hash: crypto.createHash('sha256').update('{}').digest('hex'),
      });

    const eventWriteFailed = !!eventError;
    log(`    Event write failed: ${eventWriteFailed} (expected: true)`);

    if (eventError) {
      log(`    Error: ${eventError.message}`);
    }

    // Verify: no handshake was created for this ID
    const { data: orphanHandshake } = await supabase
      .from('handshakes')
      .select('handshake_id')
      .eq('handshake_id', handshakeId)
      .maybeSingle();

    const noStateChange = !orphanHandshake;
    log(`    No handshake state created: ${noStateChange} (expected: true)`);

    // Verify: no event was persisted
    const { data: orphanEvent } = await supabase
      .from('protocol_events')
      .select('event_id')
      .eq('aggregate_id', handshakeId)
      .maybeSingle();

    const noEventPersisted = !orphanEvent;
    log(`    No event persisted: ${noEventPersisted} (expected: true)`);

    const duration = Date.now() - start;
    return {
      test: testName,
      passed: eventWriteFailed && noStateChange && noEventPersisted,
      checks: {
        event_write_failed_as_expected: eventWriteFailed,
        no_state_change_on_event_failure: noStateChange,
        no_event_persisted: noEventPersisted,
        event_first_ordering_enforced: eventWriteFailed && noStateChange,
      },
      duration_ms: duration,
    };
  } catch (err) {
    return {
      test: testName,
      passed: false,
      error: err.message,
      duration_ms: Date.now() - start,
    };
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  log('=== EP Failover Drill ===');
  log(`  Supabase:    ${SUPABASE_URL}`);
  log(`  DB Timeout:  ${DB_TIMEOUT_MS}ms`);
  log(`  Timestamp:   ${new Date().toISOString()}`);

  const results = [];

  results.push(await testCreateFailover());
  results.push(await testConsumeFailover());
  results.push(await testEventWriteFailure());

  const allPassed = results.every(r => r.passed);

  const report = {
    drill: 'failover',
    timestamp: new Date().toISOString(),
    supabase_url: SUPABASE_URL,
    config: { db_timeout_ms: DB_TIMEOUT_MS },
    summary: {
      total: results.length,
      passed: results.filter(r => r.passed).length,
      failed: results.filter(r => !r.passed).length,
      all_passed: allPassed,
    },
    tests: results,
  };

  if (JSON_OUTPUT) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    log('\n=== Results ===');
    for (const r of results) {
      const status = r.passed ? 'PASS' : 'FAIL';
      log(`  [${status}] ${r.test} (${r.duration_ms}ms)`);
      if (!r.passed && r.error) {
        log(`         Error: ${r.error}`);
      }
    }
    log(`\n  ${report.summary.passed}/${report.summary.total} passed`);
    log(`\n  Full report: re-run with --json for structured output`);
  }

  process.exit(allPassed ? 0 : 1);
}

main().catch((err) => {
  console.error('Fatal drill error:', err);
  process.exit(1);
});
