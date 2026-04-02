/**
 * EMILIA Protocol — Graceful Shutdown
 *
 * Registers SIGTERM / SIGINT handlers that:
 *   1. Stop accepting new protocol writes
 *   2. Wait for in-flight writes to drain (max 10 seconds)
 *   3. Close the Supabase connection pool
 *   4. Exit cleanly
 *
 * Called from instrumentation.js (Next.js 14+ instrumentation hook).
 * Also works in Docker standalone mode (node server.js) and in test runners.
 *
 * In-flight tracking: protocolWrite() registers each call on entry and
 * deregisters on completion. Shutdown waits until the counter reaches zero.
 *
 * @license Apache-2.0
 */

const DRAIN_TIMEOUT_MS = 10_000;

let inFlightCount = 0;
let shutdownInitiated = false;
const drainWaiters = new Set();

// ---------------------------------------------------------------------------
// In-flight write tracking — called by protocolWrite()
// ---------------------------------------------------------------------------

export function trackWriteStart() {
  inFlightCount++;
}

export function trackWriteEnd() {
  inFlightCount = Math.max(0, inFlightCount - 1);
  if (inFlightCount === 0) {
    for (const resolve of drainWaiters) resolve();
    drainWaiters.clear();
  }
}

export function isShutdownInitiated() {
  return shutdownInitiated;
}

// ---------------------------------------------------------------------------
// Drain — wait until all in-flight writes complete or timeout
// ---------------------------------------------------------------------------

function waitForDrain(timeoutMs) {
  if (inFlightCount === 0) return Promise.resolve();
  return new Promise((resolve) => {
    drainWaiters.add(resolve);
    setTimeout(() => {
      drainWaiters.delete(resolve);
      resolve(); // resolve anyway after timeout
    }, timeoutMs);
  });
}

// ---------------------------------------------------------------------------
// Shutdown sequence
// ---------------------------------------------------------------------------

async function shutdown(signal) {
  if (shutdownInitiated) return;
  shutdownInitiated = true;

  const log = (msg) => process.stderr.write(`[shutdown] ${msg}\n`);
  log(`${signal} received — initiating graceful shutdown`);

  if (inFlightCount > 0) {
    log(`draining ${inFlightCount} in-flight write(s) (max ${DRAIN_TIMEOUT_MS}ms)`);
    await waitForDrain(DRAIN_TIMEOUT_MS);
    if (inFlightCount > 0) {
      log(`drain timeout — ${inFlightCount} write(s) still in flight, exiting anyway`);
    } else {
      log('all writes drained');
    }
  }

  // Close Supabase connection pool if accessible
  try {
    const { closePool } = await import('@/lib/supabase');
    if (typeof closePool === 'function') {
      await closePool();
      log('Supabase connection pool closed');
    }
  } catch {
    // Pool close is best-effort
  }

  log('shutdown complete');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Signal registration — safe to call multiple times (idempotent via flag)
// ---------------------------------------------------------------------------

let signalsRegistered = false;

export function registerShutdownHandlers() {
  if (signalsRegistered) return;
  signalsRegistered = true;

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
}
