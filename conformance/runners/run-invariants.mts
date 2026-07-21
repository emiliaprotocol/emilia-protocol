// SPDX-License-Identifier: Apache-2.0
//
// TLA+-invariant cross-language conformance runner — JavaScript lane.
//
// Unlike run-js.mjs (which verifies canonical *receipt vectors*), this runner
// drives the REAL production state machines through the concrete action
// sequences derived from the TLA+ safety invariants in
// formal/ep_capability.tla and formal/ep_handshake.tla:
//
//   * capability domain  -> createMemoryCapabilityStore() from
//                           packages/gate/capability-receipt.js. This is the
//                           same in-process store, with the same reserve/commit
//                           guards, that executeWithCapability() uses; the
//                           Postgres store mirrors it 1:1 (CAPABILITY_SQL).
//   * handshake domain   -> the pure invariant functions exported from
//                           lib/handshake/invariants.js (checkNoDuplicateResult,
//                           checkResultImmutability, checkNotExpired,
//                           checkBindingValid), the JS-layer twins of the
//                           handshake state-machine guards.
//
// Each case asserts (a) every action's observed outcome equals its declared
// `expect`, and (b) the declared structural predicate still holds on the real
// store state. A mismatch is a conformance FINDING — the same corpus is meant
// to be replayed by the Python and Go lanes so a cross-port divergence surfaces.
//
//   node conformance/runners/run-invariants.mjs [path/to/invariants.json]
//   node conformance/runners/run-invariants.mjs --json   # machine-readable
//
// Exit 0 iff every case holds; exit 1 on any divergence.

import { generateKeyPairSync, sign } from 'node:crypto';
import { register } from 'node:module';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { canonicalize } from '../../packages/gate/execution-binding.js';
import {
  CAPABILITY_SCOPE_PROFILE,
  capabilityActionDigest,
  mintCapabilityReceipt,
  createMemoryCapabilityStore,
} from '../../packages/gate/capability-receipt.js';

// lib/handshake/invariants.js re-exports from the "@/" path alias, so register
// the alias resolver before dynamically importing it (static imports hoist).
register('./alias-loader.mjs', import.meta.url);
const {
  checkNoDuplicateResult,
  checkResultImmutability,
  checkNotExpired,
  checkBindingValid,
} = await import('../../lib/handshake/invariants.js');

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_CORPUS = resolve(__dirname, '..', 'invariants.json');

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const corpusPath = args.find((a) => !a.startsWith('--')) || DEFAULT_CORPUS;

const corpus = JSON.parse(readFileSync(corpusPath, 'utf8'));
const NOW = Date.parse(corpus.baselineNowIso || '2026-07-18T22:00:00.000Z');

// ── Capability domain harness ────────────────────────────────────────────────
// Mints a fresh issuer-signed capability envelope of a given budget/expiry and
// registers it into a REAL memory store, then executes the action sequence.

function mintAndRegister(store, { budget, expiryMs }) {
  const keys = generateKeyPairSync('ed25519');
  const payload = {
    receipt_id: `base_${Math.random().toString(36).slice(2)}`,
    created_at: new Date(NOW - 1000).toISOString(),
    subject: 'operator@conformance.test',
    claim: { action_type: 'payment.release', outcome: 'allow', capability_only: true },
  };
  const base = {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: sign(null, Buffer.from(canonicalize(payload)), keys.privateKey).toString('base64url'),
    },
    public_key: keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
  const minted = mintCapabilityReceipt(base, {
    budget: { amount: budget, currency: 'USD' },
    expiry: NOW + expiryMs,
    issuerPrivateKey: keys.privateKey,
    scope: {
      profile: CAPABILITY_SCOPE_PROFILE,
      operation_id_field: 'operation_id',
      action_digests: [capabilityActionDigest({ operation_id: 'conformance-template' })],
    },
  });
  const registered = store.registerCapability(minted.capabilityReceipt);
  if (!registered) throw new Error('capability registration failed in harness setup');
  return {
    capabilityId: minted.capabilityReceipt.capability.id,
    fingerprint: store.getState(minted.capabilityReceipt.capability.id).capability_fingerprint,
  };
}

async function runCapabilityCase(kase) {
  const store = createMemoryCapabilityStore();
  const caps = new Map();       // logical name -> { capabilityId, fingerprint }
  const tokens = new Map();     // operation id -> reservation token
  const committedAmt = new Map(); // capabilityId -> sum of committed op amounts (oracle)
  const consumedSeen = new Map(); // capabilityId -> last observed consumed (monotonicity oracle)

  const observeMonotonic = (capabilityId) => {
    const s = store.getState(capabilityId);
    if (!s) return;
    const prev = consumedSeen.get(capabilityId) ?? 0;
    if (s.consumed_amount < prev) {
      throw new DivergenceError(`consumed decreased ${prev} -> ${s.consumed_amount} (ConsumptionMonotonic violated)`);
    }
    consumedSeen.set(capabilityId, s.consumed_amount);
  };

  for (let i = 0; i < kase.actions.length; i += 1) {
    const a = kase.actions[i];
    const at = NOW + (a.atMs || 0);
    if (a.do === 'register') {
      caps.set(a.capability, mintAndRegister(store, { budget: a.budget, expiryMs: a.expiryMs }));
      committedAmt.set(caps.get(a.capability).capabilityId, 0);
      observeMonotonic(caps.get(a.capability).capabilityId);
      continue;
    }
    if (a.do === 'reserve') {
      const cap = caps.get(a.capability);
      const res = await store.reserveSpend({
        capabilityId: cap.capabilityId,
        capabilityFingerprint: cap.fingerprint,
        operationId: a.operation,
        actionDigest: capabilityActionDigest({ operation_id: a.operation }),
        amount: a.amount,
        currency: a.currency || 'USD',
        now: at,
      });
      assertExpect(kase, i, res, a.expect);
      if (res.ok) tokens.set(a.operation, res.reservation_token);
      observeMonotonic(cap.capabilityId);
      continue;
    }
    if (a.do === 'commit') {
      // Resolve the capability the operation belongs to from the store.
      const op = store.getOperation(a.operation);
      const capabilityId = op ? op.capability_id : findCapId(caps, a.capability);
      const res = await store.commitSpend({
        capabilityId,
        operationId: a.operation,
        reservationToken: tokens.get(a.operation),
        now: at,
      });
      assertExpect(kase, i, res, a.expect);
      if (res.ok) committedAmt.set(capabilityId, (committedAmt.get(capabilityId) || 0) + op.amount);
      observeMonotonic(capabilityId);
      continue;
    }
    if (a.do === 'commitRaw') {
      // Adversarial commit with an explicit (possibly bogus) token / op id.
      const cap = caps.get(a.capability);
      const res = await store.commitSpend({
        capabilityId: cap.capabilityId,
        operationId: a.operation,
        reservationToken: a.token,
        now: at,
      });
      assertExpect(kase, i, res, a.expect);
      observeMonotonic(cap.capabilityId);
      continue;
    }
    throw new Error(`unknown capability action: ${a.do}`);
  }

  // Structural predicate on the real final store state.
  const s = kase.structural;
  if (s) {
    const cap = caps.get(s.capability);
    const state = store.getState(cap.capabilityId);
    if (s.predicate === 'reserve_within_budget') {
      if (state.consumed_amount + state.reserved_amount > state.budget_amount) {
        throw new DivergenceError(`consumed(${state.consumed_amount}) + reserved(${state.reserved_amount}) > budget(${state.budget_amount})`);
      }
    } else if (s.predicate === 'consumed_is_committed_sum') {
      const expected = committedAmt.get(cap.capabilityId) || 0;
      if (state.consumed_amount !== expected) {
        throw new DivergenceError(`consumed(${state.consumed_amount}) != sum of committed ops(${expected})`);
      }
    } else if (s.predicate === 'consumption_monotonic') {
      // Already enforced step-by-step via observeMonotonic; nothing else to do.
    } else {
      throw new Error(`unknown structural predicate: ${s.predicate}`);
    }
  }
}

function findCapId(caps, name) {
  if (name && caps.has(name)) return caps.get(name).capabilityId;
  // Single-capability cases: fall back to the only registered capability.
  const only = [...caps.values()];
  if (only.length === 1) return only[0].capabilityId;
  throw new Error('commit action could not resolve its capability');
}

// ── Handshake domain harness ─────────────────────────────────────────────────
// Drives the pure exported invariant functions directly.

function runHandshakeCase(kase) {
  for (let i = 0; i < kase.actions.length; i += 1) {
    const a = kase.actions[i];
    let res;
    switch (a.do) {
      case 'check_no_duplicate_result':
        res = checkNoDuplicateResult(a.existingResults, a.bindingHash);
        break;
      case 'check_result_immutability':
        res = checkResultImmutability(a.existingResult);
        break;
      case 'check_not_expired':
        res = checkNotExpired(a.handshake);
        break;
      case 'check_binding_valid':
        res = checkBindingValid(a.binding, a.verificationPayloadHash);
        break;
      default:
        throw new Error(`unknown handshake action: ${a.do}`);
    }
    // Invariant functions return { ok, code, message }.
    assertExpect(kase, i, res, a.expect);
  }
}

// ── Shared assertion + reporting ─────────────────────────────────────────────

class DivergenceError extends Error {}

function assertExpect(kase, idx, observed, expect) {
  if (!expect) return;
  if (typeof expect.ok === 'boolean' && Boolean(observed.ok) !== expect.ok) {
    throw new DivergenceError(`action[${idx}]: expected ok=${expect.ok}, got ok=${Boolean(observed.ok)} (reason=${observed.reason || observed.code || 'none'})`);
  }
  if (expect.reason && observed.reason !== expect.reason) {
    throw new DivergenceError(`action[${idx}]: expected reason=${expect.reason}, got reason=${observed.reason || 'none'}`);
  }
  if (expect.code && observed.code !== expect.code) {
    throw new DivergenceError(`action[${idx}]: expected code=${expect.code}, got code=${observed.code || 'none'}`);
  }
}

async function main() {
  const results: any[] = [];
  let failures = 0;
  for (const inv of corpus.invariants) {
    for (const kase of inv.cases) {
      const id = `${inv.invariant}/${kase.name}`;
      try {
        if (inv.domain === 'capability') await runCapabilityCase(kase);
        else if (inv.domain === 'handshake') runHandshakeCase(kase);
        else throw new Error(`unknown domain: ${inv.domain}`);
        results.push({ id, invariant: inv.invariant, spec: inv.spec, status: 'hold' });
      } catch (err) {
        failures += 1;
        results.push({ id, invariant: inv.invariant, spec: inv.spec, status: 'DIVERGED', detail: err.message });
      }
    }
  }

  if (asJson) {
    process.stdout.write(JSON.stringify(results, null, 2) + '\n');
  } else {
    const pad = (s, n) => String(s).padEnd(n);
    console.log(`EP invariant conformance — JavaScript lane (${results.length} cases from ${corpusPath})\n`);
    for (const r of results) {
      const mark = r.status === 'hold' ? '  ok ' : ' FAIL';
      console.log(`${mark}  ${pad(r.id, 52)} ${r.spec}${r.detail ? `\n        ↳ ${r.detail}` : ''}`);
    }
    console.log(`\n${results.length - failures}/${results.length} invariant cases hold.`);
    if (failures) console.log(`${failures} CROSS-PORT/CONFORMANCE DIVERGENCE(S) — investigate before merge.`);
  }
  process.exit(failures ? 1 : 0);
}

main().catch((err) => {
  console.error('invariant runner crashed:', err);
  process.exit(2);
});
