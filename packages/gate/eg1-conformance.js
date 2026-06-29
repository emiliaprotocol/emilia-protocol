// SPDX-License-Identifier: Apache-2.0
/**
 * EG-1 Conformance — the binary artifact that turns "we adopted EMILIA Gate"
 * from a claim into a test result.
 *
 * The question EG-1 answers: *does your integration actually ENFORCE the gate,
 * or are you only claiming it?* An integration earns EG-1 only if it
 * demonstrably:
 *   1. refuses a high-risk action with NO receipt (428);
 *   2. refuses a software-tier receipt on a Class-A action;
 *   3. refuses when the observed execution drifts from the authorized fields;
 *   4. RUNS the action for a valid Class-A/quorum receipt;
 *   5. refuses a replay of the same receipt;
 *   6. refuses a tampered receipt;
 *   7. emits an execution proof bound to the authorization decision;
 *   8. produces a reliance packet whose verdict is "rely".
 *
 * This module is pure (no dependency on index.js, so no import cycle): it owns a
 * throwaway issuer keypair, mints the scenario receipts, and drives any
 * "subject" through the eight checks. A subject is an async `invoke` function
 * representing one attempt at the guarded dangerous action:
 *
 *   invoke({ receipt, observedAction }) -> {
 *     allowed: boolean, status: number, reason: string,
 *     // present only on an allowed run:
 *     decisionHash?: string, execution?: { authorizes_decision }, packet?: { verdict }
 *   }
 *
 * For integrations built on @emilia-protocol/gate, `makeGateInvoke(gate, ...)`
 * produces a conformant `invoke` from `gate.run()`. Custom integrations (an HTTP
 * service, a different language) implement `invoke` themselves and configure
 * their gate to trust `harness.publicKey` for the run.
 */
import crypto from 'node:crypto';

export const EG1_VERSION = 'EG-1';

// Same sorted-key canonical JSON the receipt signature is computed over.
const canon = (v) => (v == null ? JSON.stringify(v)
  : Array.isArray(v) ? `[${v.map(canon).join(',')}]`
    : typeof v === 'object' ? `{${Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',')}}`
      : JSON.stringify(v));

// The default high-risk action EG-1 exercises: a Class-A money movement, which
// the default gate manifest guards (selector { protocol:'mcp', tool:'release_payment' }).
export const EG1_DEFAULT_SELECTOR = Object.freeze({ protocol: 'mcp', tool: 'release_payment' });
export const EG1_DEFAULT_ACTION = Object.freeze({
  action_type: 'payment.release',
  amount_usd: 40000,
  currency: 'USD',
  payment_instruction_id: 'pi_eg1_40000',
  beneficiary_account_hash: 'sha256:eg1-beneficiary',
});

export const EG1_CHECKS = Object.freeze([
  { id: 'missing_receipt_refused', title: 'missing receipt → 428' },
  { id: 'software_on_classA_refused', title: 'software receipt on Class-A action → refused' },
  { id: 'execution_drift_refused', title: 'observed execution drift → refused' },
  { id: 'valid_classA_runs', title: 'valid Class-A/quorum receipt → runs' },
  { id: 'replay_refused', title: 'same receipt replay → refused' },
  { id: 'tampered_refused', title: 'tampered receipt → refused' },
  { id: 'execution_proof_binds', title: 'execution proof binds to authorization decision' },
  { id: 'reliance_packet_rely', title: 'reliance packet returns verdict "rely"' },
]);

/**
 * Create an EG-1 harness: a throwaway issuer key + a receipt minter for the
 * scenarios. Configure the subject's gate to trust `publicKey` for the run.
 */
export function createEg1Harness({ now = Date.now, action = EG1_DEFAULT_ACTION, idPrefix = 'eg1' } = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  let counter = 0;
  const nowMs = () => (typeof now === 'function' ? now() : now);

  /**
   * Mint a scenario receipt.
   * @param {object} o
   * @param {'allow'|'allow_with_signoff'} [o.outcome] 'allow'=software, 'allow_with_signoff'=Class-A
   * @param {object} [o.quorum] a quorum block (signers/threshold) -> quorum tier
   * @param {object} [o.tamper] fields assigned to the claim AFTER signing (breaks the signature)
   */
  function mint({ outcome = 'allow_with_signoff', quorum = null, tamper = null, extra = {} } = {}) {
    const payload = {
      receipt_id: `${idPrefix}_${++counter}`,
      subject: 'agent:eg1-conformance',
      issuer: 'ep:org:eg1',
      created_at: new Date(nowMs()).toISOString(),
      claim: {
        ...action,
        outcome,
        approver: 'ep:approver:eg1',
        ...(quorum ? { quorum } : {}),
        ...extra,
      },
    };
    const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
    const receipt = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value } };
    if (tamper) Object.assign(receipt.payload.claim, tamper); // tamper AFTER signing -> signature no longer binds
    return receipt;
  }

  return { publicKey: pub, mint, action, now: nowMs };
}

/**
 * Adapt an @emilia-protocol/gate instance into an EG-1 `invoke`. The gate must
 * have been built trusting the harness public key. Uses gate.run() so the
 * execution proof + reliance packet are produced on the allowed path.
 */
export function makeGateInvoke(gate, { selector = EG1_DEFAULT_SELECTOR, action = EG1_DEFAULT_ACTION } = {}) {
  if (!gate || typeof gate.run !== 'function') {
    throw new Error('makeGateInvoke requires an EMILIA Gate instance (with .run)');
  }
  return async ({ receipt, observedAction }) => {
    const out = await gate.run(
      { selector, receipt, observedAction: observedAction ?? action },
      async () => ({ eg1: 'side-effect-ran' }),
    );
    if (!out.ok) {
      return { allowed: false, status: out.status, reason: out.authorization?.reason ?? 'refused' };
    }
    return {
      allowed: true,
      status: 200,
      reason: out.authorization?.reason ?? 'allow',
      decisionHash: out.authorization?.evidence?.hash ?? null,
      execution: out.execution ?? null,
      packet: out.packet ?? null,
    };
  };
}

const pick = (r) => ({ allowed: !!r.allowed, status: r.status ?? null, reason: r.reason ?? null });

/**
 * Drive a subject through the eight EG-1 checks and return a JSON report.
 * @param {object} o
 * @param {(scenario:object)=>Promise<object>} o.invoke the integration under test
 * @param {object} o.harness from createEg1Harness()
 * @param {object} [o.action] the high-risk action (defaults to the harness action)
 */
export async function runEg1({ invoke, harness, action } = {}) {
  if (typeof invoke !== 'function') throw new Error('runEg1 requires an invoke(scenario) function');
  if (!harness || typeof harness.mint !== 'function') throw new Error('runEg1 requires a harness from createEg1Harness()');
  const act = action || harness.action || EG1_DEFAULT_ACTION;
  const observed = act;
  const drift = { ...act, amount_usd: Number(act.amount_usd ?? 0) + 1 };

  const results = {};
  const set = (id, pass, observed_) => { results[id] = { pass: !!pass, observed: observed_ }; };

  // 1. missing receipt → 428
  let r = await invoke({ receipt: null, observedAction: observed });
  set('missing_receipt_refused', !r.allowed && r.status === 428, pick(r));

  // 2. software receipt on a Class-A action → refused
  r = await invoke({ receipt: harness.mint({ outcome: 'allow' }), observedAction: observed });
  set('software_on_classA_refused', !r.allowed && /assurance/i.test(r.reason || ''), pick(r));

  // 3. observed execution drift → refused
  r = await invoke({ receipt: harness.mint({ outcome: 'allow_with_signoff' }), observedAction: drift });
  set('execution_drift_refused', !r.allowed && /binding/i.test(r.reason || ''), pick(r));

  // 4. valid Class-A receipt → runs (capture for 5/7/8)
  const valid = harness.mint({ outcome: 'allow_with_signoff' });
  r = await invoke({ receipt: valid, observedAction: observed });
  const validAllowed = r.allowed === true;
  set('valid_classA_runs', validAllowed, pick(r));

  // 7. execution proof binds to the authorization decision
  const boundOk = validAllowed
    && !!r.execution && !!r.execution.authorizes_decision
    && !!r.decisionHash && r.execution.authorizes_decision === r.decisionHash;
  set('execution_proof_binds', boundOk, {
    authorizes_decision: r.execution?.authorizes_decision ?? null,
    decision_hash: r.decisionHash ?? null,
  });

  // 8. reliance packet verdict "rely"
  set('reliance_packet_rely', validAllowed && String(r.packet?.verdict || '').toLowerCase() === 'rely', {
    verdict: r.packet?.verdict ?? null,
  });

  // 5. same receipt replay → refused
  r = await invoke({ receipt: valid, observedAction: observed });
  set('replay_refused', !r.allowed && /replay/i.test(r.reason || ''), pick(r));

  // 6. tampered receipt → refused
  r = await invoke({ receipt: harness.mint({ outcome: 'allow_with_signoff', tamper: { amount_usd: 9_999_999 } }), observedAction: observed });
  set('tampered_refused', !r.allowed && r.status === 428, pick(r));

  const checks = EG1_CHECKS.map((c) => ({ id: c.id, title: c.title, ...results[c.id] }));
  const passedCount = checks.filter((c) => c.pass).length;
  const passed = passedCount === checks.length;
  return {
    standard: EG1_VERSION,
    passed,
    badge: passed ? 'EG-1 Enforced' : 'EG-1 not earned',
    summary: { passed: passedCount, total: checks.length },
    checks,
    generated_at: new Date(harness.now ? harness.now() : Date.now()).toISOString(),
  };
}

export default { EG1_VERSION, EG1_CHECKS, EG1_DEFAULT_ACTION, EG1_DEFAULT_SELECTOR, createEg1Harness, makeGateInvoke, runEg1 };
