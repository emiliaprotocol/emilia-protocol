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
const sha256Hex = (v) => crypto.createHash('sha256').update(v, 'utf8').digest('hex');
const sha256Bytes = (v) => crypto.createHash('sha256').update(v).digest();

const RP_ID = 'emiliaprotocol.ai';

/**
 * Mint a GENUINE WebAuthn ECDSA-P256 device signoff over an authorization
 * context — the same structure @emilia-protocol/verify verifyWebAuthnSignoff
 * checks. This is what earns a receipt its class_a tier: a real per-signer
 * assertion, not a self-asserted `outcome` string. Used to build the Class-A and
 * quorum evidence the EG-1 harness embeds so the Gate can CRYPTOGRAPHICALLY
 * credit the tier.
 */
export function mintDeviceSignoff({ actionHash, approver, issuedAtMs = Date.now(), nonce, prevContextHash = undefined } = {}) {
  const signer = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const context = {
    ep_version: '1.0', context_type: 'ep.signoff.v1',
    action_hash: actionHash,
    policy: 'policy_eg1',
    nonce: nonce || ('sig_' + crypto.randomBytes(16).toString('hex')),
    approver,
    initiator: 'ent_agent_eg1',
    issued_at: new Date(issuedAtMs).toISOString(),
    expires_at: new Date(issuedAtMs + 5 * 60_000).toISOString(),
    ...(prevContextHash !== undefined ? { prev_context_hash: prevContextHash } : {}),
  };
  const challenge = crypto.createHash('sha256').update(canon(context), 'utf8').digest().toString('base64url');
  const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: `https://www.${RP_ID}` }), 'utf8');
  const authData = Buffer.concat([
    crypto.createHash('sha256').update(RP_ID, 'utf8').digest(),
    Buffer.from([0x05]), // UP | UV
    Buffer.from([0, 0, 0, 1]),
  ]);
  const signed = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
  const signature = crypto.sign('sha256', signed, signer.privateKey).toString('base64url');
  return {
    signoff: {
      '@type': 'ep.signoff',
      context,
      webauthn: {
        authenticator_data: authData.toString('base64url'),
        client_data_json: clientData.toString('base64url'),
        signature,
      },
      approver_public_key: signer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    },
    approver_public_key: signer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    context,
  };
}

/**
 * Mint a GENUINE EP-QUORUM-v1 evidence document: N distinct humans, each on a
 * distinct device key, each with a real WebAuthn assertion bound to the SAME
 * action_hash, within a window. verifyQuorum returns valid for it. This is what
 * earns a receipt its `quorum` tier — never a bare {signers,threshold} block.
 */
export function mintQuorumEvidence({ actionHash, threshold = 2, approvers, issuedAtMs = Date.now() } = {}) {
  const people = approvers || Array.from({ length: threshold }, (_, i) => ({ role: `approver_${i + 1}`, approver: `ep:approver:eg1_${i + 1}` }));
  const members = people.map((p, i) => {
    const s = mintDeviceSignoff({ actionHash, approver: p.approver, issuedAtMs: issuedAtMs + i * 1000 });
    return { role: p.role, approver_public_key: s.approver_public_key, signoff: { '@type': s.signoff['@type'], context: s.signoff.context, webauthn: s.signoff.webauthn } };
  });
  return {
    '@type': 'ep.quorum',
    action_hash: actionHash,
    policy: {
      mode: 'threshold',
      required: threshold,
      approvers: people,
      distinct_humans: true,
      window_sec: 900,
    },
    members,
  };
}

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
  const approverA = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const approverB = crypto.generateKeyPairSync('ed25519');
  const approverKeys = {
    'ep:key:eg1:class-a': {
      public_key: approverA.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      key_class: 'A',
    },
    'ep:key:eg1:controller': {
      public_key: approverB.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      key_class: 'B',
    },
  };
  let counter = 0;
  const nowMs = () => (typeof now === 'function' ? now() : now);

  // The action_hash the self-contained human device assertions are bound to.
  // Derived from the action so the signoff/quorum evidence is about THIS action.
  const actionHash = crypto.createHash('sha256').update(canon(action), 'utf8').digest('hex');

  function assuranceContext(payload) {
    return {
      '@version': 'EP-ASSURANCE-CONTEXT-v1',
      receipt_id: payload.receipt_id,
      claim_hash: `sha256:${sha256Hex(canon(payload.claim))}`,
    };
  }

  function classASignoff(digest) {
    const challenge = Buffer.from(digest).toString('base64url');
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'https://www.emiliaprotocol.ai' }), 'utf8');
    const rpIdHash = crypto.createHash('sha256').update('www.emiliaprotocol.ai').digest();
    const authData = Buffer.concat([rpIdHash, Buffer.from([0x05]), Buffer.from([0, 0, 0, 0])]); // UP + UV
    const signedData = Buffer.concat([authData, sha256Bytes(clientDataJSON)]);
    return {
      approver: 'ep:approver:eg1:cfo',
      approver_key_id: 'ep:key:eg1:class-a',
      key_class: 'A',
      webauthn: {
        authenticator_data: authData.toString('base64url'),
        client_data_json: clientDataJSON.toString('base64url'),
        signature: crypto.sign('sha256', signedData, approverA.privateKey).toString('base64url'),
      },
    };
  }

  function softwareSignoff(digest) {
    return {
      approver: 'ep:approver:eg1:controller',
      approver_key_id: 'ep:key:eg1:controller',
      key_class: 'B',
      signature: crypto.sign(null, digest, approverB.privateKey).toString('base64url'),
    };
  }

  function assuranceProof(payload, quorum) {
    const context = assuranceContext(payload);
    const contextHash = `sha256:${sha256Hex(canon(context))}`;
    const digest = Buffer.from(contextHash.replace(/^sha256:/, ''), 'hex');
    const threshold = Number(quorum?.threshold ?? quorum?.m ?? 1);
    const signoffs = [classASignoff(digest)];
    if (threshold >= 2) signoffs.push(softwareSignoff(digest));
    return {
      '@version': 'EP-ASSURANCE-PROOF-v1',
      context_hash: contextHash,
      threshold: threshold >= 2 ? threshold : 1,
      signoffs,
    };
  }

  /**
   * Mint a scenario receipt.
   * @param {object} o
   * @param {'allow'|'allow_with_signoff'} [o.outcome] 'allow'=software; 'allow_with_signoff'
   *   embeds a REAL WebAuthn device signoff so the receipt cryptographically earns class_a.
   * @param {object|boolean} [o.quorum] request quorum-tier evidence. Truthy -> a REAL
   *   EP-QUORUM-v1 doc (distinct humans + distinct keys + per-signer assertions). If an
   *   object with `threshold`/`signers`, its size sets the quorum size.
   * @param {boolean} [o.fakeQuorum] embed an UNVERIFIABLE self-asserted quorum block
   *   ({signers,threshold}) with no per-signer signatures — used to prove the Gate
   *   REFUSES it (must NOT be credited quorum). For adversarial tests only.
   * @param {object} [o.tamper] fields assigned to the claim AFTER signing (breaks the signature)
   */
  function mint({ outcome = 'allow_with_signoff', quorum = null, fakeQuorum = false, tamper = null, extra = {} } = {}) {
    const claim = { ...action, outcome, approver: 'ep:approver:eg1', ...extra };
    const payload = {
      receipt_id: `${idPrefix}_${++counter}`,
      subject: 'agent:eg1-conformance',
      issuer: 'ep:org:eg1',
      created_at: new Date(nowMs()).toISOString(),
      claim,
    };
    if (fakeQuorum) {
      // Self-asserted ONLY — NO members / NO signatures / NO pinned proof. The
      // Gate must refuse to credit this as quorum (assurance_too_low). For
      // adversarial tests that prove payload claims are never trusted.
      payload.quorum = { signers: ['ep:a', 'ep:b'], threshold: 2 };
    } else if (outcome === 'allow_with_signoff' || quorum) {
      // Genuine, per-signer-verifiable evidence. The PRIMARY proof is the pinned
      // EP-ASSURANCE-PROOF-v1 (verified against the harness's pinned approverKeys),
      // which is what the EG-1 gate/custody path checks. We ALSO embed self-contained
      // evidence (EP-QUORUM-v1 / WebAuthn device signoff) so a relying party that
      // does NOT pin keys can still cryptographically credit the tier (DoD audit fix).
      payload.assurance_proof = assuranceProof(payload, quorum);
      if (quorum) {
        const threshold = Number.isInteger(quorum.threshold) ? quorum.threshold
          : (Array.isArray(quorum.signers) ? quorum.signers.length : 2);
        payload.quorum = mintQuorumEvidence({ actionHash, threshold, issuedAtMs: nowMs() });
      } else {
        const s = mintDeviceSignoff({ actionHash, approver: 'ep:approver:eg1', issuedAtMs: nowMs() });
        payload.signoff = s.signoff;
        payload.approver_public_key = s.approver_public_key;
      }
    }
    const value = crypto.sign(null, Buffer.from(canon(payload), 'utf8'), privateKey).toString('base64url');
    const receipt = { '@version': 'EP-RECEIPT-v1', payload, signature: { algorithm: 'Ed25519', value } };
    if (tamper) Object.assign(receipt.payload.claim, tamper); // tamper AFTER signing -> signature no longer binds
    return receipt;
  }

  return { publicKey: pub, approverKeys, mint, action, actionHash, now: nowMs };
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

export default { EG1_VERSION, EG1_CHECKS, EG1_DEFAULT_ACTION, EG1_DEFAULT_SELECTOR, createEg1Harness, makeGateInvoke, runEg1, mintDeviceSignoff, mintQuorumEvidence };
