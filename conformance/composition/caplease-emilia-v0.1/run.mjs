// SPDX-License-Identifier: Apache-2.0
/**
 * Paper-derived CapLease model compared with the pinned EMILIA Gate runtime.
 *
 * This is not an implementation or reproduction of author-supplied CapLease
 * code: arXiv v1 does not publish such an artifact. The model below implements
 * only the transitions needed by this bounded comparison from Sections 3-4:
 * uniqueness over (sigma, confirmation event), Issued -> Prepared -> Committed,
 * pre-prepare expiry/revocation, and same-key recovery at an idempotent sink.
 */
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CAPABILITY_CAID_SCOPE_PROFILE,
  capabilityActionDigest,
  createMemoryCapabilityStore,
  mintCapabilityReceipt,
  reconcileCapabilityOperation,
  verifyCapabilityScope,
} from '../../../packages/gate/capability-receipt.js';
import { canonicalize } from '../../../packages/gate/execution-binding.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SOURCE_LOCK = JSON.parse(readFileSync(new URL('./source-lock.json', import.meta.url), 'utf8'));
const NOW = Date.parse('2026-08-16T18:00:00.000Z');
const CONFIRMATION_EVENT = 'confirmation:caplease-emilia:001';
const CAPLEASE_PRINCIPAL = 'user:buyer-controller';

const ACTION = Object.freeze({
  action_type: 'payment.transfer',
  amount: 100,
  currency: 'USD',
  destination: 'acct:vendor:9',
  operation_id: 'operation:payment:001',
});
const REISSUED_ACTION = Object.freeze({
  ...ACTION,
  operation_id: 'operation:payment:001-reissued',
});
const LOST_ACK_ACTION = Object.freeze({
  ...ACTION,
  operation_id: 'operation:payment:lost-ack',
});
const SUBSTITUTED_ACTION = Object.freeze({
  ...ACTION,
  amount: 1_000,
  destination: 'acct:attacker',
});

function digest(value) {
  return `sha256:${createHash('sha256').update(canonicalize(value), 'utf8').digest('hex')}`;
}

function materialCaid(action) {
  const material = {
    amount: action.amount,
    currency: action.currency,
    destination: action.destination,
  };
  const value = createHash('sha256').update(canonicalize(material), 'utf8').digest('base64url');
  return `caid:1:payment.transfer.1:jcs-sha256:${value}`;
}

const MATERIAL_CAID = materialCaid(ACTION);

function capLeaseActionIdentity(action) {
  return digest({
    principal: CAPLEASE_PRINCIPAL,
    tool: action.action_type,
    arguments: {
      amount: action.amount,
      currency: action.currency,
      destination: action.destination,
    },
    resource: action.destination,
  });
}

class PaperCapLeaseLedger {
  constructor() {
    this.records = new Map();
  }

  issue({ action, confirmationEvent, validFrom, validUntil, artifactId }) {
    const sigma = capLeaseActionIdentity(action);
    const key = canonicalize([sigma, confirmationEvent]);
    const existing = this.records.get(key);
    if (existing) return { created: false, artifact_id: artifactId, record: existing };
    const record = {
      sigma,
      confirmation_event: confirmationEvent,
      valid_from: validFrom,
      valid_until: validUntil,
      record_id: digest({ sigma, confirmationEvent }),
      slot: { state: 'ISSUED', key: null },
      admissions: 0,
    };
    this.records.set(key, record);
    return { created: true, artifact_id: artifactId, record };
  }

  prepare(record, action, now) {
    if (record.slot.state === 'REVOKED') return { ok: false, reason: 'authorization_revoked' };
    if (now < record.valid_from || now >= record.valid_until) {
      return { ok: false, reason: 'authorization_expired' };
    }
    if (capLeaseActionIdentity(action) !== record.sigma) {
      return { ok: false, reason: 'action_identity_mismatch' };
    }
    if (record.slot.state !== 'ISSUED') return { ok: false, reason: 'slot_not_issued' };
    record.slot.state = 'PREPARED';
    record.slot.key = digest({ record_id: record.record_id, slot: 0, tool: action.action_type });
    record.admissions += 1;
    return { ok: true, key: record.slot.key };
  }

  revoke(record) {
    if (record.slot.state !== 'ISSUED') return { ok: false, reason: 'slot_not_issued' };
    record.slot.state = 'REVOKED';
    return { ok: true };
  }

  executePrepared(record, action, sink) {
    if (record.slot.state !== 'PREPARED') return { ok: false, reason: 'slot_not_prepared' };
    try {
      const receipt = sink.execute(action, record.slot.key);
      if (receipt.key !== record.slot.key) return { ok: false, reason: 'sink_key_mismatch' };
      record.slot.state = 'COMMITTED';
      return { ok: true, result: 'ACKNOWLEDGED' };
    } catch {
      return { ok: false, result: 'ACK_LOST' };
    }
  }
}

function createIdempotentSink({ loseFirstAcknowledgement = false } = {}) {
  const results = new Map();
  let calls = 0;
  let effects = 0;
  return {
    execute(action, key) {
      calls += 1;
      const existing = results.get(key);
      if (existing) return existing;
      effects += 1;
      const receipt = { key, effect_id: `effect:${digest(action).slice(7, 23)}` };
      results.set(key, receipt);
      if (loseFirstAcknowledgement) throw new Error('acknowledgement lost after effect');
      return receipt;
    },
    get calls() { return calls; },
    get effects() { return effects; },
  };
}

function baseReceipt(privateKey, publicKey) {
  const payload = {
    receipt_id: 'receipt:caplease-comparison',
    created_at: new Date(NOW - 1_000).toISOString(),
    subject: 'agent:caplease-comparison',
    claim: { action_type: ACTION.action_type, outcome: 'allow', capability_only: true },
  };
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: {
      algorithm: 'Ed25519',
      value: sign(null, Buffer.from(canonicalize(payload), 'utf8'), privateKey).toString('base64url'),
    },
    public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

function createEmiliaFixture({ expiry = NOW + 60_000 } = {}) {
  const issuer = generateKeyPairSync('ed25519');
  const receipt = baseReceipt(issuer.privateKey, issuer.publicKey);
  const minted = mintCapabilityReceipt(receipt, {
    issuerPrivateKey: issuer.privateKey,
    budget: { amount: 1_000, currency: 'USD' },
    expiry,
    revocationMode: 'direct',
    capabilityId: 'capability:caplease-comparison',
    scope: {
      profile: CAPABILITY_CAID_SCOPE_PROFILE,
      operation_id_field: 'operation_id',
      caids: [MATERIAL_CAID],
    },
  });
  const store = createMemoryCapabilityStore();
  if (!store.registerCapability(minted.capabilityReceipt)) {
    throw new Error('failed to register EMILIA comparison capability');
  }
  const capabilityId = minted.capabilityReceipt.capability.id;
  const capabilityFingerprint = store.getState(capabilityId).capability_fingerprint;
  return { minted, store, capabilityId, capabilityFingerprint };
}

async function reserveEmilia(fixture, action, operationId, {
  now = NOW,
} = {}) {
  const scope = verifyCapabilityScope(
    fixture.minted.capabilityReceipt.capability,
    action,
    operationId,
    { resolveCaid: materialCaid },
  );
  if (!scope.ok) return scope;
  return fixture.store.reserveSpend({
    capabilityId: fixture.capabilityId,
    capabilityFingerprint: fixture.capabilityFingerprint,
    operationId,
    actionDigest: scope.action_digest,
    actionFenceDigest: scope.action_fence_digest,
    amount: action.amount,
    currency: action.currency,
    now,
  });
}

async function executeEmilia(fixture, action, {
  outcome = 'executed',
  now = NOW,
} = {}) {
  const operationId = action.operation_id;
  const reserved = await reserveEmilia(fixture, action, operationId, { now });
  if (!reserved.ok) return { ok: false, reason: reserved.reason };
  const entered = await fixture.store.beginProviderEntry({
    capabilityId: fixture.capabilityId,
    operationId,
    reservationToken: reserved.reservation_token,
    now,
  });
  if (!entered.ok) return { ok: false, reason: entered.reason };
  const committed = await fixture.store.commitSpend({
    capabilityId: fixture.capabilityId,
    operationId,
    reservationToken: reserved.reservation_token,
    outcome,
    now,
  });
  return committed.ok ? { ok: true, operation: fixture.store.getOperation(operationId) } : committed;
}

const PROVIDER_PRIVATE_KEY = createPrivateKey({
  key: Buffer.from(
    '302e020100300506032b657004220420752e048501f79628f66b7d9e93c52118e3feef74bd1167be95d901af360a9cb2',
    'hex',
  ),
  format: 'der',
  type: 'pkcs8',
});
const PROVIDER_PUBLIC_KEY = createPublicKey(PROVIDER_PRIVATE_KEY);

function signedProviderEvidence(action) {
  const body = {
    provider_id: 'provider:caplease-comparison',
    operation_id: action.operation_id,
    action_digest: capabilityActionDigest(action),
    outcome: 'executed',
  };
  return {
    body,
    signature: sign(
      null,
      Buffer.from(canonicalize(body), 'utf8'),
      PROVIDER_PRIVATE_KEY,
    ).toString('base64url'),
  };
}

function verifyProviderEvidence(evidence, context) {
  if (!evidence?.body || typeof evidence.signature !== 'string') throw new Error('evidence malformed');
  const signatureValid = verify(
    null,
    Buffer.from(canonicalize(evidence.body), 'utf8'),
    PROVIDER_PUBLIC_KEY,
    Buffer.from(evidence.signature, 'base64url'),
  );
  if (!signatureValid
      || evidence.body.provider_id !== 'provider:caplease-comparison'
      || evidence.body.operation_id !== context.operation_id
      || evidence.body.action_digest !== context.action_digest
      || evidence.body.outcome !== 'executed') {
    throw new Error('provider evidence rejected');
  }
  return {
    valid: true,
    outcome: 'executed',
    action_digest: evidence.body.action_digest,
    evidence_digest: digest(evidence),
  };
}

function issuePaperModel(ledger, action, overrides = {}) {
  return ledger.issue({
    action,
    confirmationEvent: CONFIRMATION_EVENT,
    validFrom: NOW - 1_000,
    validUntil: NOW + 60_000,
    artifactId: 'manifest:z1',
    ...overrides,
  });
}

function comparisonCheck(id, description, relation, caplease, emilia, passed) {
  return { id, description, relation, passed, caplease, emilia };
}

async function positiveCheck() {
  const ledger = new PaperCapLeaseLedger();
  const issued = issuePaperModel(ledger, ACTION);
  const prepared = ledger.prepare(issued.record, ACTION, NOW);
  const sink = createIdempotentSink();
  const completed = ledger.executePrepared(issued.record, ACTION, sink);

  const fixture = createEmiliaFixture();
  const emilia = await executeEmilia(fixture, ACTION);
  const operation = emilia.operation;
  const caplease = {
    final_state: issued.record.slot.state,
    admissions: issued.record.admissions,
    effects: sink.effects,
  };
  const emiliaObserved = {
    final_state: operation?.status ?? null,
    outcome: operation?.outcome ?? null,
    admissions: operation?.provider_entry_at ? 1 : 0,
  };
  return comparisonCheck(
    'CL-EP-01',
    'One exact action is admitted and consumed once under the supported assumptions.',
    'COMPATIBLE',
    caplease,
    emiliaObserved,
    prepared.ok === true && completed.ok === true && emilia.ok === true
      && caplease.admissions === 1 && caplease.effects === 1
      && emiliaObserved.final_state === 'committed' && emiliaObserved.outcome === 'executed',
  );
}

async function replayCheck() {
  const ledger = new PaperCapLeaseLedger();
  const first = issuePaperModel(ledger, ACTION);
  ledger.prepare(first.record, ACTION, NOW);
  ledger.executePrepared(first.record, ACTION, createIdempotentSink());
  const reissued = issuePaperModel(ledger, ACTION, { artifactId: 'manifest:z2' });
  const replayPreparation = ledger.prepare(reissued.record, ACTION, NOW);

  const fixture = createEmiliaFixture();
  const firstExecution = await executeEmilia(fixture, ACTION);
  const freshOperation = await reserveEmilia(
    fixture,
    REISSUED_ACTION,
    REISSUED_ACTION.operation_id,
  );
  const caplease = {
    fresh_artifact_result: reissued.created ? 'NEW_AUTHORIZATION' : 'EXISTING_AUTHORIZATION',
    replay_prepare_reason: replayPreparation.reason,
    admissions: first.record.admissions,
  };
  const emilia = {
    fresh_operation_result: freshOperation.ok ? 'ADMITTED' : 'REFUSED',
    reason: freshOperation.reason,
    holding_operation_id: freshOperation.holding_operation_id,
  };
  return comparisonCheck(
    'CL-EP-02',
    'Fresh identifiers do not create a second admission, but the durable identity keys differ.',
    'COMPATIBLE_WITH_DIFFERENT_IDENTITY_KEYS',
    caplease,
    emilia,
    firstExecution.ok === true && reissued.created === false
      && replayPreparation.reason === 'slot_not_issued' && first.record.admissions === 1
      && freshOperation.reason === 'action_already_committed',
  );
}

async function substitutionCheck() {
  const ledger = new PaperCapLeaseLedger();
  const issued = issuePaperModel(ledger, ACTION);
  const capleaseResult = ledger.prepare(issued.record, SUBSTITUTED_ACTION, NOW);

  const fixture = createEmiliaFixture();
  const emiliaResult = verifyCapabilityScope(
    fixture.minted.capabilityReceipt.capability,
    SUBSTITUTED_ACTION,
    SUBSTITUTED_ACTION.operation_id,
    { resolveCaid: materialCaid },
  );
  return comparisonCheck(
    'CL-EP-03',
    'Material amount or destination substitution is refused before admission.',
    'COMPATIBLE',
    { result: 'REFUSED', reason: capleaseResult.reason },
    { result: 'REFUSED', reason: emiliaResult.reason },
    capleaseResult.reason === 'action_identity_mismatch'
      && emiliaResult.reason === 'capability_action_out_of_scope',
  );
}

async function expiryCheck() {
  const ledger = new PaperCapLeaseLedger();
  const issued = issuePaperModel(ledger, ACTION, { validUntil: NOW });
  const capleaseResult = ledger.prepare(issued.record, ACTION, NOW);

  const fixture = createEmiliaFixture({ expiry: NOW });
  const emiliaResult = await reserveEmilia(fixture, ACTION, ACTION.operation_id, { now: NOW });
  return comparisonCheck(
    'CL-EP-04',
    'Expired authority cannot begin a new admission.',
    'COMPATIBLE',
    { result: 'REFUSED', reason: capleaseResult.reason },
    { result: 'REFUSED', reason: emiliaResult.reason },
    capleaseResult.reason === 'authorization_expired' && emiliaResult.reason === 'capability_expired',
  );
}

async function revocationCheck() {
  const ledger = new PaperCapLeaseLedger();
  const issued = issuePaperModel(ledger, ACTION);
  const capleaseRevoked = ledger.revoke(issued.record);
  const capleaseResult = ledger.prepare(issued.record, ACTION, NOW);

  const fixture = createEmiliaFixture();
  const emiliaRevoked = await fixture.store.revokeCapability({
    capabilityId: fixture.capabilityId,
    capabilityFingerprint: fixture.capabilityFingerprint,
    now: NOW,
  });
  const emiliaResult = await reserveEmilia(fixture, ACTION, ACTION.operation_id);
  return comparisonCheck(
    'CL-EP-05',
    'Revocation that wins before admission prevents provider entry.',
    'COMPATIBLE',
    { result: 'REFUSED', reason: capleaseResult.reason },
    { result: 'REFUSED', reason: emiliaResult.reason },
    capleaseRevoked.ok === true && emiliaRevoked.ok === true
      && capleaseResult.reason === 'authorization_revoked'
      && emiliaResult.reason === 'capability_revoked',
  );
}

async function lostAcknowledgementCheck() {
  const ledger = new PaperCapLeaseLedger();
  const issued = issuePaperModel(ledger, LOST_ACK_ACTION);
  ledger.prepare(issued.record, LOST_ACK_ACTION, NOW);
  const sink = createIdempotentSink({ loseFirstAcknowledgement: true });
  const firstCapLease = ledger.executePrepared(issued.record, LOST_ACK_ACTION, sink);
  const recoveredCapLease = ledger.executePrepared(issued.record, LOST_ACK_ACTION, sink);

  const fixture = createEmiliaFixture();
  const firstEmilia = await executeEmilia(fixture, LOST_ACK_ACTION, { outcome: 'indeterminate' });
  const replayEmilia = await reserveEmilia(
    fixture,
    LOST_ACK_ACTION,
    LOST_ACK_ACTION.operation_id,
  );
  const evidence = signedProviderEvidence(LOST_ACK_ACTION);
  const reconciled = await reconcileCapabilityOperation({
    store: fixture.store,
    capabilityId: fixture.capabilityId,
    operationId: LOST_ACK_ACTION.operation_id,
    action: LOST_ACK_ACTION,
    evidence,
    verifyEvidence: verifyProviderEvidence,
    now: NOW + 1_000,
  });
  const operation = fixture.store.getOperation(LOST_ACK_ACTION.operation_id);
  const caplease = {
    first_result: firstCapLease.result,
    recovery: 'RETRIED_SAME_KEY',
    final_state: issued.record.slot.state,
    sink_calls: sink.calls,
    effects: sink.effects,
  };
  const emilia = {
    first_result: firstEmilia.operation?.outcome === 'indeterminate' ? 'INDETERMINATE' : 'OTHER',
    blind_replay: replayEmilia.ok ? 'ADMITTED' : 'REFUSED',
    replay_reason: replayEmilia.reason,
    final_state: operation?.status ?? null,
    original_outcome: operation?.outcome ?? null,
    reconciliation: operation?.reconciliation_outcome ?? null,
    effects: 1,
    reexecuted: false,
  };
  return comparisonCheck(
    'CL-EP-06',
    'Lost acknowledgement consumes one admission in both systems but recovery contracts differ.',
    'DIFFERENT_RECOVERY_CONTRACT',
    caplease,
    emilia,
    firstCapLease.result === 'ACK_LOST' && recoveredCapLease.ok === true
      && caplease.final_state === 'COMMITTED' && caplease.sink_calls === 2 && caplease.effects === 1
      && firstEmilia.ok === true && replayEmilia.reason === 'operation_already_committed'
      && reconciled.ok === true && emilia.original_outcome === 'indeterminate'
      && emilia.reconciliation === 'executed',
  );
}

function reconciliationBoundaryCheck() {
  const caplease = {
    status: 'UNSUPPORTED',
    paper_behavior: 'recover Prepared by invoking the sink again with the same stable key',
  };
  const emilia = {
    status: 'SUPPORTED',
    behavior: 'verify same-action provider evidence and append reconciliation without reexecution',
  };
  return comparisonCheck(
    'CL-EP-07',
    'The CapLease v1 paper does not specify EMILIA-style evidence-only post-entry reconciliation.',
    'CAPLEASE_UNSUPPORTED_BY_PAPER',
    caplease,
    emilia,
    true,
  );
}

function identityBoundaryCheck() {
  const caplease = {
    identity_key: '(sigma, confirmation_event)',
    property: 'unique durable authorization record across fresh artifacts',
  };
  const emilia = {
    identity_key: '(operation_namespace, action_fence_digest)',
    property: 'duplicate-action admission fence over active or committed operations',
    confirmation_event_uniqueness: 'NOT_CLAIMED',
  };
  return comparisonCheck(
    'CL-EP-08',
    'EMILIA action fencing is not proof of CapLease authorization-instance uniqueness.',
    'EMILIA_NOT_EQUIVALENT',
    caplease,
    emilia,
    true,
  );
}

function reportDigest(report) {
  return digest(report);
}

export async function runComparison() {
  const checks = [
    await positiveCheck(),
    await replayCheck(),
    await substitutionCheck(),
    await expiryCheck(),
    await revocationCheck(),
    await lostAcknowledgementCheck(),
    reconciliationBoundaryCheck(),
    identityBoundaryCheck(),
  ];
  const compatible = checks.filter((entry) => entry.relation === 'COMPATIBLE'
    || entry.relation === 'COMPATIBLE_WITH_DIFFERENT_IDENTITY_KEYS').length;
  const different = checks.filter((entry) => entry.relation === 'DIFFERENT_RECOVERY_CONTRACT'
    || entry.relation === 'EMILIA_NOT_EQUIVALENT').length;
  const unsupported = checks.filter((entry) => entry.relation === 'CAPLEASE_UNSUPPORTED_BY_PAPER').length;
  const passed = checks.filter((entry) => entry.passed).length;
  const body = {
    '@version': 'CAPLEASE-EMILIA-COMPARISON-REPORT-v0.1',
    profile: 'CAPLEASE-EMILIA-COMPARISON-v0.1',
    passed: passed === checks.length,
    summary: { passed, total: checks.length, compatible, different, unsupported },
    source_basis: {
      caplease: {
        arxiv_id: SOURCE_LOCK.caplease.arxiv_id,
        version: SOURCE_LOCK.caplease.version,
        pdf_sha256: SOURCE_LOCK.caplease.pdf.sha256,
        tex_source_archive_sha256: SOURCE_LOCK.caplease.tex_source.archive_sha256,
        implementation_kind: 'paper-derived-executable-model',
        official_repository: SOURCE_LOCK.caplease.official_repository,
        availability_note: 'No official code artifact or repository is identified by the arXiv v1 metadata or source archive.',
      },
      emilia: {
        repository: SOURCE_LOCK.emilia.repository,
        base_revision: SOURCE_LOCK.emilia.base_revision,
        implementation_kind: 'repository-runtime',
        runtime: 'packages/gate/capability-receipt.js',
        store: 'createMemoryCapabilityStore',
        store_durable: false,
      },
    },
    checks,
    assumptions: [
      'CapLease behavior is limited to arXiv v1 Sections 3-4 and is not author-supplied code.',
      'CapLease action canonicalization, authenticated principals and confirmation events, and durable linearizable non-rollback storage are trusted as stated by the paper.',
      'CapLease duplicate-effect recovery assumes the sink enforces idempotency over the stable key.',
      'EMILIA executes its actual in-memory atomic reference store; the run demonstrates semantics, not production durability.',
      'EMILIA material-action fencing is supplied by the relying-party projection used by this bounded fixture.',
      'The EMILIA reconciliation fixture verifies an Ed25519 provider statement bound to the same operation and action digest.',
    ],
    limitations: [
      'This is neither an independent CapLease implementation nor execution of an official CapLease artifact.',
      'No comparison result upgrades admission control into exactly-once physical execution.',
      'A non-idempotent CapLease sink remains outside the effect guarantee stated in the paper.',
      'EMILIA INDETERMINATE is not proof that the effect happened or did not happen.',
      'The package does not claim CapLease and EMILIA share an authorization identity, wire format, ledger schema, or recovery protocol.',
    ],
  };
  return { ...body, report_digest: reportDigest(body) };
}

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--check' || arg === '--emit') args[arg.slice(2)] = true;
    else if (arg === '--output') {
      const value = argv[index + 1];
      if (!value || value.startsWith('--')) throw new TypeError('--output requires a path');
      args.output = value;
      index += 1;
    } else throw new TypeError(`unknown argument: ${arg}`);
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const report = await runComparison();
  if (args.check) {
    const reference = JSON.parse(readFileSync(resolve(HERE, 'report.reference.json'), 'utf8'));
    if (canonicalize(reference) !== canonicalize(report)) {
      throw new Error('CapLease comparison reference report is stale');
    }
  }
  if (args.emit || args.output) {
    const output = resolve(args.output ?? resolve(HERE, 'report.reference.json'));
    writeFileSync(output, `${JSON.stringify(report, null, 2)}\n`);
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.passed) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
