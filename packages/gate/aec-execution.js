// SPDX-License-Identifier: Apache-2.0
/**
 * Stateful execution boundary for EP-AEC.
 *
 * verifyAuthorizationChain is a pure evidence-composition decision. This
 * wrapper adds the stateful properties an executor needs: independently bound
 * action bytes, a mandatory human-assurance floor, atomic one-time reservation,
 * tamper-evident decision records, and conservative crash semantics.
 */
import { createEvidenceLog, verifyEvidenceRecord } from './evidence.js';
import { MemoryConsumptionStore } from './store.js';

const { verifyAuthorizationChain } = await import('@emilia-protocol/verify/evidence-chain')
  .catch(() => import('../verify/evidence-chain.js'));

const HUMAN_FLOORS = new Set(['class_a', 'quorum', 'class_a_or_quorum']);
const HEX_256 = /^[0-9a-f]{64}$/;
const COMPONENT_TYPE = /^[A-Za-z0-9_.:-]+$/;
const RESERVED_COMPONENT_TYPES = new Set(['ep-receipt', 'ep-quorum']);
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

function deepFreeze(value) {
  if (!value || typeof value !== 'object') return value;
  const stack = [value];
  const seen = new WeakSet();
  while (stack.length) {
    const current = stack.pop();
    if (!current || typeof current !== 'object' || seen.has(current)) continue;
    seen.add(current);
    for (const child of Object.values(current)) stack.push(child);
    Object.freeze(current);
  }
  return value;
}

function validLogRecord(record, atomicRequired, expectedEntry) {
  return verifyEvidenceRecord(record, { atomicRequired, expectedEntry });
}

function validComponent(result, type) {
  return Array.isArray(result?.components)
    && result.components.some((component) => component.type === type && component.valid === true && component.bound === true);
}

function humanFloorSatisfied(result, floor) {
  const classA = validComponent(result, 'ep-receipt');
  const quorum = validComponent(result, 'ep-quorum');
  if (floor === 'class_a') return classA;
  if (floor === 'quorum') return quorum;
  return classA || quorum;
}

function consumptionKey(result) {
  // Consume the executor-owned action instance, not a presenter-selected
  // component identifier. Otherwise an invalid decoy component or an alternate
  // valid human proof can create a fresh key for the same physical effect.
  // Repeated intended effects therefore need a unique nonce/id inside the
  // canonical action before authorization is collected.
  return HEX_256.test(result?.action_digest)
    ? `aec:action:${result.action_digest}`
    : null;
}

function instant(now) {
  try {
    const value = typeof now === 'function' ? now() : now;
    const date = value instanceof Date ? value : new Date(value);
    return Number.isFinite(date.getTime()) ? date.toISOString() : null;
  } catch {
    return null;
  }
}

/**
 * @param {object} config
 * @param {string} config.requirement relying-party AEC requirement
 * @param {object} config.policiesByType relying-party human acceptance profiles
 * @param {object} [config.verifiers] relying-party-pinned custom component verifiers
 * @param {object} [config.keysByType] relying-party-pinned custom verifier keys
 * @param {'class_a'|'quorum'|'class_a_or_quorum'} config.humanFloor
 * @param {object} [config.store] ownership-fenced consumption store
 * @param {object} [config.log] tamper-evident evidence log
 * @param {boolean} [config.allowEphemeralState=false] test/demo opt-in only
 * @param {Function|number|Date} [config.now=Date.now]
 */
export function createAECExecutionGate({
  requirement,
  policiesByType,
  verifiers = {},
  keysByType = {},
  humanFloor,
  store,
  log,
  allowEphemeralState = false,
  now = Date.now,
} = {}) {
  if (typeof requirement !== 'string' || !requirement.trim()) {
    throw new Error('AEC execution gate requires a relying-party requirement');
  }
  if (!policiesByType || typeof policiesByType !== 'object' || Array.isArray(policiesByType)) {
    throw new Error('AEC execution gate requires relying-party policiesByType');
  }
  let pinnedPolicies;
  try { pinnedPolicies = deepFreeze(structuredClone(policiesByType)); }
  catch { throw new Error('AEC execution gate policiesByType must be cloneable canonical data'); }
  if (!verifiers || typeof verifiers !== 'object' || Array.isArray(verifiers)) {
    throw new Error('AEC execution gate verifiers must be a relying-party-owned object');
  }
  const pinnedVerifiers = Object.create(null);
  try {
    for (const [type, verifier] of Object.entries(verifiers)) {
      if (!COMPONENT_TYPE.test(type) || type.length > 128 || RESERVED_COMPONENT_TYPES.has(type)
          || typeof verifier !== 'function') {
        throw new Error('invalid verifier registry member');
      }
      pinnedVerifiers[type] = verifier;
    }
    Object.freeze(pinnedVerifiers);
  } catch {
    throw new Error('AEC execution gate verifiers must contain only named custom verifier functions');
  }
  if (!keysByType || typeof keysByType !== 'object' || Array.isArray(keysByType)) {
    throw new Error('AEC execution gate keysByType must be a relying-party-owned object');
  }
  let pinnedKeysByType;
  try { pinnedKeysByType = deepFreeze(structuredClone(keysByType)); }
  catch { throw new Error('AEC execution gate keysByType must be cloneable canonical data'); }
  if (!HUMAN_FLOORS.has(humanFloor)) {
    throw new Error('AEC execution gate requires humanFloor class_a, quorum, or class_a_or_quorum');
  }
  if (!store && !allowEphemeralState) {
    throw new Error('AEC execution gate requires a durable consumption store');
  }
  if (!log && !allowEphemeralState) {
    throw new Error('AEC execution gate requires a durable strict evidence log');
  }

  const consumption = store || new MemoryConsumptionStore();
  const evidence = log || createEvidenceLog({ strict: true });
  if (!allowEphemeralState && (consumption.durable !== true || consumption.ownershipFenced !== true
      || consumption.permanentConsumption !== true)) {
    throw new Error('AEC execution gate requires a capability-marked, ownership-fenced durable store with non-expiring committed keys');
  }
  if (!allowEphemeralState && (evidence.durable !== true || evidence.strict !== true
      || evidence.forkAware !== true || evidence.atomicAppend !== true)) {
    throw new Error('AEC execution gate requires a durable strict evidence log with atomic shared-head append and fork detection');
  }
  for (const method of ['reserve', 'commit']) {
    if (typeof consumption?.[method] !== 'function') {
      throw new Error(`AEC execution gate consumption store requires ${method}()`);
    }
  }
  if (typeof evidence?.record !== 'function') {
    throw new Error('AEC execution gate evidence log requires record()');
  }
  // Capture the methods that passed construction checks. Callers may retain the
  // objects for observability, but replacing a method later must not rewrite the
  // gate's replay or evidence semantics.
  const reserveConsumption = consumption.reserve.bind(consumption);
  const commitConsumption = consumption.commit.bind(consumption);
  const releaseConsumption = typeof consumption.release === 'function'
    ? consumption.release.bind(consumption) : null;
  const recordEvidence = evidence.record.bind(evidence);

  async function deny(reason, result = null, extra = {}) {
    let decision = null;
    try {
      const entry = {
        type: 'aec.execution.decision',
        at: instant(now),
        allow: false,
        reason,
        action_digest: result?.action_digest ?? null,
        requirement,
        human_floor: humanFloor,
        ...extra,
      };
      decision = await recordEvidence(entry);
      if (!validLogRecord(decision, !allowEphemeralState, entry)) throw new Error('malformed evidence record');
    } catch {
      return { ok: false, allow: false, reason: 'evidence_log_failed', result, decision: null };
    }
    return { ok: false, allow: false, reason, result, decision };
  }

  async function run(request = {}, effect) {
    if (typeof effect !== 'function') throw new Error('AEC execution gate run() requires an effect function');
    let chain;
    let expectedAction;
    try {
      if (!request || typeof request !== 'object' || Array.isArray(request)) {
        return deny('invalid_execution_request');
      }
      // Trust configuration belongs to the relying party at gate construction.
      // Accepting verifier code or trust keys beside presenter evidence lets the
      // presenter define the proof that its own evidence must pass.
      if (own(request, 'verifiers') || own(request, 'keysByType') || own(request, 'policiesByType')) {
        return deny('runtime_trust_configuration_refused');
      }
      chain = request.chain;
      expectedAction = request.expectedAction;
    } catch {
      return deny('invalid_execution_request');
    }
    const verificationTime = instant(now);
    if (!verificationTime) return deny('invalid_verification_time');
    let actionSnapshot;
    try { actionSnapshot = deepFreeze(structuredClone(expectedAction)); }
    catch { return deny('invalid_expected_action'); }

    const result = verifyAuthorizationChain(chain, {
      verifiers: pinnedVerifiers,
      keysByType: pinnedKeysByType,
      policiesByType: pinnedPolicies,
      requirement,
      expectedAction: actionSnapshot,
      verificationTime,
    });
    if (!result.satisfied) return deny('aec_refused', result, { reasons: result.reasons });
    if (!humanFloorSatisfied(result, humanFloor)) return deny('human_floor_unsatisfied', result);

    const key = consumptionKey(result);
    if (!key) return deny('missing_stable_consumption_key', result);

    let reserved;
    try { reserved = (await reserveConsumption(key)) === true; }
    catch { return deny('consumption_store_unavailable', result, { consumption_key: key }); }
    if (!reserved) return deny('replay_refused', result, { consumption_key: key });

    let authorization;
    try {
      const entry = {
        type: 'aec.execution.decision',
        at: verificationTime,
        allow: true,
        reason: 'allow',
        action_digest: result.action_digest,
        requirement,
        human_floor: humanFloor,
        consumption_key: key,
      };
      authorization = await recordEvidence(entry);
      if (!validLogRecord(authorization, !allowEphemeralState, entry)) throw new Error('malformed evidence record');
    } catch {
      try { if (releaseConsumption) await releaseConsumption(key); } catch { /* frozen is safe */ }
      return { ok: false, allow: false, reason: 'evidence_log_failed', result, decision: null };
    }

    let effectStarted = false;
    let committed = false;
    try {
      effectStarted = true;
      const value = await effect({ action: actionSnapshot, result, authorization });
      if ((await commitConsumption(key)) !== true) throw new Error('consumption_store_commit_refused');
      committed = true;
      const executionEntry = {
        type: 'aec.execution.outcome',
        at: instant(now),
        outcome: 'executed',
        authorizes_decision: authorization.hash,
        action_digest: result.action_digest,
        consumption_key: key,
      };
      const execution = await recordEvidence(executionEntry);
      if (!validLogRecord(execution, !allowEphemeralState, executionEntry)) throw new Error('malformed evidence record');
      return { ok: true, allow: true, value, result, authorization, execution };
    } catch (error) {
      if (effectStarted && !committed) {
        try { committed = (await commitConsumption(key)) === true; } catch { /* reservation remains fail-closed */ }
      }
      try {
        const indeterminateEntry = {
          type: 'aec.execution.outcome',
          at: instant(now),
          outcome: 'indeterminate',
          authorizes_decision: authorization.hash,
          action_digest: result.action_digest,
          consumption_key: key,
        };
        const indeterminate = await recordEvidence(indeterminateEntry);
        if (!validLogRecord(indeterminate, !allowEphemeralState, indeterminateEntry)) {
          throw new Error('malformed evidence record');
        }
      } catch { /* the original failure remains primary; replay is still blocked */ }
      throw error;
    }
  }

  return { run, evidence, store: consumption };
}

export const __aecExecutionSecurityInternals = Object.freeze({
  deepFreeze,
  validLogRecord,
  validComponent,
  humanFloorSatisfied,
  consumptionKey,
  instant,
});

export default { createAECExecutionGate };
