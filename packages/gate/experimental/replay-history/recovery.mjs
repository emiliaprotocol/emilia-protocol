// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';

const VERSION = 'EP-REPLAY-CHECKPOINT-v1';
const digest = value => `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`;
const text = value => typeof value === 'string' && value.length > 0 && value.length <= 4096;
const hash = value => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
const uncertain = reason => Object.freeze({ status: 'REPLAY_HISTORY_UNCERTAIN', reason });

/** Full exact set commitment, deliberately not a compact Merkle proof format. */
export function membershipRoot(identities) {
  if (!Array.isArray(identities) || identities.some(x => !text(x))
      || new Set(identities).size !== identities.length) throw new Error('invalid_membership');
  return digest([...identities].sort());
}

export function checkpointDigest(checkpoint) {
  return digest(checkpointBody(checkpoint));
}

function checkpointBody(c) {
  if (!c || c.version !== VERSION || !text(c.stream) || !text(c.namespace_epoch)
      || !Number.isSafeInteger(c.covered_through) || c.covered_through < 0
      || !hash(c.root_digest) || !hash(c.previous_checkpoint_digest)) throw new Error('invalid_checkpoint');
  return [c.version, c.stream, c.namespace_epoch, c.covered_through,
    c.root_digest, c.previous_checkpoint_digest];
}

/**
 * Recovery-only evaluator. readVerifiedLatest must authenticate a fresh latest
 * head using relying-party pins, outside the operational store's restore and
 * deletion authority. It must reject invalid receipts, equivocation, unavailable
 * anchors and incomplete continuity. Passing a local copy violates this contract.
 * Snapshot must contain EVERY consumed native identity through the current head.
 * COMPLETE is evidence for recovery, never a consume receipt or dispatch permit.
 */
export async function evaluateReplayRecovery(input) {
  try {
    const { snapshot, expected, identity, readVerifiedLatest } = input;
    // Copy caller data before the asynchronous anchor read to avoid mutation races.
    const s = structuredClone(snapshot);
    const e = structuredClone(expected);
    if (!text(identity) || !text(e.stream) || !text(e.namespace_epoch) || !text(e.anchor_id)) {
      return uncertain('invalid_expected_scope');
    }
    const c = s.checkpoint;
    const localDigest = checkpointDigest(c);
    if (c.stream !== e.stream || c.namespace_epoch !== e.namespace_epoch) return uncertain('namespace_mismatch');
    if (membershipRoot(s.consumed_identities) !== c.root_digest) return uncertain('root_mismatch');
    const head = await readVerifiedLatest(Object.freeze({ ...e }));
    if (!head || head.anchor_id !== e.anchor_id
        || head.stream !== e.stream || head.namespace_epoch !== e.namespace_epoch
        || !Number.isSafeInteger(head.covered_through) || !hash(head.checkpoint_digest)) {
      return uncertain('anchor_unverified');
    }
    if (head.covered_through !== c.covered_through || head.checkpoint_digest !== localDigest) {
      return uncertain('anchor_head_mismatch');
    }
    return Object.freeze({ status: 'REPLAY_HISTORY_COMPLETE', namespace_epoch: c.namespace_epoch,
      covered_through: c.covered_through, root_digest: c.root_digest,
      checkpoint_digest: localDigest, anchor_id: e.anchor_id,
      membership: s.consumed_identities.includes(identity) ? 'CONSUMED' : 'ABSENT',
      dispatch_permitted: false });
  } catch {
    return uncertain('history_unavailable_or_malformed');
  }
}

/**
 * Recovery-to-consumption ordering wrapper, NOT an authorization evaluator.
 * atomicConsume is a relying-party-owned live authoritative service. It MUST
 * atomically compare the supplied recovered head with its current head and
 * durably consume identity exactly once, binding the exact action digest.
 * It returns null on conflict. Throws/lost acknowledgement are burned/uncertain;
 * this wrapper never retries or refunds. A receipt from this trusted service
 * is distinct from an asynchronous anchor checkpoint.
 */
export async function consumeRecoveredIdentity(input, dependencies) {
  try {
  const { atomicConsume } = dependencies;
    const identity = input.identity;
    const actionDigest = input.action_digest;
    const expected = structuredClone(input.expected);
    if (!hash(actionDigest)) return uncertain('invalid_action_binding');
    const recovered = await evaluateReplayRecovery({ ...input, identity, expected });
    if (recovered.status !== 'REPLAY_HISTORY_COMPLETE') return recovered;
    if (recovered.membership === 'CONSUMED') return Object.freeze({ status: 'REPLAY_CONSUMED' });
    const request = Object.freeze({ ...expected, identity, action_digest: actionDigest,
      expected_checkpoint_digest: recovered.checkpoint_digest,
      expected_covered_through: recovered.covered_through });
    const receipt = await atomicConsume(request);
    if (receipt === null) return Object.freeze({ status: 'REPLAY_CONSUMED_OR_HEAD_CHANGED' });
    if (!receipt || receipt.identity !== identity || receipt.action_digest !== actionDigest
        || receipt.stream !== expected.stream || receipt.namespace_epoch !== expected.namespace_epoch
        || receipt.previous_checkpoint_digest !== recovered.checkpoint_digest
        || !Number.isSafeInteger(receipt.sequence) || receipt.sequence !== recovered.covered_through + 1) {
      return uncertain('consume_receipt_invalid');
    }
    return Object.freeze({ status: 'REPLAY_CONSUMED_NOW', receipt: Object.freeze(structuredClone(receipt)) });
  } catch {
    return uncertain('consume_outcome_unknown');
  }
}
