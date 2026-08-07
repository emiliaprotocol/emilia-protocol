// SPDX-License-Identifier: Apache-2.0
//
// Test fixtures: real EP-RECEIPT-v1 documents signed with a throwaway key and
// verified through the published verifier, so the suites exercise the real
// signature path rather than a stub that always says yes.

import crypto from 'node:crypto';

import { approvalActionHash, canonicalizeStrictJson } from '@emilia-protocol/require-receipt';

/** An in-memory atomic store that records every call, for release assertions. */
export function spyStore() {
  const states = new Map();
  const calls = [];
  return {
    calls,
    durable: false,
    ownershipFenced: true,
    async reserve(id) {
      calls.push(['reserve', id]);
      if (states.has(id)) return false;
      states.set(id, 'reserved');
      return true;
    },
    async commit(id) {
      calls.push(['commit', id]);
      if (states.get(id) !== 'reserved') throw new Error('consumption reservation not owned');
      states.set(id, 'committed');
      return true;
    },
    async release(id) {
      calls.push(['release', id]);
      if (states.get(id) !== 'reserved') throw new Error('consumption reservation not owned');
      states.delete(id);
      return true;
    },
    stateOf(id) {
      return states.get(id) ?? 'absent';
    },
    verbs() {
      return calls.map(([verb]) => verb);
    },
  };
}

export function mintReceipt(boundAction, canonicalAction, {
  outcome = 'allow_with_signoff',
  receiptId = `rcpt_${crypto.randomBytes(8).toString('hex')}`,
  createdAt = new Date().toISOString(),
  approver = 'jane@yourco.example',
  omitCanonicalAction = false,
} = {}) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const payload = {
    receipt_id: receiptId,
    subject: 'agent:autonomous',
    created_at: createdAt,
    claim: {
      action_type: boundAction,
      outcome,
      approver,
      ...(omitCanonicalAction ? {} : {
        canonical_action: JSON.parse(JSON.stringify(canonicalAction)),
        action_hash: approvalActionHash(canonicalAction),
      }),
    },
  };
  const value = crypto
    .sign(null, Buffer.from(canonicalizeStrictJson(payload), 'utf8'), privateKey)
    .toString('base64url');
  return {
    '@version': 'EP-RECEIPT-v1',
    payload,
    signature: { algorithm: 'Ed25519', value },
    public_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
  };
}

/** Base64 carrier form, exactly what travels in the proof header. */
export function carrierFor(receipt) {
  return Buffer.from(JSON.stringify(receipt), 'utf8').toString('base64');
}
