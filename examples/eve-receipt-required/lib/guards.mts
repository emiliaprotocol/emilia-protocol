// SPDX-License-Identifier: Apache-2.0
//
// Receipt-Required guards for this Eve agent's dangerous tools.
//
// One gate per irreversible action. Both the Eve tool files (agent/tools/*.ts) and
// the local demo (demo.mjs) import these, so what you demo is exactly what runs.
//
// Zero dependency: this composes lib/emilia-gate.mjs (Node crypto only).

import { makeReceiptGate } from './emilia-gate.mjs';

// Issuer keys you trust, as comma-separated base64url SPKI. In production, set
// EMILIA_TRUSTED_KEYS and DO NOT rely on inline keys. With no trusted keys
// configured we fall back to allowInlineKey so the demo runs out of the box —
// that proves integrity, not WHO authorized, so it is demo-only.
const trustedKeys = (process.env.EMILIA_TRUSTED_KEYS || '').split(',').map((s) => s.trim()).filter(Boolean);
const demoMode = trustedKeys.length === 0;

/** Release funds — receipt bound to funds.release:<destination>. */
export const releaseFundsGate = makeReceiptGate({
  action: 'funds.release',
  trustedKeys,
  allowInlineKey: demoMode,
  maxAgeSec: 900,
});

/** Delete a repository — receipt bound to repo.delete:<owner/name>. */
export const deleteRepoGate = makeReceiptGate({
  action: 'repo.delete',
  trustedKeys,
  allowInlineKey: demoMode,
  maxAgeSec: 900,
});

export { demoMode };
