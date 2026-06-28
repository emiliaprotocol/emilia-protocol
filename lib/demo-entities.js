// SPDX-License-Identifier: Apache-2.0
//
// Synthetic demo fixtures that PUBLIC surfaces (the /demo page) may evaluate
// without authentication. Every other entity requires auth — this allowlist is
// the recon boundary that keeps the public demo working end-to-end without
// re-opening a free trust-evaluation API over real entities. Mirrors the
// demo-receipt carve-out (isDemoReceiptId) used by /api/demo/*/evidence.

export const DEMO_ENTITY_IDS = new Set(['mcp-server-ep-v1']);

export function isDemoEntity(entityId) {
  return typeof entityId === 'string' && DEMO_ENTITY_IDS.has(entityId);
}
