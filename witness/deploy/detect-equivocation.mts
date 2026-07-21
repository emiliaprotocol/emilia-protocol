#!/usr/bin/env node
/**
 * EP Witness: cross-view equivocation detector (the "gossip" half).
 *
 * The witness EMITTER (witness/server.mjs) and the local quorum check
 * (requireWitnessQuorum in @emilia-protocol/verify) together let ONE verifier
 * confirm that k distinct pinned witnesses cosigned the ONE head it holds. That
 * is the SINGLE-VIEW half. It cannot, on its own, see that the log showed a
 * DIFFERENT head to someone else.
 *
 * This module is the CROSS-VIEW half the README names as "the deploying party's
 * job": given two or more independently-collected views (each a checkpoint the
 * viewer accepted plus the witness cosignatures it gathered), it detects
 * EQUIVOCATION, the same log presenting two conflicting heads at the SAME
 * tree_size, each backed by a valid witness quorum.
 *
 * WHY THIS IS SOUND (and what it does NOT claim)
 *   A witness is honest: it signs whatever committed bytes it was shown. A
 *   MALICIOUS LOG equivocates by showing head A to one partition and head B to
 *   another at the same tree_size. Because witnesses cosign what they see, valid
 *   quorum-backed cosignature sets can exist for BOTH heads. No single verifier
 *   detects this. When two verifiers gossip their views here, a single
 *   (log_key_id, tree_size) carrying two distinct root_hashes, each meeting the
 *   witness quorum, is cryptographic proof the LOG equivocated. It does NOT
 *   accuse the witnesses (they behaved correctly); it convicts the log.
 *
 *   It is fail-closed on inputs but makes no CURRENCY claim: it reports
 *   equivocation among the views it was given, nothing about which head (if any)
 *   is the log's latest.
 *
 * Uses ONLY @emilia-protocol/verify (requireWitnessQuorum). No new crypto.
 *
 * @license Apache-2.0
 */

import { requireWitnessQuorum } from '../../packages/verify/witness.js';

const HASH_PREFIX = /^sha256:/i;
const hexOf = (h) => String(h || '').replace(HASH_PREFIX, '').toLowerCase();

/**
 * @typedef {{ checkpoint: object, cosignatures: object[], label?: string }} View
 *   One independently-collected observation: the checkpoint a viewer accepted
 *   and the witness cosignatures it gathered for that head. `label` is an
 *   optional human tag (e.g. "verifier-A") echoed in the report.
 */

/**
 * Detect log equivocation across independently-collected views.
 *
 * @param {View[]} views  two or more views to compare (gossip set).
 * @param {Array<{witness_id:string, public_key:string}>} pinnedWitnessKeys  the
 *   witnesses every viewer pins. A head "counts" only if >= k DISTINCT pinned
 *   witnesses validly cosigned it.
 * @param {number} k  witness-quorum threshold (integer >= 1).
 * @returns {{
 *   equivocation: boolean,
 *   conflicts: Array<{
 *     log_key_id: string, tree_size: number,
 *     heads: Array<{ root_hash: string, labels: string[], witness_ids: string[] }>,
 *     overlapping_witness_ids: string[]
 *   }>,
 *   quorum_backed_heads: number,
 *   reasons: string[]
 * }}
 *   `equivocation` is true iff some (log_key_id, tree_size) has >1 distinct
 *   root_hash among quorum-backed views. `overlapping_witness_ids` are the
 *   witnesses that cosigned MORE THAN ONE of the conflicting heads, the
 *   strongest proof, since one witness's signatures over two different roots at
 *   one tree_size cannot both describe a single honest head.
 */
export function detectEquivocation(views, pinnedWitnessKeys, k) {
  const reasons: string[] = [];
  if (!Array.isArray(views)) {
    return { equivocation: false, conflicts: [], quorum_backed_heads: 0, reasons: ['views must be an array'] };
  }
  if (!Array.isArray(pinnedWitnessKeys)) {
    return { equivocation: false, conflicts: [], quorum_backed_heads: 0, reasons: ['pinnedWitnessKeys must be an array'] };
  }

  // Keep only views whose held head clears the local witness quorum. A view that
  // cannot meet quorum is not a head anyone would have accepted, so it cannot be
  // used to convict the log. This reuses the exact single-view check verifiers run.
  const accepted: any[] = [];
  views.forEach((v, i) => {
    const label = (v && typeof v.label === 'string' && v.label) || `view#${i}`;
    if (!v || typeof v.checkpoint !== 'object' || v.checkpoint === null) {
      reasons.push(`${label}: missing checkpoint (skipped)`);
      return;
    }
    const q = requireWitnessQuorum(v.checkpoint, v.cosignatures || [], pinnedWitnessKeys, k);
    if (!q.ok) {
      reasons.push(`${label}: head tree_size=${v.checkpoint.tree_size} did not meet witness quorum (${q.met}/${q.required}); not counted`);
      return;
    }
    accepted.push({
      label,
      log_key_id: v.checkpoint.log_key_id,
      tree_size: v.checkpoint.tree_size,
      root_hash: hexOf(v.checkpoint.root_hash),
      witness_ids: q.witness_ids,
    });
  });

  // Group quorum-backed heads by (log_key_id, tree_size). More than one distinct
  // root_hash in a group is equivocation: the log committed two different heads
  // at one size, each with independent-witness backing.
  const byPosition = new Map<string, any>();
  for (const a of accepted) {
    const key = JSON.stringify([a.log_key_id, a.tree_size]);
    if (!byPosition.has(key)) {
      byPosition.set(key, {
        log_key_id: a.log_key_id,
        tree_size: a.tree_size,
        heads: new Map(),
      });
    }
    const { heads } = byPosition.get(key);
    if (!heads.has(a.root_hash)) heads.set(a.root_hash, { labels: [], witnessSet: new Set() });
    const h = heads.get(a.root_hash);
    h.labels.push(a.label);
    a.witness_ids.forEach((w) => h.witnessSet.add(w));
  }

  const conflicts: any[] = [];
  for (const { log_key_id, tree_size, heads } of byPosition.values()) {
    if (heads.size < 2) continue;
    const headArr = [...heads.entries()].map(([root_hash, h]) => ({
      root_hash,
      labels: h.labels,
      witness_ids: [...h.witnessSet].sort(),
    }));
    // Witnesses that appear under MORE THAN ONE conflicting root at this size.
    const witnessCount = new Map();
    for (const h of headArr) for (const w of h.witness_ids) witnessCount.set(w, (witnessCount.get(w) || 0) + 1);
    const overlapping_witness_ids = [...witnessCount.entries()].filter(([, c]) => c > 1).map(([w]) => w).sort();
    conflicts.push({
      log_key_id,
      tree_size,
      heads: headArr,
      overlapping_witness_ids,
    });
  }

  return {
    equivocation: conflicts.length > 0,
    conflicts,
    quorum_backed_heads: accepted.length,
    reasons,
  };
}

// CLI: node detect-equivocation.mjs <views.json> <pinned.json> <k>
// views.json  = [{ checkpoint, cosignatures, label? }, ...]
// pinned.json = [{ witness_id, public_key }, ...]
function main() {
  const [viewsPath, pinnedPath, kArg] = process.argv.slice(2);
  if (!viewsPath || !pinnedPath || !kArg) {
    console.error('usage: node detect-equivocation.mjs <views.json> <pinned.json> <k>');
    process.exit(2);
  }
  const fs = require('node:fs');
  const views = JSON.parse(fs.readFileSync(viewsPath, 'utf8'));
  const pinned = JSON.parse(fs.readFileSync(pinnedPath, 'utf8'));
  const res = detectEquivocation(views, pinned, Number(kArg));
  console.log(JSON.stringify(res, null, 2));
  process.exit(res.equivocation ? 1 : 0); // exit 1 signals detection to callers/CI
}

if (import.meta.url === `file://${process.argv[1]}`) {
  // dynamic require for CLI-only fs read in an ESM file
  const { createRequire } = await import('node:module');
  globalThis.require = createRequire(import.meta.url);
  main();
}
