// SPDX-License-Identifier: Apache-2.0
//
// Collusion monitoring — graph analysis over the receipt-submission network to
// surface farmed-trust patterns the v2 scoring caps make EXPENSIVE but not
// impossible. This is the detection half (the economics half is policy, not
// code): periodic scan -> ring / bilateral-concentration / timing-anomaly
// findings -> suspicious-cluster events in the tamper-evident security ledger
// -> operator review. It never auto-penalizes; it flags for a human.
//
// Edge semantics: a receipt is `submitted_by -> entity_id` (a submitter vouches
// for a target). A ring A->B->C->D->E->A manufactures unique-submitter diversity
// while one actor controls every node; bilateral concentration is a small set of
// submitters supplying most of a target's evidence; timing anomalies are
// machine-cadence bursts no organic cohort produces.

type CollusionSeverity = 'high' | 'medium' | 'low';

interface CollusionFinding {
  type: string;
  severity: CollusionSeverity;
  members: string[];
  detail?: Record<string, unknown>;
}

const DEFAULTS = {
  ringMaxLen: 6, // A->...->A; rings longer than this read as organic, not a farm
  ringMinLen: 2, // a 2-cycle is a bilateral pair
  concentrationMinReceipts: 5, // ignore targets with too little evidence to judge
  concentrationDominantShare: 0.6, // one submitter supplying >=60% of a target's receipts
  concentrationMaxSubmitters: 3, // ...from <=3 distinct submitters total
  burstWindowMs: 60_000, // receipts from one submitter inside this window...
  burstCount: 5, // ...numbering >= this look automated
};

/** Build the directed submission graph from receipt rows. */
export function buildSubmissionGraph(receipts) {
  const out = new Map(); // from -> Map(to -> count)
  const inbound = new Map(); // to -> Map(from -> count)
  for (const r of receipts) {
    const from = r.submitted_by;
    const to = r.entity_id;
    if (!from || !to || from === to) continue; // self-vouch is handled elsewhere
    if (!out.has(from)) out.set(from, new Map());
    out.get(from).set(to, (out.get(from).get(to) || 0) + 1);
    if (!inbound.has(to)) inbound.set(to, new Map());
    inbound.get(to).set(from, (inbound.get(to).get(from) || 0) + 1);
  }
  return { out, inbound };
}

/** Mutual edges A<->B — the cheapest reciprocal-vouch pattern. */
export function detectBilateralPairs(graph) {
  const pairs: CollusionFinding[] = [];
  const seen = new Set();
  for (const [a, tos] of graph.out) {
    for (const b of tos.keys()) {
      if (graph.out.get(b)?.has(a)) {
        const key = [a, b].sort().join('|');
        if (seen.has(key)) continue;
        seen.add(key);
        pairs.push({ type: 'bilateral_pair', severity: 'medium', members: [a, b].sort() });
      }
    }
  }
  return pairs;
}

/** Directed cycles up to ringMaxLen — manufactured submitter diversity. */
export function detectRings(graph, opts = {}) {
  const { ringMaxLen, ringMinLen } = { ...DEFAULTS, ...opts };
  const rings: CollusionFinding[] = [];
  const seen = new Set();

  const record = (cycle) => {
    // canonical key: rotate so the smallest node is first, then stringify
    const min = cycle.indexOf([...cycle].sort()[0]);
    const rot = cycle.slice(min).concat(cycle.slice(0, min));
    const key = rot.join('>');
    if (seen.has(key)) return;
    seen.add(key);
    rings.push({
      type: 'submission_ring',
      severity: cycle.length >= 4 ? 'high' : 'medium', // longer rings = more deliberate camouflage
      members: rot,
      detail: { length: cycle.length },
    });
  };

  const dfs = (start, node, path) => {
    if (path.length > ringMaxLen) return;
    for (const next of graph.out.get(node)?.keys() || []) {
      if (next === start && path.length >= ringMinLen) {
        record(path);
      } else if (!path.includes(next) && path.length < ringMaxLen) {
        dfs(start, next, [...path, next]);
      }
    }
  };

  for (const start of graph.out.keys()) dfs(start, start, [start]);
  return rings;
}

/** Targets whose evidence comes from a tiny, dominant submitter set. */
export function detectConcentration(receipts, opts = {}) {
  const { concentrationMinReceipts, concentrationDominantShare, concentrationMaxSubmitters } = {
    ...DEFAULTS,
    ...opts,
  };
  const byTarget = new Map(); // to -> Map(from -> count)
  for (const r of receipts) {
    if (!r.entity_id || !r.submitted_by || r.entity_id === r.submitted_by) continue;
    if (!byTarget.has(r.entity_id)) byTarget.set(r.entity_id, new Map());
    const m = byTarget.get(r.entity_id);
    m.set(r.submitted_by, (m.get(r.submitted_by) || 0) + 1);
  }
  const findings: CollusionFinding[] = [];
  for (const [target, submitters] of byTarget) {
    const total = [...submitters.values()].reduce((a, b) => a + b, 0);
    if (total < concentrationMinReceipts) continue;
    const top = Math.max(...submitters.values());
    const share = top / total;
    if (share >= concentrationDominantShare || submitters.size <= concentrationMaxSubmitters) {
      findings.push({
        type: 'submitter_concentration',
        severity: share >= concentrationDominantShare && submitters.size <= concentrationMaxSubmitters ? 'high' : 'medium',
        members: [target],
        detail: { total_receipts: total, distinct_submitters: submitters.size, top_submitter_share: Number(share.toFixed(2)) },
      });
    }
  }
  return findings;
}

/** Per-submitter bursts — machine cadence no organic cohort produces. */
export function detectTimingAnomalies(receipts, opts = {}) {
  const { burstWindowMs, burstCount } = { ...DEFAULTS, ...opts };
  const bySubmitter = new Map();
  for (const r of receipts) {
    if (!r.submitted_by || !r.created_at) continue;
    const t = Date.parse(r.created_at);
    if (Number.isNaN(t)) continue;
    if (!bySubmitter.has(r.submitted_by)) bySubmitter.set(r.submitted_by, []);
    bySubmitter.get(r.submitted_by).push(t);
  }
  const findings: CollusionFinding[] = [];
  for (const [submitter, times] of bySubmitter) {
    times.sort((a, b) => a - b);
    // sliding window: max receipts within any burstWindowMs
    let maxInWindow = 0;
    let lo = 0;
    for (let hi = 0; hi < times.length; hi += 1) {
      while (times[hi] - times[lo] > burstWindowMs) lo += 1;
      maxInWindow = Math.max(maxInWindow, hi - lo + 1);
    }
    if (maxInWindow >= burstCount) {
      findings.push({
        type: 'timing_burst',
        severity: 'medium',
        members: [submitter],
        detail: { max_in_window: maxInWindow, window_ms: burstWindowMs },
      });
    }
  }
  return findings;
}

/** Run all detectors. Returns a flat, severity-ranked findings array. */
export function scanCollusion(receipts, opts = {}) {
  const graph = buildSubmissionGraph(receipts || []);
  const findings = [
    ...detectRings(graph, opts),
    ...detectBilateralPairs(graph),
    ...detectConcentration(receipts || [], opts),
    ...detectTimingAnomalies(receipts || [], opts),
  ];
  const rank = { high: 0, medium: 1, low: 2 };
  findings.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
  return findings;
}
