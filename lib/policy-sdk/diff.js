/**
 * EP Policy Semantic Diff
 *
 * Produces a structured diff between two policy versions. Every field change
 * is classified by risk: 'tightening' (reduces accept set), 'loosening'
 * (enlarges accept set), or 'neutral' (reorganization without behavioral
 * effect).
 *
 * Use cases:
 *   - Review gate: block PRs that loosen a production policy without an ADR.
 *   - Changelog generation: auto-draft the human-readable delta.
 *   - Migration planning: estimate which active handshakes would evaluate
 *     differently under the new policy.
 *
 * The diff is purely structural — it does not run scenarios. For behavioral
 * coverage, combine with simulator.js against a canonical scenario suite.
 *
 * @license Apache-2.0
 */

import { ASSURANCE_RANK } from '@/lib/handshake/invariants.js';

/**
 * Classify a single field change.
 *
 * @param {string} path
 * @param {unknown} before
 * @param {unknown} after
 * @returns {{ path: string, before: unknown, after: unknown, risk: 'loosening'|'tightening'|'neutral', rationale: string }}
 */
function classifyChange(path, before, after) {
  // nonce_required / payload_hash_required: true → false is loosening.
  // Non-boolean values on these fields are flagged separately — they should
  // never reach production (the handshake-layer validator rejects them) but
  // they do leak in from malformed YAML / JSON editors.
  if (path.endsWith('.nonce_required') || path.endsWith('.payload_hash_required')) {
    if (before === true && after === false) {
      return { path, before, after, risk: 'loosening', rationale: `${path} went from required to optional — removes a replay/binding guard.` };
    }
    if (before === false && after === true) {
      return { path, before, after, risk: 'tightening', rationale: `${path} is now required — adds a guard.` };
    }
    // true → undefined/missing is equivalent to disabling the guard.
    if (before === true && (after === undefined || after === null)) {
      return { path, before, after, risk: 'loosening', rationale: `${path} key removed — guard no longer declared, effectively disabled.` };
    }
    // Non-boolean in either slot is a malformed policy — flag as loosening since
    // the handshake validator will reject it and the binding will fail closed,
    // but the fact that a malformed policy was authored is a review signal.
    const nonBoolean = typeof before !== 'boolean' || typeof after !== 'boolean';
    if (nonBoolean && !(before === undefined || after === undefined)) {
      return { path, before, after, risk: 'loosening', rationale: `${path} has non-boolean value (${typeof before} → ${typeof after}); policy is malformed and will fail structural validation.` };
    }
  }

  // expiry_minutes: increased = loosening, decreased = tightening.
  if (path.endsWith('.expiry_minutes') && typeof before === 'number' && typeof after === 'number') {
    if (after > before) return { path, before, after, risk: 'loosening', rationale: `expiry increased ${before}m → ${after}m — widens replay window.` };
    if (after < before) return { path, before, after, risk: 'tightening', rationale: `expiry decreased ${before}m → ${after}m — narrows replay window.` };
  }

  // minimum_assurance: lowered = loosening, raised = tightening.
  if (path.endsWith('.minimum_assurance')) {
    const b = ASSURANCE_RANK[before];
    const a = ASSURANCE_RANK[after];
    if (b !== undefined && a !== undefined) {
      if (a < b) return { path, before, after, risk: 'loosening', rationale: `assurance lowered ${before} → ${after}.` };
      if (a > b) return { path, before, after, risk: 'tightening', rationale: `assurance raised ${before} → ${after}.` };
    }
  }

  // required_claims: removed claims = loosening, added = tightening.
  if (path.endsWith('.required_claims') && Array.isArray(before) && Array.isArray(after)) {
    const beforeSet = new Set(before);
    const afterSet = new Set(after);
    const removed = [...beforeSet].filter(c => !afterSet.has(c));
    const added = [...afterSet].filter(c => !beforeSet.has(c));
    if (removed.length && !added.length) return { path, before, after, risk: 'loosening', rationale: `removed required claims: ${removed.join(', ')}.` };
    if (added.length && !removed.length) return { path, before, after, risk: 'tightening', rationale: `added required claims: ${added.join(', ')}.` };
    if (added.length && removed.length) return { path, before, after, risk: 'loosening', rationale: `claim set changed (removed: ${removed.join(', ')}; added: ${added.join(', ')}) — loosening unless the new claims are strictly stronger.` };
  }

  // Default: treat as neutral, but surface.
  return { path, before, after, risk: 'neutral', rationale: 'Field changed but risk direction not classified. Review manually.' };
}

/**
 * Recursively walk two objects and emit changes.
 */
function walk(pathPrefix, a, b, out) {
  // Handle addition/removal of entire subtrees.
  if (a === undefined && b !== undefined) {
    // Addition: default tightening if it's a new constraint, loosening if it removes something.
    // We conservatively classify new constraints as 'neutral' because "tightening" implies
    // a previous state — but structurally, adding a constraint to nothing means nothing
    // was enforced before, which is loosening. Cover the common cases:
    if (pathPrefix.endsWith('.nonce_required') || pathPrefix.endsWith('.payload_hash_required')) {
      out.push({ path: pathPrefix, before: undefined, after: b, risk: b ? 'tightening' : 'loosening', rationale: `new field ${pathPrefix} set to ${b}.` });
    } else if (pathPrefix.endsWith('.required_parties')) {
      out.push({ path: pathPrefix, before: undefined, after: b, risk: 'tightening', rationale: `required_parties introduced (previously no party requirement).` });
    } else {
      out.push({ path: pathPrefix, before: undefined, after: b, risk: 'neutral', rationale: 'field added.' });
    }
    return;
  }
  if (a !== undefined && b === undefined) {
    // Removal of a guard is almost always loosening.
    if (pathPrefix.endsWith('.nonce_required') || pathPrefix.endsWith('.payload_hash_required')) {
      out.push({ path: pathPrefix, before: a, after: undefined, risk: 'loosening', rationale: `${pathPrefix} removed — guard no longer enforced.` });
    } else if (pathPrefix.endsWith('.required_parties')) {
      out.push({ path: pathPrefix, before: a, after: undefined, risk: 'loosening', rationale: `required_parties removed — any party configuration now passes.` });
    } else {
      out.push({ path: pathPrefix, before: a, after: undefined, risk: 'neutral', rationale: 'field removed.' });
    }
    return;
  }

  if (a === b) return;

  const sameType = typeof a === typeof b && Array.isArray(a) === Array.isArray(b);
  if (sameType && a !== null && typeof a === 'object' && !Array.isArray(a)) {
    // Recurse into objects.
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    for (const k of keys) walk(pathPrefix ? `${pathPrefix}.${k}` : k, a[k], b[k], out);
    return;
  }

  // Primitives or mismatched shapes — classify directly.
  out.push(classifyChange(pathPrefix, a, b));
}

/**
 * Compute a semantic diff between two policy rules objects.
 *
 * @param {object} before - The prior policy.rules
 * @param {object} after  - The new policy.rules
 * @returns {{
 *   changes: Array,
 *   risk: 'loosening' | 'tightening' | 'neutral',
 *   summary: { loosening: number, tightening: number, neutral: number },
 * }}
 */
export function diffPolicy(before, after) {
  const out = [];
  walk('', before || {}, after || {}, out);

  const summary = { loosening: 0, tightening: 0, neutral: 0 };
  for (const c of out) summary[c.risk] = (summary[c.risk] || 0) + 1;

  // Overall diff classification:
  //   any loosening → 'loosening'
  //   only tightening → 'tightening'
  //   else → 'neutral'
  let overall = 'neutral';
  if (summary.loosening > 0) overall = 'loosening';
  else if (summary.tightening > 0) overall = 'tightening';

  return { changes: out, risk: overall, summary };
}

/**
 * Format a diff as a human-readable string.
 *
 * @param {ReturnType<typeof diffPolicy>} diff
 */
export function formatDiff(diff) {
  if (diff.changes.length === 0) return 'Policy diff: no changes.';
  const lines = [
    `Policy diff: ${diff.risk.toUpperCase()} (${diff.summary.loosening} loosening, ${diff.summary.tightening} tightening, ${diff.summary.neutral} neutral)`,
    '',
  ];
  for (const c of diff.changes) {
    const marker = c.risk === 'loosening' ? '🚨' : c.risk === 'tightening' ? '🔒' : '•';
    lines.push(`  ${marker} ${c.path}`);
    lines.push(`     ${c.rationale}`);
  }
  return lines.join('\n');
}
