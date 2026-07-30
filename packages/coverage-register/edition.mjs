/**
 * EP-COVERAGE-EDITION-v1 — build one dated, reproducible edition of the
 * Agent Authorization Coverage register from a registry snapshot.
 *
 * Deterministic by construction: the same snapshot in produces byte-identical
 * output. No clock is read here and no network call is made here. The edition
 * date comes from the snapshot's own provenance, so a published edition can be
 * re-derived by anybody, years later, from the snapshot alone.
 */

import crypto from 'node:crypto';
import { deriveVerdict, boilerplateDigest } from './verdict.mjs';
import { CATEGORIES, RUBRIC_VERSION, rubricIntegrityProblems } from './rubric.mjs';

export const EDITION_PROFILE = 'EP-COVERAGE-EDITION-v1';

/**
 * Registry records arrive one row per published version. Keep the row the
 * registry itself marks latest; fall back to the newest publishedAt when no row
 * is flagged, so a target is never silently dropped.
 */
export function selectLatest(rows) {
  const byName = new Map();
  for (const row of rows) {
    const server = row?.server;
    const meta = row?._meta?.['io.modelcontextprotocol.registry/official'] ?? {};
    const name = server?.name;
    if (!name) continue;
    const candidate = { server, status: meta.status ?? null, isLatest: meta.isLatest === true, publishedAt: meta.publishedAt ?? '' };
    const held = byName.get(name);
    if (!held) { byName.set(name, candidate); continue; }
    if (candidate.isLatest && !held.isLatest) { byName.set(name, candidate); continue; }
    if (candidate.isLatest === held.isLatest && candidate.publishedAt > held.publishedAt) byName.set(name, candidate);
  }
  return [...byName.values()].sort((a, b) => (a.server.name < b.server.name ? -1 : a.server.name > b.server.name ? 1 : 0));
}

/** Deterministic JSON: object keys sorted at every level. */
export function canonicalJson(value) {
  return JSON.stringify(sortDeep(value), null, 2) + '\n';
}

function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === 'object') {
    return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortDeep(v[k])]));
  }
  return v;
}

/**
 * PUBLICATION GATE.
 *
 * Machine classification of a one-line registry description is roughly 80%
 * precise, measured by hand on the first live 200-row sample: 4 of 5 findings
 * were correct and the fifth read "debug deployment" as a deploy capability. One
 * wrong dated verdict about a named company costs more than this entire register
 * is worth, so no target is ever published on machine output alone.
 *
 * Every finding starts as `candidate`. A human moves it to `confirmed` by
 * reading the declaration, or to `rejected`. Only `confirmed` findings may
 * appear in a published edition, which is the same discipline already used for
 * the six verified Fire Drill reports.
 */
export const REVIEW_STATES = Object.freeze(['candidate', 'confirmed', 'rejected']);

/**
 * @param {object} snapshot
 * @param {object} [opts]
 * @param {Record<string,'confirmed'|'rejected'>} [opts.review] target -> state
 */
export function buildEdition(snapshot, opts = {}) {
  const problems = rubricIntegrityProblems();
  if (problems.length) throw new Error(`rubric integrity: ${problems.join('; ')}`);

  const asOf = snapshot?.provenance?.as_of;
  if (!asOf) throw new Error('snapshot is missing provenance.as_of; refusing to build an undated edition');

  const latest = selectLatest(snapshot.rows ?? []);
  const targets = latest.map(({ server, status }) => {
    const v = deriveVerdict(server, asOf);
    const reviewed = opts.review?.[server.name] ?? null;
    if (reviewed && !REVIEW_STATES.includes(reviewed)) {
      throw new Error(`unknown review state ${JSON.stringify(reviewed)} for ${server.name}`);
    }
    return {
      target: server.name,
      review_state: v.is_finding ? (reviewed ?? 'candidate') : 'not_applicable',
      boilerplate_digest: boilerplateDigest(server),
      title: server.title ?? null,
      registry_status: status,
      verdict: v.verdict,
      is_finding: v.is_finding,
      sentence: v.sentence,
      categories: v.categories,
      evidence: v.evidence,
      authorization_evidence: v.authorization_evidence ?? [],
      declaration_digest: v.declaration_digest,
      remedy: v.remedy,
    };
  });

  // One vendor publishing the same boilerplate across many servers inflates
  // every count. On the first live sample, eight targets shared one description.
  // Report distinct declarations alongside target counts so a reader can never
  // mistake repeated boilerplate for independent evidence.
  const clusterSize = new Map();
  for (const t of targets) clusterSize.set(t.boilerplate_digest, (clusterSize.get(t.boilerplate_digest) ?? 0) + 1);
  for (const t of targets) {
    const n = clusterSize.get(t.boilerplate_digest);
    if (n > 1) t.declaration_cluster = { size: n, note: 'identical declaration text published across multiple targets' };
  }

  const counts = { total: targets.length, distinct_declarations: clusterSize.size };
  counts.findings_candidate = targets.filter((t) => t.review_state === 'candidate').length;
  counts.findings_confirmed = targets.filter((t) => t.review_state === 'confirmed').length;
  counts.findings_rejected = targets.filter((t) => t.review_state === 'rejected').length;
  counts.publishable = counts.findings_confirmed;
  for (const key of ['NO_CONSEQUENTIAL_ACTION_DECLARED', 'DECLARED_AUTHORIZATION', 'DECLARATION_SILENT', 'INDETERMINATE']) {
    counts[key] = targets.filter((t) => t.verdict === key).length;
  }
  counts.findings_distinct_declarations = new Set(
    targets.filter((t) => t.is_finding).map((t) => t.boilerplate_digest),
  ).size;

  const by_category = {};
  for (const c of CATEGORIES) {
    const matched = targets.filter((t) => t.categories.includes(c.id));
    by_category[c.id] = {
      label: c.label,
      assurance_class: c.assurance_class,
      declared: matched.length,
      declared_with_authorization: matched.filter((t) => t.verdict === 'DECLARED_AUTHORIZATION').length,
      pct_of_corpus: counts.total ? Number(((100 * matched.length) / counts.total).toFixed(2)) : 0,
    };
  }

  const edition = {
    '@version': EDITION_PROFILE,
    rubric: RUBRIC_VERSION,
    as_of: asOf,
    provenance: snapshot.provenance,
    scope_limit:
      'Every verdict in this edition is a statement about a declaration as published to the public MCP registry on the stated date. No target was contacted, probed, or invoked. Registry-declaration signal is strictly weaker than a tool-level scan: a target whose runtime does require human approval, but whose published declaration does not say so, is recorded as DECLARATION_SILENT and that sentence remains true.',
    publication_state:
      targets.some((t) => t.review_state === 'candidate')
        ? 'DRAFT — contains unreviewed candidate findings. Not publishable. Every finding must be confirmed or rejected by a human reading the declaration before this edition may be published.'
        : 'REVIEWED — every finding in this edition was confirmed by human review.',
    correction_policy:
      'Challenges are corrected publicly within 24 hours or the verdict is withdrawn. Every verdict carries the exact declaration digest assessed and the quoted span that produced it, so any target can re-derive or dispute it with the reproduce command.',
    counts,
    by_category,
    targets,
  };
  edition.edition_digest = `sha256:${crypto.createHash('sha256').update(canonicalJson({ ...edition, edition_digest: undefined }), 'utf8').digest('hex')}`;
  return edition;
}

/** Re-derive from the snapshot and compare against a published edition. */
export function reproduce(snapshot, published) {
  const rebuilt = buildEdition(snapshot);
  const drift = [];
  if (rebuilt.edition_digest !== published.edition_digest) {
    drift.push(`edition_digest differs: rebuilt ${rebuilt.edition_digest} vs published ${published.edition_digest}`);
  }
  const pubByTarget = new Map((published.targets ?? []).map((t) => [t.target, t]));
  for (const t of rebuilt.targets) {
    const p = pubByTarget.get(t.target);
    if (!p) { drift.push(`target present in rebuild but not in published edition: ${t.target}`); continue; }
    if (p.verdict !== t.verdict) drift.push(`${t.target}: verdict ${p.verdict} -> ${t.verdict}`);
    if (p.declaration_digest !== t.declaration_digest) drift.push(`${t.target}: declaration digest changed`);
  }
  return { reproduced: drift.length === 0, drift, rebuilt };
}
