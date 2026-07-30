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
import { deriveVerdict, boilerplateDigest, applyHumanReview } from './verdict.mjs';
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
    if (candidate.isLatest === held.isLatest && candidate.publishedAt > held.publishedAt) { byName.set(name, candidate); continue; }
    if (candidate.isLatest === held.isLatest && candidate.publishedAt === held.publishedAt
      && canonicalJson(candidate) > canonicalJson(held)) byName.set(name, candidate);
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
 * Every machine match starts as a non-finding candidate. A human moves it to
 * `confirmed` or `rejected` with a review record bound to the assessed text.
 * Publication remains a separate, assessment-bound approval.
 */
export const REVIEW_STATES = Object.freeze(['confirmed', 'rejected']);

function normalizeReview(target, verdict, review) {
  if (review === null || review === undefined) return null;
  if (!review || typeof review !== 'object' || Array.isArray(review)) {
    throw new Error(`review for ${target} must be an object bound to the assessed declaration`);
  }
  if (!REVIEW_STATES.includes(review.state)) {
    throw new Error(`unknown review state ${JSON.stringify(review.state)} for ${target}`);
  }
  if (review.declaration_digest !== verdict.declaration_digest) {
    throw new Error(`review for ${target} is stale or unbound: declaration_digest does not match`);
  }
  if (typeof review.reviewer !== 'string' || review.reviewer.trim().length < 3) {
    throw new Error(`review for ${target} requires a stable reviewer identifier`);
  }
  if (typeof review.reviewed_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(review.reviewed_at)) {
    throw new Error(`review for ${target} requires reviewed_at as an RFC 3339 UTC timestamp`);
  }
  if (typeof review.rationale !== 'string' || review.rationale.trim().length < 12) {
    throw new Error(`review for ${target} requires a substantive rationale`);
  }
  return Object.freeze({
    state: review.state,
    declaration_digest: review.declaration_digest,
    reviewer: review.reviewer.trim(),
    reviewed_at: review.reviewed_at,
    rationale: review.rationale.trim(),
  });
}

function normalizePublicationApproval(approval, assessmentDigest) {
  if (approval === null || approval === undefined) return null;
  if (!approval || typeof approval !== 'object' || Array.isArray(approval)) {
    throw new Error('publication approval must be an object bound to the reviewed assessment');
  }
  if (approval.assessment_digest !== assessmentDigest) {
    throw new Error('publication approval is stale or unbound: assessment_digest does not match');
  }
  if (typeof approval.approved_by !== 'string' || approval.approved_by.trim().length < 3) {
    throw new Error('publication approval requires a stable approver identifier');
  }
  if (typeof approval.approved_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(approval.approved_at)) {
    throw new Error('publication approval requires approved_at as an RFC 3339 UTC timestamp');
  }
  if (typeof approval.correction_uri !== 'string' || !/^(?:https:\/\/|mailto:)[^\s]+$/.test(approval.correction_uri)) {
    throw new Error('publication approval requires an HTTPS or mailto correction_uri');
  }
  if (!Number.isInteger(approval.correction_sla_hours) || approval.correction_sla_hours < 1 || approval.correction_sla_hours > 24) {
    throw new Error('publication approval requires correction_sla_hours between 1 and 24');
  }
  return Object.freeze({
    assessment_digest: assessmentDigest,
    approved_by: approval.approved_by.trim(),
    approved_at: approval.approved_at,
    correction_uri: approval.correction_uri,
    correction_sla_hours: approval.correction_sla_hours,
  });
}

/**
 * @param {object} snapshot
 * @param {object} [opts]
 * @param {Record<string,object>} [opts.review] target -> declaration-bound review record
 * @param {object} [opts.publication] explicit approval bound to assessment_digest
 */
export function buildEdition(snapshot, opts = {}) {
  const problems = rubricIntegrityProblems();
  if (problems.length) throw new Error(`rubric integrity: ${problems.join('; ')}`);

  const asOf = snapshot?.provenance?.as_of;
  if (!asOf || !/^\d{4}-\d{2}-\d{2}$/.test(asOf)) throw new Error('snapshot is missing a valid provenance.as_of; refusing to build an undated edition');
  if (opts.review !== undefined && (!opts.review || typeof opts.review !== 'object' || Array.isArray(opts.review))) {
    throw new Error('review bundle must be an object keyed by target');
  }

  const latest = selectLatest(snapshot.rows ?? []);
  const assessedSnapshotDigest = `sha256:${crypto.createHash('sha256').update(canonicalJson({
    provenance: snapshot.provenance,
    rows: latest,
  }), 'utf8').digest('hex')}`;
  const seenReviewTargets = new Set();
  const targets = latest.map(({ server, status, publishedAt }) => {
    const machineVerdict = deriveVerdict(server, asOf);
    const suppliedReview = opts.review?.[server.name] ?? null;
    const review = normalizeReview(server.name, machineVerdict, suppliedReview);
    if (review) seenReviewTargets.add(server.name);
    if (review && machineVerdict.requires_review !== true) {
      throw new Error(`review supplied for ${server.name}, but its current declaration is not a candidate`);
    }
    const v = review ? applyHumanReview(machineVerdict, review) : machineVerdict;
    return {
      target: server.name,
      review_state: machineVerdict.requires_review ? (review?.state ?? 'candidate') : 'not_applicable',
      review,
      boilerplate_digest: boilerplateDigest(server),
      title: server.title ?? null,
      declared_version: server.version ?? null,
      published_at: publishedAt || null,
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

  for (const target of Object.keys(opts.review ?? {})) {
    if (!seenReviewTargets.has(target)) {
      throw new Error(`review supplied for absent or non-candidate target ${target}`);
    }
  }

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
  counts.findings_confirmed = targets.filter((t) => t.verdict === 'DECLARATION_SILENT_CONFIRMED').length;
  counts.findings_rejected = targets.filter((t) => t.verdict === 'CANDIDATE_REJECTED').length;
  for (const key of ['NO_MATCHING_CATEGORY_SIGNAL', 'DECLARED_AUTHORIZATION_SIGNAL', 'DECLARATION_SILENT_CANDIDATE', 'DECLARATION_SILENT_CONFIRMED', 'CANDIDATE_REJECTED', 'INDETERMINATE']) {
    counts[key] = targets.filter((t) => t.verdict === key).length;
  }
  counts.findings_distinct_declarations = new Set(
    targets.filter((t) => t.verdict === 'DECLARATION_SILENT_CONFIRMED').map((t) => t.boilerplate_digest),
  ).size;

  const by_category = {};
  for (const c of CATEGORIES) {
    const matched = targets.filter((t) => t.categories.includes(c.id));
    by_category[c.id] = {
      label: c.label,
      assurance_class: c.assurance_class,
      matching_signal: matched.length,
      authorization_signal: matched.filter((t) => t.verdict === 'DECLARED_AUTHORIZATION_SIGNAL').length,
      confirmed_gap: matched.filter((t) => t.verdict === 'DECLARATION_SILENT_CONFIRMED').length,
      pct_with_matching_signal: counts.total ? Number(((100 * matched.length) / counts.total).toFixed(2)) : 0,
    };
  }

  const assessmentDigest = `sha256:${crypto.createHash('sha256').update(canonicalJson({
    as_of: asOf,
    rubric: RUBRIC_VERSION,
    source_snapshot_digest: assessedSnapshotDigest,
    targets,
  }), 'utf8').digest('hex')}`;
  const publicationApproval = normalizePublicationApproval(opts.publication, assessmentDigest);
  const hasCandidates = targets.some((t) => t.review_state === 'candidate');
  if (hasCandidates && publicationApproval) {
    throw new Error('publication approval refused while unreviewed candidates remain');
  }
  if (snapshot.provenance.truncated === true && publicationApproval) {
    throw new Error('publication approval refused for a truncated snapshot');
  }
  const publicationState = hasCandidates
    ? 'DRAFT_UNREVIEWED — contains unreviewed candidates and must not be published.'
    : snapshot.provenance.truncated === true
      ? 'DRAFT_TRUNCATED — the source snapshot is incomplete and must not be published as a coverage edition.'
      : publicationApproval
        ? 'READY_FOR_PUBLICATION — every candidate was dispositioned and an accountable approver accepted this exact assessment digest.'
        : 'REVIEWED_NOT_APPROVED — every candidate was dispositioned, but this edition has no publication approval and must not be published.';
  counts.publishable = publicationApproval && !hasCandidates ? counts.findings_confirmed : 0;

  const edition = {
    '@version': EDITION_PROFILE,
    rubric: RUBRIC_VERSION,
    as_of: asOf,
    provenance: snapshot.provenance,
    source_snapshot_digest: assessedSnapshotDigest,
    assessment_digest: assessmentDigest,
    publication_approval: publicationApproval,
    scope_limit:
      'Every classification in this edition is limited to the registry name, title and description as captured in the source snapshot. No target was contacted, probed, or invoked. Automated absence of a matching category or authorization phrase is not evidence that a capability or runtime control does not exist. Only declaration-bound, human-confirmed gaps are findings.',
    publication_state: publicationState,
    correction_policy: publicationApproval
      ? `Challenges may be submitted at ${publicationApproval.correction_uri}. Confirmed findings are corrected or withdrawn within ${publicationApproval.correction_sla_hours} hours. Every candidate and confirmed finding carries the declaration digest and quoted span assessed.`
      : 'Not active: this edition is not approved for publication.',
    counts,
    by_category,
    targets,
  };
  edition.edition_digest = `sha256:${crypto.createHash('sha256').update(canonicalJson({ ...edition, edition_digest: undefined }), 'utf8').digest('hex')}`;
  return edition;
}

/** Re-derive from the snapshot and compare against a published edition. */
export function reproduce(snapshot, published) {
  const drift = [];
  const review = {};
  for (const target of published.targets ?? []) {
    if (target.review_state === 'confirmed' || target.review_state === 'rejected') {
      if (!target.review) {
        drift.push(`${target.target}: reviewed target is missing its review record`);
      } else {
        review[target.target] = target.review;
      }
    }
  }
  let rebuilt;
  try {
    rebuilt = buildEdition(snapshot, { review, publication: published.publication_approval ?? null });
  } catch (error) {
    return { reproduced: false, drift: [...drift, `rebuild refused: ${error.message}`], rebuilt: null };
  }
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
