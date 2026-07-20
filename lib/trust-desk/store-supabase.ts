/**
 * AI Trust Desk — Supabase backend (engagements + pages).
 *
 * @license Apache-2.0
 *
 * Loaded ONLY when TRUST_DESK_STORE=supabase (via dynamic import in store.js /
 * page-store.js), so the file/CLI path never pulls in the Supabase client or
 * its `@/`-aliased deps. Tables: trust_desk_engagements, trust_desk_pages
 * (migration 092_trust_desk.sql). Service-role access; RLS denies anon.
 */

import { getServiceClient } from '../supabase.js';

const ENG_TABLE = 'trust_desk_engagements';
const PAGE_TABLE = 'trust_desk_pages';

/**
 * The engagement record this backend reads/writes. Extends the shared
 * EngagementRecord (see store.js) with `outcome` and `slug`, which store.js
 * itself never reads but the row mapping below (engagementRow) does.
 * @typedef {import('./store.js').EngagementRecord & {outcome?: string, slug?: string}} EngagementRecord
 */

/**
 * The published trust-page document (see minter.js mintTrustPage's `doc`).
 * Only the fields this module reads are declared; the doc also carries
 * claims, contact, product_tagline, etc. that pass through untouched.
 * @typedef {object} TrustDeskPublishedDoc
 * @property {string} slug
 * @property {string} [company]
 * @property {string} [last_rehashed]
 * @property {{engagement_id?: string}} [pipeline]
 * @property {{expires_at?: string}} [engagement]
 */

/**
 * A minted policy artifact (see policy-mint.js mintPolicies()).
 * @typedef {{doc_id?: string, filename: string, content: string, content_hash?: string}} TrustDeskPolicyArtifact
 */

// ── Engagements ─────────────────────────────────────────────────────────────

/** @param {EngagementRecord} record */
export async function putEngagement(record) {
  const sb = getServiceClient();
  const row = engagementRow(record);
  const { error } = await sb.from(ENG_TABLE).upsert(row, { onConflict: 'engagement_id' });
  if (error) throw new Error(`trust-desk SB putEngagement: ${error.message}`);
  return record;
}

/** @param {string} engagementId */
export async function getEngagement(engagementId) {
  const sb = getServiceClient();
  const { data, error } = await sb
    .from(ENG_TABLE)
    .select('data')
    .eq('engagement_id', engagementId)
    .maybeSingle();
  if (error) throw new Error(`trust-desk SB getEngagement: ${error.message}`);
  return data ? data.data : null;
}

/**
 * @param {string} engagementId
 * @param {Partial<EngagementRecord>} patch
 */
export async function patchEngagement(engagementId, patch) {
  const current = await getEngagement(engagementId);
  if (!current) return null;
  const next = { ...current, ...patch, updated_at: new Date().toISOString() };
  return putEngagement(next).then(() => next);
}

/**
 * @param {string} engagementId
 * @param {(typeof import('./store.js').STATUS)[keyof typeof import('./store.js').STATUS]} status
 */
export async function setStatus(engagementId, status, extra = {}) {
  const current = await getEngagement(engagementId);
  if (!current) return null;
  const history = Array.isArray(current.status_history) ? current.status_history : [];
  history.push({ status, at: new Date().toISOString() });
  return patchEngagement(engagementId, { status, status_history: history, ...extra });
}

export async function listEngagements() {
  const sb = getServiceClient();
  const { data, error } = await sb
    .from(ENG_TABLE)
    .select('data')
    .order('created_at', { ascending: false });
  if (error) throw new Error(`trust-desk SB listEngagements: ${error.message}`);
  return (data || []).map((r) => r.data);
}

/** @param {(typeof import('./store.js').STATUS)[keyof typeof import('./store.js').STATUS]} status */
export async function listByStatus(status) {
  return (await listEngagements()).filter((e) => e.status === status);
}

// ── Pages ───────────────────────────────────────────────────────────────────

/**
 * Upsert a published page.
 * @param {object} opts
 * @param {object} opts.doc the published trust-page document (see
 *   TrustDeskPublishedDoc below; typed loosely here so this stays assignable
 *   from callers like page-store.js's own untyped-`doc` passthrough)
 * @param {Array<TrustDeskPolicyArtifact>} opts.policies
 * @param {object} opts.answers
 */
export async function putPage({ doc, policies, answers }) {
  const d = /** @type {TrustDeskPublishedDoc} */ (doc);
  const sb = getServiceClient();
  const row = {
    slug: d.slug,
    engagement_id: d.pipeline?.engagement_id || null,
    company: d.company || null,
    doc,
    policies,
    answers,
    published_at: d.last_rehashed || new Date().toISOString(),
    expires_at: d.engagement?.expires_at || null,
  };
  const { error } = await sb.from(PAGE_TABLE).upsert(row, { onConflict: 'slug' });
  if (error) throw new Error(`trust-desk SB putPage: ${error.message}`);
  return d.slug;
}

/**
 * Read a published page + its artifacts.
 * @param {string} slug
 * @returns {Promise<{doc: TrustDeskPublishedDoc, policies: Array<TrustDeskPolicyArtifact>, answers: object}|null>}
 */
export async function getPage(slug) {
  const sb = getServiceClient();
  const { data, error } = await sb
    .from(PAGE_TABLE)
    .select('doc, policies, answers')
    .eq('slug', slug)
    .maybeSingle();
  if (error) throw new Error(`trust-desk SB getPage: ${error.message}`);
  return data || null;
}

export async function listPageSlugs() {
  const sb = getServiceClient();
  const { data, error } = await sb.from(PAGE_TABLE).select('slug');
  if (error) throw new Error(`trust-desk SB listPageSlugs: ${error.message}`);
  return (data || []).map((r) => r.slug);
}

/** @param {string} slug */
export async function getPageMonitor(slug) {
  const sb = getServiceClient();
  const { data, error } = await sb.from(PAGE_TABLE).select('monitor').eq('slug', slug).maybeSingle();
  if (error) throw new Error(`trust-desk SB getPageMonitor: ${error.message}`);
  return data?.monitor || {};
}

/**
 * @param {string} slug
 * @param {object} monitor
 */
export async function setPageMonitor(slug, monitor) {
  const sb = getServiceClient();
  const { error } = await sb.from(PAGE_TABLE).update({ monitor }).eq('slug', slug);
  if (error) throw new Error(`trust-desk SB setPageMonitor: ${error.message}`);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/** @param {EngagementRecord} record */
function engagementRow(record) {
  return {
    engagement_id: record.engagement_id,
    slug: record.slug || null,
    company: record.intake?.company || record.company || null,
    status: record.status || 'intake_received',
    outcome: record.outcome || null,
    data: record,
  };
}
