// Generated from store-supabase.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
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
// ── Engagements ─────────────────────────────────────────────────────────────
export async function putEngagement(record) {
    const sb = getServiceClient();
    const row = engagementRow(record);
    const { error } = await sb.from(ENG_TABLE).upsert(row, { onConflict: 'engagement_id' });
    if (error)
        throw new Error(`trust-desk SB putEngagement: ${error.message}`);
    return record;
}
export async function getEngagement(engagementId) {
    const sb = getServiceClient();
    const { data, error } = await sb
        .from(ENG_TABLE)
        .select('data')
        .eq('engagement_id', engagementId)
        .maybeSingle();
    if (error)
        throw new Error(`trust-desk SB getEngagement: ${error.message}`);
    return data ? data.data : null;
}
export async function patchEngagement(engagementId, patch) {
    const current = await getEngagement(engagementId);
    if (!current)
        return null;
    const next = { ...current, ...patch, updated_at: new Date().toISOString() };
    return putEngagement(next).then(() => next);
}
export async function setStatus(engagementId, status, extra = {}) {
    const current = await getEngagement(engagementId);
    if (!current)
        return null;
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
    if (error)
        throw new Error(`trust-desk SB listEngagements: ${error.message}`);
    return (data || []).map((r) => r.data);
}
export async function listByStatus(status) {
    return (await listEngagements()).filter((e) => e.status === status);
}
// ── Pages ───────────────────────────────────────────────────────────────────
/**
 * Upsert a published page.
 * @param {object} opts { doc, policies:[{doc_id,filename,content,content_hash}], answers }
 */
export async function putPage({ doc, policies, answers }) {
    const sb = getServiceClient();
    const row = {
        slug: doc.slug,
        engagement_id: doc.pipeline?.engagement_id || null,
        company: doc.company || null,
        doc,
        policies,
        answers,
        published_at: doc.last_rehashed || new Date().toISOString(),
        expires_at: doc.engagement?.expires_at || null,
    };
    const { error } = await sb.from(PAGE_TABLE).upsert(row, { onConflict: 'slug' });
    if (error)
        throw new Error(`trust-desk SB putPage: ${error.message}`);
    return doc.slug;
}
/**
 * Read a published page + its artifacts.
 * @returns {Promise<{doc, policies, answers}|null>}
 */
export async function getPage(slug) {
    const sb = getServiceClient();
    const { data, error } = await sb
        .from(PAGE_TABLE)
        .select('doc, policies, answers')
        .eq('slug', slug)
        .maybeSingle();
    if (error)
        throw new Error(`trust-desk SB getPage: ${error.message}`);
    return data || null;
}
export async function listPageSlugs() {
    const sb = getServiceClient();
    const { data, error } = await sb.from(PAGE_TABLE).select('slug');
    if (error)
        throw new Error(`trust-desk SB listPageSlugs: ${error.message}`);
    return (data || []).map((r) => r.slug);
}
export async function getPageMonitor(slug) {
    const sb = getServiceClient();
    const { data, error } = await sb.from(PAGE_TABLE).select('monitor').eq('slug', slug).maybeSingle();
    if (error)
        throw new Error(`trust-desk SB getPageMonitor: ${error.message}`);
    return data?.monitor || {};
}
export async function setPageMonitor(slug, monitor) {
    const sb = getServiceClient();
    const { error } = await sb.from(PAGE_TABLE).update({ monitor }).eq('slug', slug);
    if (error)
        throw new Error(`trust-desk SB setPageMonitor: ${error.message}`);
}
// ── Helpers ─────────────────────────────────────────────────────────────────
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
