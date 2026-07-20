/**
 * AI Trust Desk — engagement state store (backend-agnostic).
 *
 * @license Apache-2.0
 *
 * Holds pipeline state for every engagement (intake → published). Two backends:
 *
 *   file      (default)  — data/trust-desk/engagements/<id>.json. Zero-config;
 *                          works locally and in tests. NOTE: Vercel's runtime
 *                          filesystem is read-only, so this cannot persist new
 *                          engagements in production.
 *   supabase  (flagged)  — set TRUST_DESK_STORE=supabase. Required for prod on
 *                          Vercel. Dynamically imported so the file/CLI path
 *                          never loads the Supabase client.
 *
 * All functions are async so callers don't care which backend is active.
 */

import fs from 'node:fs';
import path from 'node:path';
import { logger } from '../logger.js';

const ENGAGEMENT_DIR = path.join(process.cwd(), 'data', 'trust-desk', 'engagements');

/** Pipeline status values, in order. */
export const STATUS = Object.freeze({
  INTAKE_RECEIVED: 'intake_received',
  EXTRACTING: 'extracting',
  CLASSIFYING: 'classifying',
  ANSWERING: 'answering',
  VERIFYING: 'verifying',
  MINTING: 'minting',
  PUBLISHED: 'published',
  ESCALATED: 'escalated',
  FAILED: 'failed',
});

/** @returns {'file'|'supabase'} */
export function storeBackend() {
  return process.env.TRUST_DESK_STORE === 'supabase' ? 'supabase' : 'file';
}

let _sb = null;
async function sb() {
  if (!_sb) _sb = await import('./store-supabase.js');
  return _sb;
}

// ── Public API (async; delegates to the active backend) ─────────────────────

export async function putEngagement(record) {
  if (!record?.engagement_id) throw new Error('putEngagement: engagement_id required');
  if (storeBackend() === 'supabase') return (await sb()).putEngagement(stamp(record));
  return filePut(stamp(record));
}

export async function getEngagement(engagementId) {
  if (storeBackend() === 'supabase') return (await sb()).getEngagement(engagementId);
  return fileGet(engagementId);
}

export async function patchEngagement(engagementId, patch) {
  if (storeBackend() === 'supabase') return (await sb()).patchEngagement(engagementId, patch);
  const current = fileGet(engagementId);
  if (!current) return null;
  const next = { ...current, ...patch, updated_at: isoNow() };
  fs.writeFileSync(fileFor(engagementId), JSON.stringify(next, null, 2));
  return next;
}

export async function setStatus(engagementId, status, extra = {}) {
  if (storeBackend() === 'supabase') return (await sb()).setStatus(engagementId, status, extra);
  const current = fileGet(engagementId);
  if (!current) return null;
  const history = Array.isArray(current.status_history) ? current.status_history : [];
  history.push({ status, at: isoNow() });
  return patchEngagement(engagementId, { status, status_history: history, ...extra });
}

export async function listEngagements() {
  if (storeBackend() === 'supabase') return (await sb()).listEngagements();
  ensureDir();
  return fs
    .readdirSync(ENGAGEMENT_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => {
      try {
        return JSON.parse(fs.readFileSync(path.join(ENGAGEMENT_DIR, f), 'utf8'));
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
}

export async function listByStatus(status) {
  return (await listEngagements()).filter((e) => e.status === status);
}

// ── File backend internals ──────────────────────────────────────────────────

function ensureDir() {
  if (!fs.existsSync(ENGAGEMENT_DIR)) fs.mkdirSync(ENGAGEMENT_DIR, { recursive: true });
}

function fileFor(engagementId) {
  if (!/^eng_[a-f0-9]{6,}$/.test(engagementId)) {
    throw new Error(`invalid engagement id: ${engagementId}`);
  }
  return path.join(ENGAGEMENT_DIR, `${engagementId}.json`);
}

function filePut(record) {
  ensureDir();
  fs.writeFileSync(fileFor(record.engagement_id), JSON.stringify(record, null, 2));
  return record;
}

function fileGet(engagementId) {
  let file;
  try {
    file = fileFor(engagementId);
  } catch {
    return null;
  }
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    logger.error('trust-desk store: failed to parse engagement', {
      engagementId,
      error: err.message,
    });
    return null;
  }
}

function stamp(record) {
  return {
    ...record,
    updated_at: record.updated_at || isoNow(),
    created_at: record.created_at || isoNow(),
  };
}

function isoNow() {
  return new Date().toISOString();
}
