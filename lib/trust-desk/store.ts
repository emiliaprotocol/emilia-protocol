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

/**
 * Pipeline state for one engagement. The pipeline (intake -> published) adds
 * fields as it progresses, and the two backends (file/supabase) round-trip
 * whatever shape the caller hands them — genuinely dynamic, so the index
 * signature carries the stage-specific fields (intake, classification,
 * answers, verification, mint, etc.) that this store is agnostic to.
 */
export interface EngagementRecord {
  engagement_id: string;
  slug?: string;
  status?: string;
  status_history?: Array<{ status: string; at: string }>;
  created_at?: string;
  updated_at?: string;
  [key: string]: any;
}

/** @returns {'file'|'supabase'} */
export function storeBackend(): 'file' | 'supabase' {
  return process.env.TRUST_DESK_STORE === 'supabase' ? 'supabase' : 'file';
}

let _sb: any = null;
async function sb(): Promise<any> {
  if (!_sb) _sb = await import('./store-supabase.js');
  return _sb;
}

// ── Public API (async; delegates to the active backend) ─────────────────────

export async function putEngagement(record: EngagementRecord): Promise<EngagementRecord> {
  if (!record?.engagement_id) throw new Error('putEngagement: engagement_id required');
  if (storeBackend() === 'supabase') return (await sb()).putEngagement(stamp(record));
  return filePut(stamp(record));
}

export async function getEngagement(engagementId: string): Promise<EngagementRecord | null> {
  if (storeBackend() === 'supabase') return (await sb()).getEngagement(engagementId);
  return fileGet(engagementId);
}

export async function patchEngagement(
  engagementId: string,
  patch: Record<string, any>,
): Promise<EngagementRecord | null> {
  if (storeBackend() === 'supabase') return (await sb()).patchEngagement(engagementId, patch);
  const current = fileGet(engagementId);
  if (!current) return null;
  const next = { ...current, ...patch, updated_at: isoNow() };
  fs.writeFileSync(fileFor(engagementId), JSON.stringify(next, null, 2));
  return next;
}

export async function setStatus(
  engagementId: string,
  status: string,
  extra: Record<string, any> = {},
): Promise<EngagementRecord | null> {
  if (storeBackend() === 'supabase') return (await sb()).setStatus(engagementId, status, extra);
  const current = fileGet(engagementId);
  if (!current) return null;
  const history: Array<{ status: string; at: string }> = Array.isArray(current.status_history)
    ? current.status_history
    : [];
  history.push({ status, at: isoNow() });
  return patchEngagement(engagementId, { status, status_history: history, ...extra });
}

export async function listEngagements(): Promise<EngagementRecord[]> {
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

export async function listByStatus(status: string): Promise<EngagementRecord[]> {
  return (await listEngagements()).filter((e) => e.status === status);
}

// ── File backend internals ──────────────────────────────────────────────────

function ensureDir(): void {
  if (!fs.existsSync(ENGAGEMENT_DIR)) fs.mkdirSync(ENGAGEMENT_DIR, { recursive: true });
}

function fileFor(engagementId: string): string {
  if (!/^eng_[a-f0-9]{6,}$/.test(engagementId)) {
    throw new Error(`invalid engagement id: ${engagementId}`);
  }
  return path.join(ENGAGEMENT_DIR, `${engagementId}.json`);
}

function filePut(record: EngagementRecord): EngagementRecord {
  ensureDir();
  fs.writeFileSync(fileFor(record.engagement_id), JSON.stringify(record, null, 2));
  return record;
}

function fileGet(engagementId: string): EngagementRecord | null {
  let file: string;
  try {
    file = fileFor(engagementId);
  } catch {
    return null;
  }
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err: any) {
    logger.error('trust-desk store: failed to parse engagement', {
      engagementId,
      error: err.message,
    });
    return null;
  }
}

function stamp(record: EngagementRecord): EngagementRecord {
  return {
    ...record,
    updated_at: record.updated_at || isoNow(),
    created_at: record.created_at || isoNow(),
  };
}

function isoNow(): string {
  return new Date().toISOString();
}
