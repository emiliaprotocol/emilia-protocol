/**
 * AI Trust Desk — engagement state store.
 *
 * @license Apache-2.0
 *
 * Holds pipeline state for every engagement as it moves intake → published.
 * File-backed by default (data/trust-desk/engagements/<id>.json) so the whole
 * pipeline runs with zero external services. The interface is intentionally
 * narrow (get/put/patch/list) so a Supabase/Postgres backend can drop in
 * behind it later without touching the pipeline.
 *
 * The rendered trust page is a SEPARATE artifact (data/trust-desk/customers/
 * <slug>.json, owned by minter.js + customers.js). This store holds pipeline
 * STATE; that file holds the published DOCUMENT.
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

function ensureDir() {
  if (!fs.existsSync(ENGAGEMENT_DIR)) {
    fs.mkdirSync(ENGAGEMENT_DIR, { recursive: true });
  }
}

function fileFor(engagementId) {
  // Defense-in-depth against path traversal: engagement ids are `eng_<hex>`.
  if (!/^eng_[a-f0-9]{6,}$/.test(engagementId)) {
    throw new Error(`invalid engagement id: ${engagementId}`);
  }
  return path.join(ENGAGEMENT_DIR, `${engagementId}.json`);
}

/**
 * Create a new engagement record.
 * @param {object} record must include `engagement_id`
 */
export function putEngagement(record) {
  ensureDir();
  if (!record?.engagement_id) throw new Error('putEngagement: engagement_id required');
  const file = fileFor(record.engagement_id);
  const withMeta = {
    ...record,
    updated_at: record.updated_at || isoNow(),
    created_at: record.created_at || isoNow(),
  };
  fs.writeFileSync(file, JSON.stringify(withMeta, null, 2));
  return withMeta;
}

/**
 * Read an engagement by id. Returns null if missing.
 * @param {string} engagementId
 */
export function getEngagement(engagementId) {
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

/**
 * Shallow-merge a patch into an existing engagement and stamp status/updated_at.
 * @param {string} engagementId
 * @param {object} patch
 * @returns {object|null} updated record, or null if not found
 */
export function patchEngagement(engagementId, patch) {
  const current = getEngagement(engagementId);
  if (!current) return null;
  const next = { ...current, ...patch, updated_at: isoNow() };
  fs.writeFileSync(fileFor(engagementId), JSON.stringify(next, null, 2));
  return next;
}

/**
 * Record a status transition with an optional structured note.
 * @param {string} engagementId
 * @param {string} status one of STATUS.*
 * @param {object} [extra] merged into the record
 */
export function setStatus(engagementId, status, extra = {}) {
  const current = getEngagement(engagementId);
  if (!current) return null;
  const history = Array.isArray(current.status_history) ? current.status_history : [];
  history.push({ status, at: isoNow() });
  return patchEngagement(engagementId, { status, status_history: history, ...extra });
}

/** List all engagements (newest first). */
export function listEngagements() {
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

/** List engagements in a given status. */
export function listByStatus(status) {
  return listEngagements().filter((e) => e.status === status);
}

function isoNow() {
  return new Date().toISOString();
}
