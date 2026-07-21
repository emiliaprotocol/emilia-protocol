/**
 * AI Trust Desk — published-page store (backend-agnostic).
 *
 * @license Apache-2.0
 *
 * The published trust page = a doc (claims with signatures) + its artifacts
 * (policy markdown + the answers payload), which the verify endpoint re-hashes.
 * Two backends, selected by TRUST_DESK_STORE (see store.js:storeBackend):
 *
 *   file      — data/trust-desk/customers/<slug>.json + <slug>/policies/*.md +
 *               <slug>/answers.json. The committed demo + CLI + tests use this.
 *   supabase  — trust_desk_pages row. Required on Vercel (read-only FS).
 *
 * getPublishedPage() returns a uniform shape with a SYNC getArtifact() closure
 * so the verifier stays synchronous regardless of backend.
 */

import fs from 'node:fs';
import path from 'node:path';
import { hydrateCustomerDoc, trustPageStatus } from './customers.js';
import { storeBackend } from './store.js';

const CUSTOMER_DIR = path.join(process.cwd(), 'data', 'trust-desk', 'customers');

let _sb = null;
async function sb() {
  if (!_sb) _sb = await import('./store-supabase.js');
  return _sb;
}

/**
 * Persist a published page.
 * @param {object} opts { slug, doc, policies:[{doc_id,filename,content,content_hash}], answers }
 */
export async function putPublishedPage({ slug, doc, policies, answers }) {
  if (storeBackend() === 'supabase') {
    return (await sb()).putPage({ doc, policies, answers });
  }
  // File backend: write the same layout the renderer + CLI already expect.
  const dir = path.join(CUSTOMER_DIR, slug);
  fs.mkdirSync(path.join(dir, 'policies'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'answers.json'), JSON.stringify(answers, null, 2));
  for (const p of policies) {
    fs.writeFileSync(path.join(dir, 'policies', p.filename), p.content);
  }
  fs.writeFileSync(path.join(CUSTOMER_DIR, `${slug}.json`), JSON.stringify(doc, null, 2));
  return slug;
}

/**
 * Load a published page + a sync artifact reader.
 * @param {string} slug
 * @returns {Promise<{raw,customer,status,getArtifact:(source_file:string)=>(string|null)}|null>}
 */
export async function getPublishedPage(slug) {
  if (typeof slug !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(slug)) return null;

  if (storeBackend() === 'supabase') {
    const page = await (await sb()).getPage(slug);
    if (!page) return null;
    const { doc, policies = [], answers = {} } = page;
    const byFilename = new Map(policies.map((p) => [p.filename, p.content]));
    const getArtifact = (sourceFile) => {
      if (!sourceFile) return null;
      if (sourceFile.endsWith('/answers.json')) return JSON.stringify(answers);
      return byFilename.get(path.basename(sourceFile)) ?? null;
    };
    return { raw: doc, customer: hydrateCustomerDoc(doc), status: trustPageStatus(doc), getArtifact };
  }

  // File backend
  const file = path.join(CUSTOMER_DIR, `${slug}.json`);
  if (!file.startsWith(CUSTOMER_DIR + path.sep) || !fs.existsSync(file)) return null;
  const doc = JSON.parse(fs.readFileSync(file, 'utf8'));
  const getArtifact = (sourceFile) => {
    const p = path.join(CUSTOMER_DIR, sourceFile || '');
    if (!p.startsWith(CUSTOMER_DIR + path.sep) || !fs.existsSync(p)) return null;
    return fs.readFileSync(p, 'utf8');
  };
  return { raw: doc, customer: hydrateCustomerDoc(doc), status: trustPageStatus(doc), getArtifact };
}

/** List published slugs across the active backend. */
export async function listPublishedSlugs() {
  if (storeBackend() === 'supabase') return (await sb()).listPageSlugs();
  if (!fs.existsSync(CUSTOMER_DIR)) return [];
  return fs
    .readdirSync(CUSTOMER_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.replace(/\.json$/, ''));
}

/** Read the monitor marker for a page ({} if none). */
export async function getPageMonitor(slug) {
  if (storeBackend() === 'supabase') return (await sb()).getPageMonitor(slug);
  try {
    return JSON.parse(fs.readFileSync(path.join(CUSTOMER_DIR, slug, 'monitor.json'), 'utf8'));
  } catch {
    return {};
  }
}

/** Persist the monitor marker for a page. */
export async function setPageMonitor(slug, monitor) {
  if (storeBackend() === 'supabase') return (await sb()).setPageMonitor(slug, monitor);
  const dir = path.join(CUSTOMER_DIR, slug);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'monitor.json'), JSON.stringify(monitor, null, 2));
  return undefined;
}
