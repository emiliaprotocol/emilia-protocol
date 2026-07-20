/**
 * AI Trust Desk — policy minting (template → substituted, hashed doc).
 *
 * @license Apache-2.0
 *
 * Deterministic `{{VAR}}` substitution with a fallback so no published policy
 * ever shows a raw placeholder. Each minted doc is hashed with the same
 * canonical text hash used everywhere else (hashText), so the hash on a trust
 * page claim binds to the exact bytes a buyer reads.
 */

import fs from 'node:fs';
import path from 'node:path';
import { loadTemplates } from './templates-index.js';
import { buildPolicyVars } from './policy-defaults.js';
import { hashText } from './hash.js';
import { logger } from '../logger.js';

const PLACEHOLDER_RE = /\{\{\s*([A-Z0-9_]+)\s*\}\}/g;

/**
 * Substitute `{{VAR}}` placeholders. Unknown variables resolve through a
 * readable fallback (never a raw placeholder, never a crash).
 * @param {string} text
 * @param {Record<string,string>} vars
 * @returns {string}
 */
export function substitute(text, vars = {}) {
  if (!text) return '';
  return String(text).replace(PLACEHOLDER_RE, (_m, name) => {
    if (Object.prototype.hasOwnProperty.call(vars, name)) return String(vars[name]);
    return fallbackFor(name, vars);
  });
}

/**
 * Readable fallback for an unresolved variable. Pattern-matched by suffix so a
 * brand-new template variable still renders sensibly.
 * @param {string} name
 * @param {Record<string,string>} vars
 * @returns {string}
 */
function fallbackFor(name, vars) {
  if (/_EMAIL$/.test(name)) return vars.SECURITY_LEAD_EMAIL || 'security@vendor.example';
  if (/_SLA$|_WINDOW$|_TTL$/.test(name)) return 'as specified in the MSA';
  if (/_CADENCE$|_FREQUENCY$/.test(name)) return 'periodic';
  if (/_RETENTION$/.test(name)) return 'per the data retention policy';
  if (/_REGION$/.test(name)) return 'United States';
  if (/_DPA$|_DPA_DATE$/.test(name)) return 'on file';
  if (/_PROVIDER$|_TOOL$|_DB$/.test(name)) return 'as disclosed in the subprocessor map';
  if (/_NAME$/.test(name)) return vars.SECURITY_LEAD_NAME || 'Security Team';
  if (/_TITLE$/.test(name)) return 'Authorized Representative';
  if (/_URL$/.test(name)) return vars.TRUST_PAGE_URL || 'https://www.emiliaprotocol.ai/trust-desk';
  if (/_CADENCE|_SLA|_LIMIT|_RATE/.test(name)) return 'as configured per tenant';
  return 'Available to the requesting party under NDA';
}

/**
 * Count unresolved placeholders remaining in a string (should be 0 post-mint).
 * @param {string} text
 */
export function unresolvedCount(text) {
  const m = String(text).match(PLACEHOLDER_RE);
  return m ? m.length : 0;
}

/**
 * Mint all 5 policy docs for an engagement. Always returns the substituted
 * content in-memory (so a Supabase backend can persist it); writes markdown
 * files only when `outDir` is provided (file backend / local).
 *
 * @param {object} opts
 * @param {object} opts.intake
 * @param {string} opts.slug
 * @param {string} [opts.outDir]  if set, also write policy markdown here
 * @param {string} [opts.effectiveDate]
 * @returns {Array<{doc_id: string, title: string, filename: string, path: string|null, content: string, content_hash: string, bytes: number}>}
 */
export function mintPolicies({ intake, slug, outDir, effectiveDate }) {
  const vars = buildPolicyVars(intake, { slug, effectiveDate });
  const templates = loadTemplates();
  if (outDir) fs.mkdirSync(outDir, { recursive: true });

  return templates.map((tpl) => {
    const filled = substitute(tpl.content, vars);
    const leftover = unresolvedCount(filled);
    if (leftover > 0) {
      // Should be impossible given the fallback, but never publish a raw
      // uppercase variable — replace any straggler defensively and log.
      logger.warn('trust-desk policy-mint: unresolved placeholders after substitution', {
        template: tpl.id,
        count: leftover,
      });
    }
    const safe = filled
      // Any stray uppercase `{{VAR}}` → NDA text (defensive; should be none).
      .replace(PLACEHOLDER_RE, 'Available to the requesting party under NDA')
      // Incident-time fill-in fields (e.g. `{{READ | MODIFIED | EXPOSED}}` in the
      // runbook's example notification letter) aren't onboarding variables —
      // render them as bracketed fill-ins, not broken mustache syntax.
      .replace(/\{\{\s*([^{}]+?)\s*\}\}/g, (_m, inner) => `[${inner.trim()}]`);
    const filename = `${tpl.id}.md`;
    let filePath = null;
    if (outDir) {
      filePath = path.join(outDir, filename);
      fs.writeFileSync(filePath, safe);
    }
    return {
      doc_id: tpl.id,
      title: tpl.title,
      filename,
      path: filePath,
      content: safe,
      content_hash: hashText(safe),
      bytes: Buffer.byteLength(safe, 'utf8'),
    };
  });
}
