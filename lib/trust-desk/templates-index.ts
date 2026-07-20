/**
 * AI Trust Desk — policy template index.
 *
 * @license Apache-2.0
 *
 * The 5 versioned AI policy templates are the ONLY trusted source for
 * template-bucket answers. This module loads them once, hashes each, and
 * exposes keyword sets + section splits used by the classifier (to bucket a
 * question) and the answerer (to pull the relevant excerpt deterministically).
 *
 * Adding a template = add an entry to TEMPLATES below. The file must exist
 * under content/trust-desk/templates/.
 */

import fs from 'node:fs';
import path from 'node:path';
import { hashText } from './hash.js';

const TEMPLATE_DIR = path.join(process.cwd(), 'content', 'trust-desk', 'templates');

/**
 * Template registry. `keywords` drive classification; they are matched
 * case-insensitively against question text. Keep them specific — a keyword
 * that matches too broadly causes mis-bucketing.
 */
const TEMPLATES = [
  {
    id: 'ai-data-handling',
    title: 'AI Data Handling & Model Training Disclosure',
    file: 'ai-data-handling.md',
    keywords: [
      'data handling', 'model training', 'training data', 'customer data',
      'data retention', 'data deletion', 'pii', 'personal data', 'fine-tune',
      'fine tuning', 'data residency', 'data governance', 'inference data',
      'opt out', 'opt-out', 'data processing', 'retention period',
    ],
  },
  {
    id: 'prompt-injection',
    title: 'Prompt Injection Defense Statement',
    file: 'prompt-injection.md',
    keywords: [
      'prompt injection', 'jailbreak', 'adversarial', 'indirect injection',
      'system prompt', 'prompt leak', 'instruction', 'guardrail', 'input sanitization',
      'red team', 'red-team', 'llm attack', 'prompt security',
    ],
  },
  {
    id: 'ai-subprocessors',
    title: 'AI Subprocessor & Data Flow Map',
    file: 'ai-subprocessors.md',
    keywords: [
      'subprocessor', 'sub-processor', 'data flow', 'third party', 'third-party',
      'vendor', 'data sharing', 'model provider', 'openai', 'anthropic',
      'vector database', 'embedding', 'data transfer', 'where does data go',
      'who has access', 'dpa', 'data processing agreement',
    ],
  },
  {
    id: 'agent-access-control',
    title: 'AI Agent Access Control Policy',
    file: 'agent-access-control.md',
    keywords: [
      'agent', 'tool access', 'tool call', 'permission', 'authorization',
      'least privilege', 'rbac', 'access control', 'privilege', 'human in the loop',
      'human-in-the-loop', 'approval', 'autonomous', 'action', 'delegation',
      'kill switch', 'kill-switch', 'scope',
    ],
  },
  {
    id: 'ai-incident-response',
    title: 'AI Incident Response Runbook',
    file: 'ai-incident-response.md',
    keywords: [
      'incident', 'incident response', 'breach', 'notification', 'disclosure',
      'postmortem', 'post-mortem', 'sev', 'severity', 'escalation', 'on-call',
      'on call', 'runbook', 'containment', 'remediation', 'rto', 'rpo',
      'response time', 'security incident',
    ],
  },
];

/**
 * @typedef {Object} TemplateEntry
 * @property {string} id
 * @property {string} title
 * @property {string} file
 * @property {string} path
 * @property {string} content
 * @property {string|null} content_hash
 * @property {string[]} keywords
 * @property {Array<{heading:string,body:string}>} sections
 */

/** @type {TemplateEntry[]|null} */
let _cache = null;

/**
 * Load + hash all templates. Cached for the process lifetime.
 * @returns {TemplateEntry[]}
 */
export function loadTemplates() {
  if (_cache) return _cache;
  _cache = TEMPLATES.map((t) => {
    const filePath = path.join(TEMPLATE_DIR, t.file);
    const content = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
    return {
      ...t,
      path: filePath,
      content,
      content_hash: content ? hashText(content) : null,
      sections: splitSections(content),
    };
  });
  return _cache;
}

/**
 * Look up a single template by id.
 * @param {string} id
 * @returns {TemplateEntry|null}
 */
export function getTemplate(id) {
  return loadTemplates().find((t) => t.id === id) || null;
}

/**
 * Score a question's affinity to each template by keyword overlap.
 *
 * Scoring weights SPECIFICITY: a multi-word keyword ("prompt injection",
 * "model training") is a far stronger signal than a single word ("agent"),
 * so it contributes more. Hyphens and whitespace are normalized so
 * "least-privilege" matches the keyword "least privilege". A single
 * multi-word hit (weight 1.0) is enough to clear the classifier's template
 * threshold; single words accumulate (0.4 each).
 *
 * @param {string} questionText
 * @returns {Array<{id:string,score:number,hits:string[]}>} sorted desc by score
 */
export function scoreTemplates(questionText) {
  const hay = normalizeMatch(questionText);
  return loadTemplates()
    .map((t) => {
      const hits = [];
      let score = 0;
      for (const k of t.keywords) {
        const nk = normalizeMatch(k);
        if (hay.includes(nk)) {
          hits.push(k);
          // Weight by normalized token count so hyphenated keywords like
          // "fine-tune" count as the multi-word signals they are.
          score += nk.includes(' ') ? 1.0 : 0.4;
        }
      }
      return { id: t.id, score, hits };
    })
    .sort((a, b) => b.score - a.score);
}

/**
 * Lowercase + collapse hyphens/underscores/whitespace to single spaces.
 * @param {string} s
 * @returns {string}
 */
function normalizeMatch(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/[-_/]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Split markdown into `## N. Heading` sections for excerpt selection.
 * @param {string} content
 * @returns {Array<{heading:string,body:string}>}
 */
function splitSections(content) {
  if (!content) return [];
  const lines = content.split('\n');
  const sections = [];
  let current = null;
  for (const line of lines) {
    const h = line.match(/^##\s+(.*)$/);
    if (h) {
      if (current) sections.push(current);
      current = { heading: h[1].trim(), body: '' };
    } else if (current) {
      current.body += line + '\n';
    }
  }
  if (current) sections.push(current);
  return sections.map((s) => ({ heading: s.heading, body: s.body.trim() }));
}
