/**
 * AI Trust Desk — question classifier.
 *
 * @license Apache-2.0
 *
 * Buckets every extracted question so the answerer knows where its answer may
 * legitimately come from. Heuristic-first (deterministic, zero-cost, runs with
 * no API key); LLM-refined only for the ambiguous tail when a provider is
 * configured.
 *
 *   soc2_overlap      → general security control, answerable from SOC2 posture
 *   ai_template_match → strong match to one of the 5 AI policy templates
 *   ai_specific       → AI question with no strong template match (LLM-grounded)
 *   customer_specific → needs customer-only facts (escalate unless in intake)
 *   novel             → unrecognized pattern (always escalate)
 */

import { scoreTemplates } from './templates-index.js';
import { llmJSON, llmAvailable } from './llm.js';
import { logger } from '../logger.js';

export const BUCKET = Object.freeze({
  SOC2_OVERLAP: 'soc2_overlap',
  AI_TEMPLATE_MATCH: 'ai_template_match',
  AI_SPECIFIC: 'ai_specific',
  CUSTOMER_SPECIFIC: 'customer_specific',
  NOVEL: 'novel',
});

// Top template score above which we trust a deterministic template match.
// Scoring: multi-word keyword hit = 1.0, single-word = 0.4 (see scoreTemplates).
// 1.0 → a single specific multi-word hit (or 3 single words) is enough.
const TEMPLATE_THRESHOLD = 1.0;

const SOC2_KEYWORDS = [
  'encryption at rest', 'encryption in transit', 'encrypt', 'at rest', 'in transit',
  'tls', 'mfa', 'multi-factor', 'access review', 'background check',
  'vulnerability scan', 'penetration test', 'pen test', 'sdlc', 'change management',
  'backup', 'disaster recovery', 'business continuity', 'soc 2', 'soc2', 'iso 27001',
  'audit log', 'monitoring', 'patch', 'firewall', 'endpoint',
  'password policy', 'single sign-on', 'sso', 'data center', 'uptime', 'sla',
];

const CUSTOMER_FACT_PATTERNS = [
  /\blist (your|all)\b/i, /\bname your\b/i, /\bwhich (model|provider|cloud|region)/i,
  /\bwhat (cloud|region|provider|model)\b/i, /\bwho (are|is) your\b/i,
  /\bprovide a list\b/i, /\bidentify your\b/i,
];

const AI_HINT = /\b(ai|ml|model|llm|gpt|inference|embedding|agent|prompt|rag|fine-?tun|vector)\b/i;

/**
 * Classify a list of questions.
 * @param {Array} questions output of extractor.extractQuestions().questions
 * @param {object} intake engagement intake fields
 * @returns {Promise<Array>} questions annotated with {bucket, matched_template, classify_confidence, classify_reason, classify_source}
 */
export async function classifyQuestions(questions, intake = {}) {
  const heuristic = questions.map((q) => ({ ...q, ...heuristicClassify(q) }));

  if (!llmAvailable()) {
    return heuristic.map((q) => ({ ...q, classify_source: 'heuristic' }));
  }

  // LLM-refine only the ambiguous tail (ai_specific / novel) to recover
  // template matches the keyword heuristic missed. Bounded concurrency.
  const refined = await refineAmbiguous(heuristic, intake);
  return refined;
}

/** Deterministic single-question classification. */
export function heuristicClassify(q) {
  const text = q.text || '';
  const lower = text.toLowerCase();
  const scored = scoreTemplates(text);
  const top = scored[0];

  if (top && top.score >= TEMPLATE_THRESHOLD) {
    return {
      bucket: BUCKET.AI_TEMPLATE_MATCH,
      matched_template: top.id,
      classify_confidence: Math.min(0.95, 0.6 + top.score * 0.3),
      classify_reason: `keyword match: ${top.hits.slice(0, 3).join(', ')}`,
    };
  }

  const soc2Hits = SOC2_KEYWORDS.filter((k) => lower.includes(k));
  const isCustomerFact = CUSTOMER_FACT_PATTERNS.some((p) => p.test(text));
  const isAi = AI_HINT.test(text);

  // Customer-specific only when it's an AI-ish "list/name your X" question —
  // a generic "list your data centers" is SOC2-shaped, not AI-specific.
  if (isCustomerFact && isAi) {
    return {
      bucket: BUCKET.CUSTOMER_SPECIFIC,
      matched_template: null,
      classify_confidence: 0.7,
      classify_reason: 'requires customer-only AI fact',
    };
  }

  if (soc2Hits.length > 0 && !isAi) {
    return {
      bucket: BUCKET.SOC2_OVERLAP,
      matched_template: null,
      classify_confidence: 0.75,
      classify_reason: `general security control: ${soc2Hits.slice(0, 2).join(', ')}`,
    };
  }

  if (isAi || (top && top.score > 0.2)) {
    return {
      bucket: BUCKET.AI_SPECIFIC,
      matched_template: top && top.score > 0.2 ? top.id : null,
      classify_confidence: 0.55,
      classify_reason: 'AI-related, weak template signal',
    };
  }

  return {
    bucket: BUCKET.NOVEL,
    matched_template: null,
    classify_confidence: 0.4,
    classify_reason: 'no recognized control or AI pattern',
  };
}

// ── LLM refinement ──────────────────────────────────────────────────────────

async function refineAmbiguous(classified, intake) {
  const TEMPLATE_IDS = ['ai-data-handling', 'prompt-injection', 'ai-subprocessors',
    'agent-access-control', 'ai-incident-response'];

  const out = [...classified];
  const ambiguousIdx = classified
    .map((q, i) => (q.bucket === BUCKET.AI_SPECIFIC || q.bucket === BUCKET.NOVEL ? i : -1))
    .filter((i) => i !== -1);

  // Concurrency cap so we don't fan out 50 requests at once.
  const CONCURRENCY = 6;
  for (let start = 0; start < ambiguousIdx.length; start += CONCURRENCY) {
    const batch = ambiguousIdx.slice(start, start + CONCURRENCY);
    await Promise.all(
      batch.map(async (i) => {
        const q = classified[i];
        const res = await llmJSON({
          system:
            'You classify enterprise AI security questionnaire questions. Respond ONLY with JSON: ' +
            '{"bucket": one of ["ai_template_match","soc2_overlap","ai_specific","customer_specific","novel"], ' +
            '"matched_template": one of ["ai-data-handling","prompt-injection","ai-subprocessors","agent-access-control","ai-incident-response"] or null, ' +
            '"confidence": 0..1}. Choose ai_template_match only when the question is squarely answered by that policy template.',
          user: `Question: ${q.text}\nSection: ${q.section || '(none)'}`,
          maxTokens: 150,
          validate: (o) =>
            o && typeof o.bucket === 'string' && Object.values(BUCKET).includes(o.bucket),
        });
        if (res.ok) {
          const matched =
            res.data.matched_template && TEMPLATE_IDS.includes(res.data.matched_template)
              ? res.data.matched_template
              : null;
          out[i] = {
            ...q,
            bucket: res.data.bucket,
            matched_template: matched,
            classify_confidence: clamp01(res.data.confidence ?? q.classify_confidence),
            classify_reason: `${q.classify_reason} → llm:${res.provider}`,
            classify_source: 'llm',
          };
        } else {
          out[i] = { ...q, classify_source: 'heuristic', classify_note: res.reason };
          if (res.reason && res.reason.startsWith('provider_error')) {
            logger.warn('trust-desk classify: llm refine failed', { id: q.id, reason: res.reason });
          }
        }
      }),
    );
  }

  // Anything not refined keeps its heuristic label, tagged accordingly.
  return out.map((q) => (q.classify_source ? q : { ...q, classify_source: 'heuristic' }));
}

function clamp01(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return 0.5;
  return Math.max(0, Math.min(1, x));
}
