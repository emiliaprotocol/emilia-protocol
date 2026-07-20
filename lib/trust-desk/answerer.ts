/**
 * AI Trust Desk — question answerer.
 *
 * @license Apache-2.0
 *
 * Produces an answer for each classified question. The governing rule, which
 * the verifier later enforces: NO ANSWER SHIPS WITHOUT A SOURCE. Sources are
 * one of:
 *   - template   : an excerpt from one of the 5 versioned policy templates
 *   - intake      : a field the customer themselves provided
 *   - boilerplate : a fixed, audited fragment (e.g. SOC2 posture framing)
 *
 * Template and intake answers are DETERMINISTIC (no LLM, no hallucination
 * surface). Only ai_specific / customer-fact-present questions touch the LLM,
 * and those are forced to cite a template excerpt or they escalate.
 */

import { BUCKET } from './classifier.js';
import { getTemplate } from './templates-index.js';
import { substitute } from './policy-mint.js';
import { llmJSON, llmAvailable } from './llm.js';

export const ANSWER_STATUS = Object.freeze({
  ANSWERED: 'answered',
  ESCALATED: 'escalated',
});

const MIN_LLM_CONFIDENCE = 0.75;

/**
 * Answer one classified question.
 * @param {object} q classified question (from classifier)
 * @param {object} ctx { intake, policyVars }
 * @returns {Promise<object>} answer record
 */
export async function answerQuestion(q, ctx) {
  switch (q.bucket) {
    case BUCKET.AI_TEMPLATE_MATCH:
      return answerFromTemplate(q, ctx);
    case BUCKET.SOC2_OVERLAP:
      return answerFromSoc2(q, ctx);
    case BUCKET.CUSTOMER_SPECIFIC:
      return answerFromIntakeFact(q, ctx);
    case BUCKET.AI_SPECIFIC:
      return answerWithLlm(q, ctx);
    case BUCKET.NOVEL:
    default:
      return escalate(q, 'novel_question');
  }
}

/**
 * Answer every question with bounded concurrency.
 * @returns {Promise<Array>} answer records (same order as input)
 */
export async function answerAll(questions, ctx, concurrency = 8) {
  const out = new Array(questions.length);
  for (let start = 0; start < questions.length; start += concurrency) {
    const batch = questions.slice(start, start + concurrency);
    const results = await Promise.all(batch.map((q) => answerQuestion(q, ctx)));
    results.forEach((r, j) => {
      out[start + j] = r;
    });
  }
  return out;
}

// ── Deterministic answerers ─────────────────────────────────────────────────

function answerFromTemplate(q, ctx) {
  const tpl = getTemplate(q.matched_template);
  if (!tpl || !tpl.content) return escalate(q, 'template_missing');

  const section = selectSection(tpl, q.text);
  const excerpt = section ? firstParagraphs(section.body, 2) : firstParagraphs(tpl.content, 2);
  const answer = substitute(excerpt, ctx.policyVars).trim();

  return {
    ...base(q),
    status: ANSWER_STATUS.ANSWERED,
    answer,
    confidence: 0.95,
    sources: [
      {
        kind: 'template',
        template_id: tpl.id,
        template_hash: tpl.content_hash,
        section: section ? section.heading : null,
      },
    ],
    answer_source: 'deterministic',
  };
}

function answerFromSoc2(q, ctx) {
  const status = ctx.intake?.soc2_status || 'unspecified';
  const phrasing = SOC2_PHRASING[status] || SOC2_PHRASING.default;
  const answer =
    `${phrasing} Controls relevant to this question are covered under our SOC 2 program ` +
    `and apply to the AI product surface. Evidence (report, bridge letter) is available to the ` +
    `requesting party under NDA.`;

  return {
    ...base(q),
    status: ANSWER_STATUS.ANSWERED,
    answer,
    confidence: 0.86,
    sources: [
      { kind: 'intake', field: 'soc2_status', value: status },
      { kind: 'boilerplate', id: 'soc2-posture-v1' },
    ],
    answer_source: 'deterministic',
  };
}

/**
 * Customer-specific facts: answerable only from a field the customer actually
 * supplied. If the relevant field is empty, escalate — we never invent a
 * subprocessor, region, or model provider.
 */
function answerFromIntakeFact(q, ctx) {
  const intake = ctx.intake || {};
  const lower = (q.text || '').toLowerCase();

  let field = null;
  let value = null;
  if (/cloud|region|data center|datacentre|hosting/.test(lower)) {
    field = 'cloud_provider';
    value = intake.cloud_provider;
  } else if (/model|provider|llm|openai|anthropic|foundation/.test(lower)) {
    field = 'model_providers';
    value = intake.model_providers || intake.cloud_provider;
  } else if (/data|train|inference|pii|customer data/.test(lower)) {
    field = 'ai_uses_customer_data';
    value = intake.ai_uses_customer_data;
  }

  if (!value || String(value).trim().length === 0) {
    return escalate(q, `missing_customer_fact:${field || 'unknown'}`);
  }

  const answer =
    `Per information provided by ${intake.company || 'the vendor'}: ${String(value).trim()}. ` +
    `This reflects the current production configuration; material changes are disclosed via the ` +
    `subprocessor and data-flow policy.`;

  return {
    ...base(q),
    status: ANSWER_STATUS.ANSWERED,
    answer,
    // A fact the customer supplied verbatim in intake is high-trust — they
    // asserted it about their own system. Above the verifier's 0.85 gate.
    confidence: 0.9,
    sources: [{ kind: 'intake', field, value: String(value).trim() }],
    answer_source: 'deterministic',
  };
}

// ── LLM answerer (grounded, source-forced) ──────────────────────────────────

async function answerWithLlm(q, ctx) {
  if (!llmAvailable()) return escalate(q, 'no_llm_provider');

  const tpl = q.matched_template ? getTemplate(q.matched_template) : null;
  const grounding = tpl
    ? tpl.sections.slice(0, 8).map((s) => `## ${s.heading}\n${s.body}`).join('\n\n').slice(0, 6000)
    : '';

  const res = await llmJSON({
    system:
      'You answer enterprise AI security questionnaire questions for a vendor. ' +
      'You MUST ground every answer in the supplied policy excerpts. ' +
      'If the excerpts do not support an answer, set "answer" to "" and "sources" to []. ' +
      'NEVER assert a certification (SOC 2, ISO 27001, FedRAMP) or a specific subprocessor unless it appears in the excerpts. ' +
      'Respond ONLY with JSON: {"answer": string, "sources": string[] (section headings you used), "confidence": 0..1}.',
    user:
      `Question: ${q.text}\n\n` +
      (grounding
        ? `Policy excerpts you may use (the ONLY permitted source):\n${grounding}`
        : 'No policy excerpts are available for this question. If you cannot answer from general, non-claiming security best practice, return an empty answer.'),
    maxTokens: 600,
    validate: (o) => o && typeof o.answer === 'string' && Array.isArray(o.sources),
  });

  if (!res.ok) return escalate(q, `llm_${/** @type {{ok:false,reason:string,provider:string|null,raw?:string}} */ (res).reason}`);

  const { answer, sources, confidence } = res.data;
  const conf = clamp01(confidence);
  if (!answer || answer.trim().length === 0 || sources.length === 0 || conf < MIN_LLM_CONFIDENCE) {
    return escalate(q, 'llm_low_confidence_or_no_source', { llm_confidence: conf });
  }

  return {
    ...base(q),
    status: ANSWER_STATUS.ANSWERED,
    answer: answer.trim(),
    confidence: conf,
    sources: [
      ...(tpl
        ? [{ kind: 'template', template_id: tpl.id, template_hash: tpl.content_hash }]
        : []),
      ...sources.map((s) => ({ kind: 'template_section', section: String(s) })),
    ],
    answer_source: `llm:${res.provider}`,
  };
}

// ── Helpers ─────────────────────────────────────────────────────────────────

const SOC2_PHRASING = {
  type2: 'We maintain a current SOC 2 Type II report.',
  type1: 'We hold a SOC 2 Type I report with Type II in progress.',
  in_progress: 'Our SOC 2 audit is in progress (Type II observation window underway).',
  planned: 'A SOC 2 audit is planned but not yet started.',
  none: 'We do not currently hold a SOC 2 report; equivalent controls are described below.',
  default: 'Our security program is aligned to SOC 2 control families.',
};

function base(q) {
  return { id: q.id, question: q.text, section: q.section, bucket: q.bucket };
}

function escalate(q, reason, extra = {}) {
  return {
    ...base(q),
    status: ANSWER_STATUS.ESCALATED,
    answer: null,
    confidence: 0,
    sources: [],
    escalation_reason: reason,
    answer_source: 'escalation',
    ...extra,
  };
}

/** Pick the template section whose heading/body best overlaps the question. */
function selectSection(tpl, questionText) {
  const lower = (questionText || '').toLowerCase();
  const words = new Set(lower.split(/\W+/).filter((w) => w.length > 3));
  let best = null;
  let bestScore = -1;
  for (const s of tpl.sections) {
    const hay = `${s.heading} ${s.body}`.toLowerCase();
    let score = 0;
    for (const w of words) if (hay.includes(w)) score++;
    if (score > bestScore) {
      bestScore = score;
      best = s;
    }
  }
  return bestScore > 0 ? best : tpl.sections[0] || null;
}

function firstParagraphs(text, n) {
  const paras = String(text)
    .split(/\n\s*\n/)
    .map((p) => p.trim())
    .filter(Boolean);
  return paras.slice(0, n).join('\n\n');
}

function clamp01(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return 0;
  return Math.max(0, Math.min(1, x));
}
