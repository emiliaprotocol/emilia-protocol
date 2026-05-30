/**
 * AI Trust Desk — LLM client with graceful degradation.
 *
 * @license Apache-2.0
 *
 * Provider order: Anthropic (ANTHROPIC_API_KEY) → OpenAI (OPENAI_API_KEY).
 * No SDK dependency — both are called over `fetch` so the pipeline adds zero
 * packages. When neither key is present, `llmAvailable()` is false and the
 * pipeline routes every non-deterministic question to the reviewer queue
 * instead of guessing. That is the whole safety story: no key → no
 * hallucination, just escalation.
 *
 * Every call returns structured JSON validated against a caller-supplied
 * predicate. Malformed output → { ok:false } so callers fail closed.
 */

import { logger } from '../logger.js';

const ANTHROPIC_URL = 'https://api.anthropic.com/v1/messages';
const OPENAI_URL = 'https://api.openai.com/v1/chat/completions';

// Defaults are current (verified against the live /v1/models list). Override
// per-deploy with TRUST_DESK_ANTHROPIC_MODEL / TRUST_DESK_OPENAI_MODEL.
const ANTHROPIC_MODEL = process.env.TRUST_DESK_ANTHROPIC_MODEL || 'claude-sonnet-4-6';
const OPENAI_MODEL = process.env.TRUST_DESK_OPENAI_MODEL || 'gpt-4o';

const DEFAULT_TIMEOUT_MS = 45_000;

/** @returns {boolean} whether any provider key is configured. */
export function llmAvailable() {
  return Boolean(process.env.ANTHROPIC_API_KEY || process.env.OPENAI_API_KEY);
}

/** @returns {'anthropic'|'openai'|null} the active provider. */
export function activeProvider() {
  if (process.env.ANTHROPIC_API_KEY) return 'anthropic';
  if (process.env.OPENAI_API_KEY) return 'openai';
  return null;
}

/**
 * Call the active LLM and parse a single JSON object from its reply.
 *
 * @param {object} opts
 * @param {string} opts.system  system prompt
 * @param {string} opts.user    user prompt (should request JSON only)
 * @param {number} [opts.maxTokens=900]
 * @param {number} [opts.temperature=0]
 * @param {(obj:any)=>boolean} [opts.validate] predicate; reject parse if false
 * @returns {Promise<{ok:true,data:any,provider:string,usage?:object}|{ok:false,reason:string,provider:string|null,raw?:string}>}
 */
export async function llmJSON({ system, user, maxTokens = 900, temperature = 0, validate } = {}) {
  const provider = activeProvider();
  if (!provider) return { ok: false, reason: 'no_provider', provider: null };

  let raw;
  let usage;
  try {
    if (provider === 'anthropic') {
      ({ raw, usage } = await callAnthropic({ system, user, maxTokens, temperature }));
    } else {
      ({ raw, usage } = await callOpenAI({ system, user, maxTokens, temperature }));
    }
  } catch (err) {
    logger.warn('trust-desk llm: provider call failed', { provider, error: err.message });
    return { ok: false, reason: `provider_error: ${err.message}`, provider };
  }

  const parsed = parseJsonObject(raw);
  if (parsed === undefined) {
    return { ok: false, reason: 'unparseable_json', provider, raw };
  }
  if (validate && !safeValidate(validate, parsed)) {
    return { ok: false, reason: 'schema_validation_failed', provider, raw };
  }
  return { ok: true, data: parsed, provider, usage };
}

// ── Providers ───────────────────────────────────────────────────────────────

async function callAnthropic({ system, user, maxTokens, temperature }) {
  const res = await fetchWithTimeout(ANTHROPIC_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: ANTHROPIC_MODEL,
      max_tokens: maxTokens,
      temperature,
      system,
      messages: [{ role: 'user', content: user }],
    }),
  });
  if (!res.ok) throw new Error(`anthropic ${res.status}: ${await safeText(res)}`);
  const json = await res.json();
  const raw = Array.isArray(json.content)
    ? json.content.filter((c) => c.type === 'text').map((c) => c.text).join('')
    : '';
  return { raw, usage: json.usage };
}

async function callOpenAI({ system, user, maxTokens, temperature }) {
  const res = await fetchWithTimeout(OPENAI_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: OPENAI_MODEL,
      max_tokens: maxTokens,
      temperature,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
    }),
  });
  if (!res.ok) throw new Error(`openai ${res.status}: ${await safeText(res)}`);
  const json = await res.json();
  const raw = json.choices?.[0]?.message?.content ?? '';
  return { raw, usage: json.usage };
}

// ── Helpers ─────────────────────────────────────────────────────────────────

async function fetchWithTimeout(url, init, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function safeText(res) {
  try {
    return (await res.text()).slice(0, 300);
  } catch {
    return '<unreadable>';
  }
}

function safeValidate(fn, obj) {
  try {
    return Boolean(fn(obj));
  } catch {
    return false;
  }
}

/**
 * Parse the first JSON object found in a model reply. Tolerates code fences
 * and leading/trailing prose. Returns undefined when nothing parses.
 */
export function parseJsonObject(text) {
  if (typeof text !== 'string') return undefined;
  const trimmed = text.trim();

  // Fast path: clean JSON.
  try {
    return JSON.parse(trimmed);
  } catch {
    /* fall through */
  }

  // Strip ```json … ``` fences.
  const fence = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) {
    try {
      return JSON.parse(fence[1].trim());
    } catch {
      /* fall through */
    }
  }

  // Last resort: first balanced { … } span.
  const start = trimmed.indexOf('{');
  const end = trimmed.lastIndexOf('}');
  if (start !== -1 && end > start) {
    try {
      return JSON.parse(trimmed.slice(start, end + 1));
    } catch {
      /* fall through */
    }
  }
  return undefined;
}
