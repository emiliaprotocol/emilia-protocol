/**
 * AI Trust Desk — verification firewall.
 *
 * @license Apache-2.0
 *
 * Nothing publishes unless it clears these gates. The verifier is PURE CODE —
 * no LLM, no judgment call — so the quality bar is deterministic and auditable.
 * An answer that fails any gate is removed from the auto-publish set and routed
 * to the reviewer.
 *
 * Gates:
 *   1. source_exists      — at least one cited source
 *   2. source_hash_match  — cited template hash matches the live template hash
 *   3. confidence         — answer confidence ≥ threshold
 *   4. no_pii_leak        — no email/phone/SSN that the customer didn't supply
 *   5. forbidden_claims   — no certification claim unsupported by intake
 *   6. length_sanity      — answer length within bounds
 */

import { ANSWER_STATUS } from './answerer.js';
import { loadTemplates } from './templates-index.js';

const MIN_CONFIDENCE = 0.85;
const MIN_LEN = 40;
const MAX_LEN = 2000;

// Auto-publish only when ≥ this fraction of questions pass. Below it the whole
// packet escalates; in between, the packet publishes with failures flagged.
const FULL_ESCALATION_FAIL_RATE = 0.2;

const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
const PHONE_RE = /(?:\+?\d[\d\s().-]{7,}\d)/g;
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;

const CERT_CLAIMS = [
  { re: /\bsoc\s?2\s+type\s+(?:ii|2)\b/i, key: 'type2' },
  { re: /\bsoc\s?2\s+type\s+(?:i|1)\b/i, key: 'type1or2' },
  { re: /\biso\s?27001\b/i, key: 'iso27001' },
  { re: /\bfedramp\b/i, key: 'fedramp' },
  { re: /\bhitrust\b/i, key: 'hitrust' },
  { re: /\bpci[\s-]?dss\b/i, key: 'pci' },
];

/**
 * Verify a single answer against the 6 gates.
 * @param {object} answer answerer output (status === 'answered')
 * @param {object} ctx { intake }
 * @returns {{passed:boolean, failures:Array<{gate:string,detail:string}>}}
 */
export function verifyAnswer(answer, ctx = {}) {
  const failures = [];
  const intake = ctx.intake || {};
  const text = answer.answer || '';

  // Gate 1 — source exists
  if (!Array.isArray(answer.sources) || answer.sources.length === 0) {
    failures.push({ gate: 'source_exists', detail: 'no cited source' });
  }

  // Gate 2 — cited template hash matches the live template
  const templates = loadTemplates();
  for (const s of answer.sources || []) {
    if (s.kind === 'template' && s.template_id) {
      const live = templates.find((t) => t.id === s.template_id);
      if (!live) {
        failures.push({ gate: 'source_hash_match', detail: `unknown template ${s.template_id}` });
      } else if (s.template_hash && s.template_hash !== live.content_hash) {
        failures.push({
          gate: 'source_hash_match',
          detail: `template ${s.template_id} hash drift`,
        });
      }
    }
  }

  // Gate 3 — confidence threshold
  if (typeof answer.confidence !== 'number' || answer.confidence < MIN_CONFIDENCE) {
    failures.push({
      gate: 'confidence',
      detail: `confidence ${answer.confidence} < ${MIN_CONFIDENCE}`,
    });
  }

  // Gate 4 — PII leak (anything not supplied by the customer in intake)
  const allowed = allowedContacts(intake);
  for (const email of text.match(EMAIL_RE) || []) {
    if (!allowed.has(email.toLowerCase())) {
      failures.push({ gate: 'no_pii_leak', detail: `unexpected email: ${email}` });
    }
  }
  if (SSN_RE.test(text)) failures.push({ gate: 'no_pii_leak', detail: 'SSN pattern present' });
  // Phone numbers are noisy (version strings etc.) — only flag clearly formatted ones.
  for (const ph of text.match(PHONE_RE) || []) {
    const digits = ph.replace(/\D/g, '');
    if (digits.length >= 10 && digits.length <= 11) {
      failures.push({ gate: 'no_pii_leak', detail: `phone-like sequence: ${ph.trim()}` });
    }
  }

  // Gate 5 — forbidden certification claims not backed by intake
  for (const claim of CERT_CLAIMS) {
    if (claim.re.test(text) && !certSupported(claim.key, intake)) {
      failures.push({
        gate: 'forbidden_claims',
        detail: `claims ${claim.key} but intake does not support it`,
      });
    }
  }

  // Gate 6 — length sanity
  if (text.length < MIN_LEN) {
    failures.push({ gate: 'length_sanity', detail: `too short (${text.length} chars)` });
  } else if (text.length > MAX_LEN) {
    failures.push({ gate: 'length_sanity', detail: `too long (${text.length} chars)` });
  }

  return { passed: failures.length === 0, failures };
}

/**
 * Verify a whole engagement's answers and decide the publish path.
 * @param {Array} answers answerer outputs (mixed answered/escalated)
 * @param {object} ctx { intake }
 * @returns {{decision:'auto'|'partial'|'full', passRate:number, perQuestion:Array, counts:object}}
 */
export function verifyEngagement(answers, ctx = {}) {
  const perQuestion = answers.map((a) => {
    if (a.status !== ANSWER_STATUS.ANSWERED) {
      return { id: a.id, status: a.status, passed: false, failures: [{ gate: 'answered', detail: a.escalation_reason || 'not answered' }] };
    }
    const v = verifyAnswer(a, ctx);
    return { id: a.id, status: a.status, passed: v.passed, failures: v.failures };
  });

  const total = perQuestion.length || 1;
  const passed = perQuestion.filter((p) => p.passed).length;
  const failed = total - passed;
  const failRate = failed / total;
  const passRate = passed / total;

  let decision;
  if (failed === 0) decision = 'auto';
  else if (failRate <= FULL_ESCALATION_FAIL_RATE) decision = 'partial';
  else decision = 'full';

  return {
    decision,
    passRate,
    perQuestion,
    counts: { total, passed, failed },
  };
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function allowedContacts(intake) {
  const set = new Set();
  for (const v of [intake.contact_email, intake.data_officer_email, intake.security_lead_email]) {
    if (v) set.add(String(v).toLowerCase());
  }
  // The vendor's own domain emails are fine (owner fields reference them).
  return set;
}

function certSupported(key, intake) {
  const soc2 = intake.soc2_status;
  switch (key) {
    case 'type2':
      return soc2 === 'type2';
    case 'type1or2':
      return soc2 === 'type1' || soc2 === 'type2';
    case 'iso27001':
      return intake.iso27001 === true || /iso\s?27001/i.test(intake.certifications || '');
    case 'fedramp':
      return intake.fedramp === true || /fedramp/i.test(intake.certifications || '');
    case 'hitrust':
      return /hitrust/i.test(intake.certifications || '');
    case 'pci':
      return /pci/i.test(intake.certifications || '');
    default:
      return false;
  }
}
