/**
 * EP-COVERAGE-VERDICT-v1 — derive one verdict for one published declaration.
 *
 * Two invariants are enforced in code rather than left to editorial care,
 * because both of them are the difference between a defensible public record
 * and a liability:
 *
 *   1. A verdict never asserts anything about runtime behaviour. Every emitted
 *      sentence is a statement about a document as published on a date. See
 *      `assertVerdictIsDocumentClaim`.
 *   2. A candidate always carries the exact quoted span that produced it, plus a
 *      digest over the canonical assessed text. Without the span a
 *      target cannot see what to fix; without the digest nobody can prove which
 *      field projection was assessed.
 */

import crypto from 'node:crypto';
import { CATEGORIES, VERDICTS, AUTHORIZATION_PHRASES, NEGATION_PREFIXES, READ_ONLY_MARKERS, READ_ONLY_EXEMPT_CATEGORIES, RUBRIC_VERSION } from './rubric.mjs';

export const VERDICT_PROFILE = 'EP-COVERAGE-VERDICT-v1';

/** Words that must never appear in a published verdict sentence. */
const FORBIDDEN_RUNTIME_WORDS = Object.freeze([
  'vulnerable', 'vulnerability', 'insecure', 'exploit', 'unprotected',
  'does not require', 'fails to require', 'no approval is required',
  'unsafe', 'breach', 'flaw',
]);

/**
 * The declaration text we classify, assembled in a fixed order so the digest is
 * stable. Only fields the target itself published to the public registry.
 */
export function declarationText(server) {
  return [server?.name ?? '', server?.title ?? '', server?.description ?? '']
    .join('\n')
    .trim();
}

export function declarationDigest(text) {
  return `sha256:${crypto.createHash('sha256').update(text, 'utf8').digest('hex')}`;
}

/**
 * Digest over the prose ONLY, excluding the target name. Used to detect one
 * vendor republishing identical boilerplate across many registry entries, which
 * would otherwise inflate every count. The full `declaration_digest` keeps the
 * name because it pins the exact bytes assessed for reproduction; this one
 * deliberately drops it so N differently-named twins collapse to one.
 */
export function boilerplateDigest(server) {
  const prose = [server?.title ?? '', server?.description ?? ''].join('\n').trim().toLowerCase();
  return `sha256:${crypto.createHash('sha256').update(prose, 'utf8').digest('hex')}`;
}

/** True when the text immediately before `at` negates the capability. */
export function isNegated(haystackLower, at) {
  const before = haystackLower.slice(Math.max(0, at - 28), at);
  return NEGATION_PREFIXES.some((p) => before.endsWith(p));
}

/**
 * Find the first NON-NEGATED occurrence. Scanning only the first occurrence
 * would let a single negated mention mask a later genuine one, so walk them all.
 */
function findSpan(haystackLower, original, needle) {
  let at = haystackLower.indexOf(needle);
  while (at >= 0) {
    if (!isNegated(haystackLower, at)) {
      const start = Math.max(0, at - 40);
      const end = Math.min(original.length, at + needle.length + 40);
      return {
        matched: needle,
        quote: original.slice(start, end).replace(/\s+/g, ' ').trim(),
      };
    }
    at = haystackLower.indexOf(needle, at + needle.length);
  }
  return null;
}

/**
 * Classify one registry record.
 *
 * `asOf` is the edition date and is REQUIRED. It is never defaulted to the
 * current clock: a verdict with an implicit date is not reproducible, and
 * reproducibility is the only thing that makes this record worth citing.
 */
export function deriveVerdict(server, asOf) {
  if (!asOf || !/^\d{4}-\d{2}-\d{2}$/.test(asOf)) {
    throw new Error('deriveVerdict requires asOf as YYYY-MM-DD; refusing to stamp an undated verdict');
  }

  const text = declarationText(server);
  const digest = declarationDigest(text);
  const lower = text.toLowerCase();

  const base = {
    profile: VERDICT_PROFILE,
    rubric: RUBRIC_VERSION,
    target: server?.name ?? null,
    as_of: asOf,
    declaration_digest: digest,
    scope_limit:
      'Registry-declaration signal only: the advertised name, title and description as published to the public MCP registry. Not a tool-level scan, not a runtime observation, not a vulnerability claim.',
  };

  if (!text) {
    return finalize({ ...base, verdict: 'INDETERMINATE', categories: [], evidence: [], reason: 'empty declaration' });
  }

  const readOnly = READ_ONLY_MARKERS.some((m) => lower.includes(m));

  const categories = [];
  const evidence = [];
  for (const category of CATEGORIES) {
    if (readOnly && !READ_ONLY_EXEMPT_CATEGORIES.includes(category.id)) continue;
    for (const kw of category.keywords) {
      const span = findSpan(lower, text, kw);
      if (span) {
        categories.push(category.id);
        evidence.push({ category: category.id, ...span });
        break;
      }
    }
  }

  if (categories.length === 0) {
    return finalize({
      ...base,
      verdict: 'NO_MATCHING_CATEGORY_SIGNAL',
      categories: [],
      evidence: [],
      ...(readOnly ? { self_described_read_only: true } : {}),
    });
  }

  const authorization = [];
  for (const phrase of AUTHORIZATION_PHRASES) {
    const span = findSpan(lower, text, phrase);
    if (span) authorization.push(span);
  }

  return finalize({
    ...base,
    verdict: authorization.length > 0 ? 'DECLARED_AUTHORIZATION_SIGNAL' : 'DECLARATION_SILENT_CANDIDATE',
    categories,
    evidence,
    authorization_evidence: authorization,
  });
}

function renderSentence(verdictId, asOf, categories) {
  const labels = categories
    .map((id) => CATEGORIES.find((c) => c.id === id)?.label ?? id)
    .join(', ');
  return VERDICTS[verdictId].sentence
    .replace('{date}', asOf)
    .replace('{categories}', labels || 'a consequential capability');
}

function finalize(v) {
  const sentence = renderSentence(v.verdict, v.as_of, v.categories);
  assertVerdictIsDocumentClaim(sentence);
  return Object.freeze({
    ...v,
    is_finding: VERDICTS[v.verdict].is_finding,
    requires_review: VERDICTS[v.verdict].requires_review,
    sentence,
    remedy: VERDICTS[v.verdict].is_finding
      ? 'Publish a human-authorization precondition in the registry declaration. The verdict changes on the next edition.'
      : null,
  });
}

/** Apply a declaration-bound human disposition to an automated candidate. */
export function applyHumanReview(verdict, review) {
  if (verdict.verdict !== 'DECLARATION_SILENT_CANDIDATE' || verdict.requires_review !== true) {
    throw new Error(`review supplied for non-candidate verdict ${verdict.verdict}`);
  }
  const reviewedVerdict = review.state === 'confirmed'
    ? 'DECLARATION_SILENT_CONFIRMED'
    : 'CANDIDATE_REJECTED';
  return finalize({ ...verdict, verdict: reviewedVerdict, review });
}

/**
 * Fail closed on wording. If a sentence would only be true given an assumption
 * about the target's runtime, it must not ship.
 */
export function assertVerdictIsDocumentClaim(sentence) {
  const lower = sentence.toLowerCase();
  for (const bad of FORBIDDEN_RUNTIME_WORDS) {
    if (lower.includes(bad)) {
      throw new Error(
        `verdict sentence makes a runtime claim (${JSON.stringify(bad)}); verdicts must be facts about the published declaration only`,
      );
    }
  }
  if (!lower.startsWith('as published on ')) {
    throw new Error('verdict sentence must open with "As published on <date>" so the claim is explicitly dated and scoped');
  }
  return true;
}
