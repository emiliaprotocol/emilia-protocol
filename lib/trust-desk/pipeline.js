/**
 * AI Trust Desk — pipeline orchestrator.
 *
 * @license Apache-2.0
 *
 * Runs an engagement intake → published trust page (or → escalated). Each stage
 * persists a status transition to the store so progress is observable and a
 * crashed run can be diagnosed. The deterministic path (extract → template
 * answers → verify → mint → sign) needs no external service; LLM/email/Slack
 * are progressive enhancements that degrade to escalation, not failure.
 *
 * Decision gate (from the verifier):
 *   auto    → publish, zero human touch
 *   partial → publish the verified answers, flag the rest for a reviewer
 *   full    → do not publish; escalate the whole packet
 */

import { extractQuestions, ExtractionUnsupportedError } from './extractor.js';
import { classifyQuestions } from './classifier.js';
import { answerAll } from './answerer.js';
import { verifyEngagement } from './verifier.js';
import { mintPolicies } from './policy-mint.js';
import { buildPolicyVars } from './policy-defaults.js';
import { mintTrustPage } from './minter.js';
import { notifyPublished, notifyEscalated } from './notify.js';
import { deriveSlug } from './ids.js';
import { setStatus, getEngagement, STATUS } from './store.js';
import { logger } from '../logger.js';

/**
 * @param {object} opts
 * @param {object} opts.engagement engagement record { engagement_id, intake, questionnaire_* }
 * @param {boolean} [opts.persist=true] write status transitions to the store
 * @returns {Promise<object>} pipeline result
 */
export async function runPipeline({ engagement, persist = true }) {
  const t0 = Date.now();
  const id = engagement.engagement_id;
  const intake = engagement.intake || {};
  const slug = engagement.slug || deriveSlug(intake.company, id);
  const log = logger.child ? logger.child({ engagement_id: id }) : logger;

  const persistStatus = async (status, extra) => {
    if (!persist || !id) return;
    if (await getEngagement(id)) await setStatus(id, status, extra);
  };

  try {
    // ── 1. EXTRACT ──
    await persistStatus(STATUS.EXTRACTING);
    let extraction;
    try {
      extraction = await extractQuestions({
        filePath: engagement.questionnaire_path,
        content: engagement.questionnaire_content,
        filename: engagement.questionnaire_filename,
      });
    } catch (err) {
      if (err instanceof ExtractionUnsupportedError) {
        return await finishEscalated({
          id, slug, persist, reason: `extraction_unsupported:${err.format}`,
          detail: err.message, engagement, t0,
        });
      }
      throw err;
    }
    log.info?.('trust-desk pipeline: extracted', {
      questions: extraction.total_questions,
      format: extraction.source_format,
    });
    if (extraction.total_questions === 0) {
      return await finishEscalated({
        id, slug, persist, reason: 'no_questions_extracted',
        detail: extraction.warnings.join('; ') || 'parser found no questions',
        engagement, t0,
      });
    }

    // ── 2. CLASSIFY ──
    await persistStatus(STATUS.CLASSIFYING);
    const classified = await classifyQuestions(extraction.questions, intake);

    // ── 3. ANSWER ──
    await persistStatus(STATUS.ANSWERING);
    const policyVars = buildPolicyVars(intake, { slug });
    const answers = await answerAll(classified, { intake, policyVars });

    // ── 4. VERIFY ──
    await persistStatus(STATUS.VERIFYING);
    const verification = verifyEngagement(answers, { intake });
    log.info?.('trust-desk pipeline: verified', {
      decision: verification.decision,
      ...verification.counts,
    });

    if (verification.decision === 'full') {
      return await finishEscalated({
        id, slug, persist, reason: 'verification_full_escalation',
        detail: `pass rate ${(verification.passRate * 100).toFixed(0)}% below threshold`,
        engagement, t0, verification, answers,
      });
    }

    // ── 5. MINT policies + trust page ──
    await persistStatus(STATUS.MINTING);
    // Content-only mint (no outDir) — the page-store owns persistence so this
    // works identically on the file backend and on Vercel (Supabase backend).
    const policies = mintPolicies({ intake, slug });
    const minted = await mintTrustPage({ engagement, answers, verification, policies, slug });

    // ── 6. NOTIFY + finalize ──
    const trustUrl = `https://www.emiliaprotocol.ai/trust-desk/c/${slug}`;
    const notify = await notifyPublished({ engagement, slug, trustUrl });
    if (verification.decision === 'partial') {
      // Publish what passed; flag the failures for a reviewer in parallel.
      await notifyEscalated({
        engagement,
        reason: `partial: ${verification.counts.failed} question(s) need review`,
        etaHours: 4,
      });
    }

    const result = {
      ok: true,
      outcome: verification.decision === 'partial' ? 'published_partial' : 'published',
      engagement_id: id,
      slug,
      trust_url: trustUrl,
      decision: verification.decision,
      counts: verification.counts,
      escalated_questions: answers.filter((a) => a.status !== 'answered').map((a) => ({
        id: a.id, reason: a.escalation_reason,
      })),
      policies: policies.map((p) => ({ doc_id: p.doc_id, content_hash: p.content_hash })),
      claims: minted.claims.map((c) => ({ id: c.id, claim_id: c.claim_id, content_hash: c.content_hash })),
      expires_at: minted.expires_at,
      duration_ms: Date.now() - t0,
      notify,
    };
    await persistStatus(STATUS.PUBLISHED, {
      slug,
      outcome: result.outcome,
      published_at: minted.published_at,
      expires_at: minted.expires_at,
      verification: { decision: verification.decision, counts: verification.counts },
    });
    return result;
  } catch (err) {
    log.error?.('trust-desk pipeline: failed', { error: err.message, stack: err.stack });
    await persistStatus(STATUS.FAILED, { error: err.message });
    return {
      ok: false,
      outcome: 'failed',
      engagement_id: id,
      slug,
      error: err.message,
      duration_ms: Date.now() - t0,
    };
  }
}

async function finishEscalated({ id, slug, persist, reason, detail, engagement, t0, verification, answers }) {
  const perQuestionEscalations = (answers || [])
    .filter((a) => a.status !== 'answered')
    .map((a) => ({ id: a.id, reason: a.escalation_reason }));

  if (persist && id && (await getEngagement(id))) {
    await setStatus(id, STATUS.ESCALATED, {
      escalation_reason: reason,
      escalation_detail: detail,
      slug,
      verification: verification
        ? { decision: verification.decision, counts: verification.counts }
        : undefined,
      escalated_questions: perQuestionEscalations,
    });
  }
  // Fire-and-forget customer notice; never block escalation on email.
  notifyEscalated({ engagement, reason, etaHours: reason.startsWith('extraction') ? 24 : 4 }).catch(
    () => {},
  );

  return {
    ok: true,
    outcome: 'escalated',
    engagement_id: id,
    slug,
    reason,
    detail,
    escalated_questions: perQuestionEscalations,
    verification: verification
      ? { decision: verification.decision, counts: verification.counts }
      : undefined,
    duration_ms: Date.now() - t0,
  };
}
