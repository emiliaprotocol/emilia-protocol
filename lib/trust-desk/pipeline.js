// Generated from pipeline.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
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
 *   auto    → answers cleared machine verification
 *   partial → some answers cleared; the rest are flagged for the reviewer
 *   full    → nothing cleared; escalate the whole packet, never publish
 *
 * A named human signs off before anything becomes public. The pipeline runs
 * extract → classify → answer → verify and then PARKS at `awaiting_review`
 * with the prepared answers persisted. Publication happens only when
 * `publishReviewed()` is called with a reviewer identity, which is recorded on
 * the engagement. Nothing reaches a buyer's screen on a machine decision alone:
 * these answers go to a bank's risk team under the customer's name, so the
 * liability sits with a person who read them.
 *
 * Set TRUST_DESK_REQUIRE_REVIEW=false to restore straight-through publishing
 * (development and fixtures only; it is on by default).
 */
import { extractQuestions, ExtractionUnsupportedError } from './extractor.js';
import { classifyQuestions } from './classifier.js';
import { answerAll } from './answerer.js';
import { verifyEngagement } from './verifier.js';
import { mintPolicies } from './policy-mint.js';
import { buildPolicyVars } from './policy-defaults.js';
import { mintTrustPage } from './minter.js';
import { notifyPublished, notifyEscalated, notifyInternal } from './notify.js';
import { emitTrustPageReceipt } from './ep-receipt.js';
import { deriveSlug } from './ids.js';
import { compareAndSetStatus, setStatus, getEngagement, STATUS } from './store.js';
import { logger } from '../logger.js';
import { assertQuestionnaireWithinBudget, createTrustDeskLlmBudget, TrustDeskResourceLimitError, } from './resource-budget.js';
/**
 * Pipeline orchestrator.
 */
export async function runPipeline({ engagement, persist = true, llmBudgetOptions, }) {
    const t0 = Date.now();
    // Start the model deadline before extraction so parser time cannot be added
    // on top of the route's fixed execution contract.
    const llmBudget = createTrustDeskLlmBudget((llmBudgetOptions || {}));
    const id = engagement.engagement_id;
    const intake = engagement.intake || {};
    const slug = engagement.slug || deriveSlug(intake.company, id);
    const log = logger.child ? logger.child({ engagement_id: id }) : logger;
    const persistStatus = async (status, extra) => {
        if (!persist || !id)
            return;
        if (await getEngagement(id))
            await setStatus(id, status, extra);
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
        }
        catch (err) {
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
        try {
            assertQuestionnaireWithinBudget(extraction.questions);
        }
        catch (err) {
            if (err instanceof TrustDeskResourceLimitError) {
                return await finishEscalated({
                    id,
                    slug,
                    persist,
                    reason: err.code === 'question_count_exceeded'
                        ? 'questionnaire_question_limit'
                        : 'questionnaire_text_limit',
                    detail: err.message,
                    engagement,
                    t0,
                });
            }
            throw err;
        }
        // One engagement-scoped budget is shared across classification and
        // answering so two individually bounded phases cannot multiply the bill.
        // ── 2. CLASSIFY ──
        await persistStatus(STATUS.CLASSIFYING);
        const classified = await classifyQuestions(extraction.questions, intake, { llmBudget });
        // ── 3. ANSWER ──
        await persistStatus(STATUS.ANSWERING);
        const policyVars = buildPolicyVars(intake, { slug });
        const answers = await answerAll(classified, { intake, policyVars, llmBudget });
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
        // ── 5. PARK FOR HUMAN SIGN-OFF ──
        // Everything above is machine work. Publication is a person's decision, so
        // the prepared answers are persisted and the run stops here until
        // publishReviewed() is called with a reviewer identity.
        if (requiresReview()) {
            await persistStatus(STATUS.AWAITING_REVIEW, {
                slug,
                answers,
                verification: { decision: verification.decision, counts: verification.counts },
                prepared_at: new Date().toISOString(),
            });
            await notifyInternal(`Trust Desk: engagement ${id} (${intake.company || 'unknown company'}) is prepared and `
                + `awaiting sign-off. Verification ${verification.decision}, `
                + `${verification.counts.failed} of ${answers.length} question(s) need attention. `
                + `Review at /trust-desk/review/${id}`);
            return {
                ok: true,
                outcome: 'awaiting_review',
                engagement_id: id,
                slug,
                decision: verification.decision,
                counts: verification.counts,
                escalated_questions: answers.filter((a) => a.status !== 'answered').map((a) => ({
                    id: a.id, reason: a.escalation_reason,
                })),
                duration_ms: Date.now() - t0,
            };
        }
        // ── 5b. MINT policies + trust page (review disabled) ──
        await persistStatus(STATUS.MINTING);
        // Content-only mint (no outDir) — the page-store owns persistence so this
        // works identically on the file backend and on Vercel (Supabase backend).
        const policies = mintPolicies({ intake, slug });
        const minted = await mintTrustPage({ engagement, answers, verification, policies, slug });
        // ── 6. NOTIFY + finalize ──
        const trustUrl = `https://www.emiliaprotocol.ai/trust-desk/c/${slug}`;
        // EP secures EP — emit a real protocol receipt for this publish (best-effort,
        // gated on TRUST_DESK_EP_RECEIPTS; never fails a publish).
        const epReceipt = await emitTrustPageReceipt({ engagement, slug, trustUrl, verification, minted });
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
            ep_receipt: epReceipt,
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
    }
    catch (err) {
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
async function finishEscalated({ id, slug, persist, reason, detail, engagement, t0, verification, answers, }) {
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
    notifyEscalated({
        engagement,
        reason,
        etaHours: reason.startsWith('extraction') ? 24 : 4,
    }).catch(() => { });
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
/**
 * Is a human sign-off required before publication? On by default. Only a
 * deliberate opt-out disables it, so a missing or misspelled env var fails
 * toward review rather than toward publishing.
 */
export function requiresReview() {
    return process.env.TRUST_DESK_REQUIRE_REVIEW !== 'false';
}
/**
 * Publish an engagement a named human has signed off on.
 *
 * Mints the policy docs and the trust page from the answers prepared by
 * runPipeline, records who approved and when, and emits the protocol receipt.
 * Refuses anything not sitting at `awaiting_review`, so an approval cannot be
 * replayed against an engagement that already published.
 */
export async function publishReviewed({ engagementId, reviewer, note, }) {
    const t0 = Date.now();
    const log = logger.child ? logger.child({ engagement_id: engagementId }) : logger;
    if (!reviewer || typeof reviewer !== 'string' || !reviewer.trim()) {
        return { ok: false, error: 'reviewer_required', detail: 'a named reviewer is required to publish' };
    }
    let engagement = await getEngagement(engagementId);
    if (!engagement)
        return { ok: false, error: 'engagement_not_found' };
    if (engagement.status !== STATUS.AWAITING_REVIEW) {
        return {
            ok: false,
            error: 'not_awaiting_review',
            detail: `engagement is ${engagement.status}, not ${STATUS.AWAITING_REVIEW}`,
        };
    }
    const answers = engagement.answers;
    if (!Array.isArray(answers) || answers.length === 0) {
        return { ok: false, error: 'no_prepared_answers' };
    }
    const intake = engagement.intake || {};
    const slug = engagement.slug || deriveSlug(intake.company, engagementId);
    const verification = engagement.verification || { decision: 'partial', counts: {} };
    const approvedAt = new Date().toISOString();
    try {
        const claimed = await compareAndSetStatus(engagementId, STATUS.AWAITING_REVIEW, STATUS.MINTING, { reviewer: reviewer.trim(), approved_at: approvedAt });
        if (!claimed.ok || !claimed.record) {
            return {
                ok: false,
                error: claimed.reason === 'not_found' ? 'engagement_not_found' : 'not_awaiting_review',
                detail: claimed.record ? `engagement is ${claimed.record.status}` : undefined,
            };
        }
        const claimedEngagement = claimed.record;
        engagement = claimedEngagement;
        const policies = mintPolicies({ intake, slug });
        const minted = await mintTrustPage({ engagement: claimedEngagement, answers, verification, policies, slug });
        const trustUrl = `https://www.emiliaprotocol.ai/trust-desk/c/${slug}`;
        const epReceipt = await emitTrustPageReceipt({
            engagement: claimedEngagement, slug, trustUrl, verification, minted,
        });
        const notify = await notifyPublished({ engagement: claimedEngagement, slug, trustUrl });
        await setStatus(engagementId, STATUS.PUBLISHED, {
            slug,
            outcome: verification.decision === 'partial' ? 'published_partial' : 'published',
            reviewer,
            approved_at: approvedAt,
            review_note: note || null,
            published_at: minted.published_at,
            expires_at: minted.expires_at,
        });
        return {
            ok: true,
            outcome: verification.decision === 'partial' ? 'published_partial' : 'published',
            engagement_id: engagementId,
            slug,
            trust_url: trustUrl,
            reviewer,
            approved_at: approvedAt,
            decision: verification.decision,
            counts: verification.counts,
            policies: policies.map((p) => ({ doc_id: p.doc_id, content_hash: p.content_hash })),
            claims: minted.claims.map((c) => ({ id: c.id, claim_id: c.claim_id, content_hash: c.content_hash })),
            expires_at: minted.expires_at,
            ep_receipt: epReceipt,
            duration_ms: Date.now() - t0,
            notify,
        };
    }
    catch (err) {
        log.error?.('trust-desk publishReviewed: failed', { error: err.message });
        await setStatus(engagementId, STATUS.FAILED, { error: err.message, reviewer });
        return { ok: false, error: 'publish_failed', detail: err.message };
    }
}
/**
 * Reject a prepared engagement. Nothing is published and the reason is recorded
 * against the reviewer, so a decision not to publish leaves the same trail as a
 * decision to publish.
 */
export async function rejectReviewed({ engagementId, reviewer, reason, }) {
    if (!reviewer?.trim())
        return { ok: false, error: 'reviewer_required' };
    if (!reason?.trim())
        return { ok: false, error: 'reason_required' };
    const engagement = await getEngagement(engagementId);
    if (!engagement)
        return { ok: false, error: 'engagement_not_found' };
    if (engagement.status !== STATUS.AWAITING_REVIEW) {
        return { ok: false, error: 'not_awaiting_review', detail: `engagement is ${engagement.status}` };
    }
    const rejectedAt = new Date().toISOString();
    const claimed = await compareAndSetStatus(engagementId, STATUS.AWAITING_REVIEW, STATUS.REJECTED, { reviewer: reviewer.trim(), reason: reason.trim(), rejected_at: rejectedAt });
    if (!claimed.ok) {
        return {
            ok: false,
            error: claimed.reason === 'not_found' ? 'engagement_not_found' : 'not_awaiting_review',
            detail: claimed.record ? `engagement is ${claimed.record.status}` : undefined,
        };
    }
    await notifyEscalated({
        engagement,
        reason: `reviewer ${reviewer} rejected: ${reason}`,
        etaHours: 24,
    });
    return { ok: true, outcome: 'rejected', engagement_id: engagementId, reviewer, reason, rejected_at: rejectedAt };
}
