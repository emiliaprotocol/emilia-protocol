// Generated from minter.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * AI Trust Desk — trust-page minter.
 *
 * @license Apache-2.0
 *
 * Builds the published trust-page document from a completed pipeline run and
 * persists it via the page-store (file or Supabase). Every claim carries a
 * NON-NULL content_hash bound to a real artifact, and a STORED signed envelope
 * (reproducible HMAC) so a buyer verifies the same signature the page shows.
 */
import { signClaim, hashClaim } from './hash.js';
import { getSigningKey } from './signing.js';
import { shortClaimId } from './ids.js';
import { putPublishedPage } from './page-store.js';
import { logger } from '../logger.js';
/**
 * @param opts.engagement   the engagement record (intake + ids)
 * @param opts.answers      answerer outputs
 * @param opts.verification verifyEngagement() result
 * @param opts.policies     mintPolicies() result (each has .content)
 */
export async function mintTrustPage({ engagement, answers, verification, policies, slug, expiryMonths = 6, }) {
    const intake = engagement.intake || engagement;
    const key = getSigningKey();
    const now = new Date();
    const publishedAt = now.toISOString();
    const expiresAt = addMonths(now, expiryMonths).toISOString();
    const answered = answers.filter((a) => a.status === 'answered');
    const escalated = answers.filter((a) => a.status !== 'answered');
    // ── Answers payload (buyer-facing Q&A artifact; content_hash source) ──
    const answersPayload = {
        slug,
        generated_at: publishedAt,
        total_questions: answers.length,
        answered: answered.length,
        escalated: escalated.length,
        items: answers.map((a) => ({
            id: a.id,
            question: a.question,
            section: a.section,
            status: a.status,
            answer: a.answer,
            sources: a.sources,
            confidence: a.confidence,
            escalation_reason: a.escalation_reason || null,
        })),
    };
    // ── Assemble claims ──
    const rawClaims = [];
    // 1) Questionnaire response claim
    rawClaims.push({
        id: 'questionnaire-response',
        title: 'Completed AI security questionnaire',
        category: 'questionnaire',
        source_file: `${slug}/answers.json`,
        summary: `Answered ${answered.length} of ${answers.length} questions ` +
            `(${verification.counts.passed} verified-source). ` +
            `Aligned with SOC 2 and NIST AI RMF.`,
        bullets: answered.slice(0, 4).map((a) => truncate(a.question, 90)),
        content_hash: hashClaim(answersPayload),
        policy_version: '1.0',
    });
    // 2) One claim per minted policy doc
    for (const p of policies) {
        rawClaims.push({
            id: p.doc_id,
            title: p.title,
            category: 'policy',
            source_file: `${slug}/policies/${p.filename}`,
            summary: `Signed policy document (${p.bytes.toLocaleString()} bytes). Hash binds to published text.`,
            bullets: sectionHeadings(p.content),
            content_hash: p.content_hash,
            policy_version: '1.0',
        });
    }
    // ── Sign each claim once (stable, reproducible envelope) ──
    const claims = rawClaims.map((c) => {
        const envelope = signClaim({
            claim_id_source: c.id,
            customer: slug,
            source_file: c.source_file,
            content_hash: c.content_hash,
            title: c.title,
        }, key);
        return {
            ...c,
            claim_id: envelope.claim_id || shortClaimId(envelope.payload_hash),
            payload_hash: envelope.payload_hash,
            signed_at: envelope.signed_at,
            signer: envelope.signer,
            signature: envelope.signature,
        };
    });
    // ── Build + persist the published document ──
    const doc = {
        slug,
        company: intake.company,
        website: intake.website || null,
        contact: {
            name: intake.contact_name || null,
            email: intake.contact_email || null,
            role: intake.contact_role || 'Security Contact',
        },
        product_tagline: intake.product_description || null,
        engagement: {
            tier: intake.tier_preference || intake.tier || 'packet',
            buyer_name: intake.buyer_name || null,
            started_at: (engagement.created_at || publishedAt).slice(0, 10),
            delivered_at: publishedAt.slice(0, 10),
            expires_at: expiresAt.slice(0, 10),
        },
        status: 'active',
        last_rehashed: publishedAt,
        generated_by: 'trust-desk-pipeline',
        pipeline: {
            engagement_id: engagement.engagement_id,
            decision: verification.decision,
            pass_rate: Number(verification.passRate.toFixed(3)),
            escalated_questions: escalated.length,
        },
        claims,
    };
    await putPublishedPage({
        slug,
        doc,
        policies: policies.map((p) => ({
            doc_id: p.doc_id,
            filename: p.filename,
            content: p.content,
            content_hash: p.content_hash,
        })),
        answers: answersPayload,
    });
    logger.info('trust-desk: minted trust page', {
        slug,
        claims: claims.length,
        decision: verification.decision,
    });
    return { slug, claims, expires_at: expiresAt, published_at: publishedAt };
}
// ── Helpers ─────────────────────────────────────────────────────────────────
function sectionHeadings(content) {
    return String(content || '')
        .split('\n')
        .filter((l) => /^##\s+/.test(l))
        .slice(0, 5)
        .map((l) => l.replace(/^##\s+/, '').replace(/^[\d.]+\s*/, '').trim());
}
function truncate(s, n) {
    const str = String(s || '');
    return str.length > n ? `${str.slice(0, n - 1)}…` : str;
}
function addMonths(date, months) {
    const d = new Date(date);
    d.setMonth(d.getMonth() + months);
    return d;
}
