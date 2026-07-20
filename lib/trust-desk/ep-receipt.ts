/**
 * AI Trust Desk — "EP secures EP" dogfood.
 * @license Apache-2.0
 *
 * Every successful Trust Desk publish can ALSO emit a real EMILIA Protocol
 * receipt via the canonical write path — so the product that sells trust is
 * itself recorded on the protocol it sells.
 *
 * SAFETY POSTURE:
 *   - Gated on TRUST_DESK_EP_RECEIPTS === '1' (DEFAULT OFF). With the flag unset,
 *     this is a no-op and nothing touches Supabase — the file-backend pipeline,
 *     the CLI, and tests stay hermetic.
 *   - Best-effort: wrapped in a total try/catch. A ledger failure NEVER fails a
 *     publish. Returns { receipt_id, receipt_hash } on success, else null.
 *   - Dynamic imports keep the Supabase/canonical-writer code out of the
 *     deterministic CLI subtree unless actually invoked.
 */

import { logger } from '../logger.js';

const SUBMITTER = 'emilia-trust-desk';

function enabled() {
  return process.env.TRUST_DESK_EP_RECEIPTS === '1';
}

/**
 * Idempotently ensure the desk + subject entities exist. Best-effort.
 * @param {string} subjectId entity_id for the trust-page subject (`td-${slug}`)
 * @param {string|null} company display name for the subject entity, if known
 * @returns {Promise<boolean>} true if both present/created
 */
async function resolveDeskEntities(subjectId, company) {
  try {
    const { getServiceClient } = await import('../supabase.js');
    const sb = getServiceClient();
    const rows = [
      {
        entity_id: SUBMITTER,
        display_name: 'EMILIA Trust Desk',
        entity_type: 'service_provider',
        description: 'Automated AI security trust-page service operated by EMILIA Protocol.',
      },
      {
        entity_id: subjectId,
        display_name: company || subjectId,
        entity_type: 'service_provider',
        description: `AI vendor with a published EMILIA Trust Desk page (${subjectId}).`,
      },
    ];
    await sb.from('entities').upsert(rows, { onConflict: 'entity_id', ignoreDuplicates: true });
    return true;
  } catch (err) {
    logger.warn('trust-desk dogfood: entity resolve failed', { error: err.message });
    return false;
  }
}

/**
 * Emit a provenance_check receipt for a freshly published trust page.
 * @param {object} opts
 * @param {{intake?: {company?: string}}} opts.engagement engagement record { engagement_id, intake, ... }; intake.company feeds the subject display name
 * @param {string} opts.slug
 * @param {string} opts.trustUrl
 * @param {{decision?: string}} opts.verification
 * @param {{claims?: Array<{content_hash?: string}>, published_at?: string}} opts.minted
 * @returns {Promise<{receipt_id:string|null, receipt_hash:string|null}|null>}
 */
export async function emitTrustPageReceipt({ engagement, slug, trustUrl, verification, minted }) {
  if (!enabled()) return null;
  try {
    const subjectId = `td-${slug}`;
    const company = engagement?.intake?.company || null;
    await resolveDeskEntities(subjectId, company);

    const { canonicalSubmitReceipt } = await import('../canonical-writer.js');
    const { signingKeyFingerprint } = await import('./signing.js');

    const claimHashes = (minted?.claims || []).map((c) => c.content_hash).filter(Boolean);
    const onTarget = verification?.decision !== 'partial';

    // canonicalSubmitReceipt's own JSDoc types this as Promise<Object> (via
    // createReceipt's { receipt, entityScore, warnings } or { error, status }
    // shape) — re-assert the shape actually produced/consumed here rather
    // than widen to any, matching the pattern in lib/protocol-write.js.
    const result = /** @type {{ error?: any, receipt?: { receipt_id?: string, receipt_hash?: string, canonical_hash?: string } }} */ (
      await canonicalSubmitReceipt(
        {
          entity_id: subjectId,
          transaction_ref: `td:${slug}:${minted?.published_at || new Date().toISOString()}`,
          transaction_type: 'provenance_check',
          claims: {
            delivered: true,
            on_time: true,
            as_described: onTarget,
          },
          evidence: {
            trust_page_url: trustUrl,
            claim_hashes: claimHashes,
            signing_key_fingerprint: safeFingerprint(signingKeyFingerprint),
            verification_decision: verification?.decision || null,
          },
          provenance_tier: 'self_attested',
        },
        { entity_id: SUBMITTER },
      )
    );

    if (result?.error) {
      logger.warn('trust-desk dogfood: receipt submit returned error', { error: String(result.error) });
      return null;
    }
    const r = result?.receipt || {};
    logger.info('trust-desk dogfood: EP receipt emitted', { slug, receipt_id: r.receipt_id });
    return { receipt_id: r.receipt_id || null, receipt_hash: r.receipt_hash || r.canonical_hash || null };
  } catch (err) {
    logger.warn('trust-desk dogfood: emit threw (swallowed)', { error: err.message });
    return null;
  }
}

/**
 * @param {() => string} fn
 * @returns {string|null}
 */
function safeFingerprint(fn) {
  try {
    return fn();
  } catch {
    return null;
  }
}
