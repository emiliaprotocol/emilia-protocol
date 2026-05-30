/**
 * POST /api/trust-desk/intake
 *
 * @license Apache-2.0
 *
 * Receives a Trust Desk intake (form fields + optional questionnaire file),
 * persists the engagement, and runs the automation pipeline AFTER the response
 * is sent (next/server `after`) so the form gets an instant ack. The pipeline
 * publishes a trust page or escalates to a reviewer — either way the customer
 * is notified out of band.
 *
 * Accepts multipart/form-data (file upload) or application/json.
 */

import { NextResponse, after } from 'next/server';
import fs from 'node:fs';
import path from 'node:path';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger';
import { newEngagementId, deriveSlug } from '@/lib/trust-desk/ids';
import { putEngagement, STATUS } from '@/lib/trust-desk/store';
import { runPipeline } from '@/lib/trust-desk/pipeline';

export const dynamic = 'force-dynamic';
export const maxDuration = 60;

const UPLOAD_DIR = path.join(process.cwd(), 'data', 'trust-desk', 'uploads');
const MAX_BYTES = 25 * 1024 * 1024; // 25 MB

export async function POST(request) {
  try {
    const { fields, file } = await readBody(request);

    // Required fields.
    if (!fields.company?.trim() || !fields.contact_email?.trim()) {
      return epProblem(400, 'missing_fields', 'company and contact_email are required');
    }
    if (!String(fields.contact_email).includes('@')) {
      return epProblem(400, 'invalid_email', 'contact_email must be a valid email');
    }
    // Match the public form's gating: financial services only for now.
    const selling = fields.selling_into || 'financial_services';
    if (selling !== 'fintech' && selling !== 'financial_services') {
      return epProblem(
        422,
        'unsupported_vertical',
        'Trust Desk currently serves AI vendors selling into financial services. Healthcare is on the waitlist.',
      );
    }

    const engagementId = newEngagementId();
    const slug = deriveSlug(fields.company, engagementId);

    // Persist the uploaded questionnaire (or inline text) to disk.
    let questionnairePath = null;
    let questionnaireFilename = null;
    if (file && file.buffer?.length) {
      if (file.buffer.length > MAX_BYTES) {
        return epProblem(413, 'file_too_large', 'questionnaire exceeds 25 MB');
      }
      fs.mkdirSync(UPLOAD_DIR, { recursive: true });
      questionnaireFilename = safeName(file.filename || 'questionnaire.bin');
      questionnairePath = path.join(UPLOAD_DIR, `${engagementId}__${questionnaireFilename}`);
      fs.writeFileSync(questionnairePath, file.buffer);
    } else if (fields.questionnaire_text?.trim()) {
      fs.mkdirSync(UPLOAD_DIR, { recursive: true });
      questionnaireFilename = `${engagementId}.md`;
      questionnairePath = path.join(UPLOAD_DIR, questionnaireFilename);
      fs.writeFileSync(questionnairePath, fields.questionnaire_text);
    } else {
      return epProblem(
        400,
        'missing_questionnaire',
        'attach a questionnaire file or provide questionnaire_text',
      );
    }

    const intake = {
      company: fields.company.trim(),
      website: fields.website || null,
      contact_name: fields.contact_name || 'Security Team',
      contact_email: fields.contact_email.trim(),
      contact_role: fields.contact_role || 'Security Contact',
      product_description: fields.product_description || '',
      selling_into: selling,
      buyer_name: fields.buyer_name || null,
      active_deal_blocked: fields.active_deal_blocked || 'no',
      ai_uses_customer_data: fields.ai_uses_customer_data || 'unsure',
      cloud_provider: fields.cloud_provider || '',
      model_providers: fields.model_providers || '',
      soc2_status: fields.soc2_status || 'in_progress',
      tier_preference: fields.tier_preference || 'packet',
      notes: fields.notes || '',
    };

    const engagement = {
      engagement_id: engagementId,
      slug,
      intake,
      questionnaire_path: questionnairePath,
      questionnaire_filename: questionnaireFilename,
      status: STATUS.INTAKE_RECEIVED,
      status_history: [{ status: STATUS.INTAKE_RECEIVED, at: new Date().toISOString() }],
    };
    putEngagement(engagement);

    // Run the pipeline AFTER responding so the form gets an instant ack.
    after(async () => {
      try {
        const result = await runPipeline({ engagement });
        logger.info('trust-desk intake: pipeline finished', {
          engagement_id: engagementId,
          outcome: result.outcome,
        });
      } catch (err) {
        logger.error('trust-desk intake: pipeline threw', {
          engagement_id: engagementId,
          error: err.message,
        });
      }
    });

    return NextResponse.json({
      ok: true,
      engagement_id: engagementId,
      status: STATUS.INTAKE_RECEIVED,
      status_url: `/api/trust-desk/status/${engagementId}`,
      message: 'Intake received. Your trust page is being generated.',
    });
  } catch (err) {
    logger.error('trust-desk intake: failed', { error: err.message });
    return epProblem(500, 'intake_error', 'Failed to process intake');
  }
}

// ── Body parsing (multipart or JSON) ────────────────────────────────────────

async function readBody(request) {
  const ctype = request.headers.get('content-type') || '';
  if (ctype.includes('multipart/form-data')) {
    const form = await request.formData();
    const fields = {};
    let file = null;
    for (const [key, value] of form.entries()) {
      if (typeof value === 'object' && value && 'arrayBuffer' in value) {
        const buffer = Buffer.from(await value.arrayBuffer());
        file = { filename: value.name, buffer };
      } else {
        fields[key] = String(value);
      }
    }
    return { fields, file };
  }
  // JSON body
  const body = await request.json().catch(() => ({}));
  return { fields: body, file: null };
}

function safeName(name) {
  return String(name).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120);
}
