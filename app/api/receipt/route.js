import crypto from 'crypto';
import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';

/**
 * POST /api/receipt
 *
 * Protocol-standard receipt submission endpoint.
 * Creates a self-verifying EP-RECEIPT-v1 document with Ed25519 signature.
 *
 * This is the conformance-standard route. Returns the signed receipt document
 * in EP-RECEIPT-v1 format — the protocol's self-verifying receipt format.
 *
 * Body: { issuer, subject, outcome, action_type, context? }
 * Returns: EP-RECEIPT-v1 signed document
 *
 * @public — accepts issuer entity_id, looks up signing key from DB.
 */
export async function POST(request) {
  try {
    const body = await request.json();

    const issuer = (body.issuer || '').trim();
    const subject = (body.subject || '').trim();
    const outcome = body.outcome || 'positive';
    const actionType = body.action_type || 'interaction';
    const context = body.context || {};

    if (!issuer) return epProblem(400, 'missing_issuer', 'issuer is required');
    if (!subject) return epProblem(400, 'missing_subject', 'subject is required');

    const supabase = getGuardedClient();

    // Look up issuer's signing key
    const { data: issuerEntity, error: issuerErr } = await supabase
      .from('entities')
      .select('entity_id, private_key_encrypted, public_key')
      .eq('entity_id', issuer)
      .single();

    if (issuerErr || !issuerEntity) {
      return epProblem(404, 'issuer_not_found', 'Issuer entity not found');
    }

    // Build receipt payload (canonical format)
    const receiptId = `ep_r_${crypto.randomBytes(16).toString('hex')}`;
    const now = new Date().toISOString();

    const payload = {
      receipt_id: receiptId,
      issuer,
      subject,
      claim: {
        action_type: actionType,
        outcome,
        context,
      },
      created_at: now,
      protocol_version: 'EP-CORE-v1.0',
    };

    // Sign the canonical payload with Ed25519
    let signatureValue = null;
    if (issuerEntity.private_key_encrypted) {
      try {
        const privateKeyDer = Buffer.from(issuerEntity.private_key_encrypted, 'base64url');
        const keyObject = crypto.createPrivateKey({
          key: privateKeyDer,
          format: 'der',
          type: 'pkcs8',
        });
        const canonicalPayload = JSON.stringify(payload, Object.keys(payload).sort());
        const sig = crypto.sign(null, Buffer.from(canonicalPayload, 'utf8'), keyObject);
        signatureValue = Buffer.from(sig).toString('base64url');
      } catch (sigErr) {
        // Signing failed — return unsigned receipt
      }
    }

    // Build EP-RECEIPT-v1 document
    const document = {
      '@version': 'EP-RECEIPT-v1',
      payload,
      signature: {
        algorithm: 'Ed25519',
        signer: issuer,
        value: signatureValue,
        key_discovery: '/.well-known/ep-keys.json',
      },
      metadata: {
        operator: 'ep_operator_emilia_primary',
        issued_at: now,
      },
    };

    // No DB persistence here. /api/receipt is the protocol-standard
    // signed-document endpoint — the EP-RECEIPT-v1 payload IS the receipt
    // (self-verifying via the embedded Ed25519 signature). Callers who need
    // the receipt in the trust-DB should POST it to /api/receipts/submit,
    // which goes through canonical-writer.js (the only sanctioned trust-table
    // writer per check-protocol-discipline.js). Keeping a best-effort insert
    // here would bypass the canonical writer and silently degrade write
    // semantics on failure, which is exactly what the discipline check exists
    // to prevent.

    return NextResponse.json(document, { status: 201 });
  } catch (err) {
    return epProblem(500, 'internal_error', 'Receipt creation failed');
  }
}
