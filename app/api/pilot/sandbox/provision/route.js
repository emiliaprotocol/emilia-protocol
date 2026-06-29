// SPDX-License-Identifier: Apache-2.0
// POST /api/pilot/sandbox/provision — self-serve observe-mode pilot.
//
// Issues a scoped pilot entity + API key so a government (or any) team can run
// their own traffic through the GovGuard/FinGuard adapters in OBSERVE mode and
// get an automated "what would have required approval" report — with no sales
// call. Mirrors the verified /api/entity creation path (entities + api_keys).
//
// The pilot is observe-only by contract: nothing the caller does here can block
// a real system. The report at GET /api/pilot/sandbox/report is scoped to the
// authenticated entity, so a pilot only ever sees its own observed actions.

import crypto from 'node:crypto';
import { NextResponse } from 'next/server';
import { getGuardedClient } from '@/lib/write-guard';
import { epProblem } from '@/lib/errors';
import { logger } from '@/lib/logger.js';
import { seal } from '@/lib/crypto/secret-box';
import { readLimitedJson } from '@/lib/http/body-limit';

const BASE = 'https://www.emiliaprotocol.ai';
const MAX_PROVISION_BYTES = 8 * 1024;

export async function POST(request) {
  try {
    const parsed = await readLimitedJson(request, MAX_PROVISION_BYTES, { invalidValue: {} });
    if (!parsed.ok) return epProblem(parsed.status, parsed.code, parsed.detail);
    const body = parsed.value;
    const rawOrgName = typeof body.org === 'string'
      ? body.org
      : (typeof body.name === 'string' ? body.name : 'Pilot organization');
    const orgName = rawOrgName.slice(0, 160).trim() || 'Pilot organization';
    // Vertical only selects which example we hand back; the engine is identical.
    const vertical = ['gov', 'fin', 'health'].includes(body.vertical) ? body.vertical : 'gov';

    const suffix = crypto.randomBytes(12).toString('hex');
    const entityId = `ep_entity_${suffix}`;
    const ownerId = `ep_owner_${crypto.randomBytes(16).toString('hex')}`;

    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    });
    const publicKeyB64 = Buffer.from(publicKey).toString('base64url');
    const privateKeyB64 = Buffer.from(privateKey).toString('base64url');

    const apiKey = `ep_live_${crypto.randomBytes(32).toString('hex')}`;
    const keyHash = crypto.createHash('sha256').update(apiKey, 'utf8').digest('hex');

    const supabase = getGuardedClient();

    const { data: inserted, error: entityError } = await supabase
      .from('entities')
      .insert({
        entity_id: entityId,
        organization_id: entityId,
        owner_id: ownerId,
        display_name: `Pilot · ${orgName}`,
        entity_type: 'agent',
        description: `Observe-mode pilot sandbox for ${orgName}`,
        api_key_hash: keyHash,
        public_key: publicKeyB64,
        private_key_encrypted: seal(privateKeyB64),
      })
      .select('id')
      .single();

    if (entityError || !inserted) {
      logger.error('[pilot/sandbox] entity insert failed:', entityError);
      return epProblem(500, 'provision_failed', 'Could not provision the sandbox');
    }

    const { error: keyError } = await supabase.from('api_keys').insert({
      entity_id: inserted.id,
      key_hash: keyHash,
      key_prefix: apiKey.slice(0, 16),
      label: 'Pilot sandbox key',
    });
    if (keyError) {
      logger.error('[pilot/sandbox] api_keys insert failed:', keyError);
      return epProblem(500, 'provision_failed', 'Sandbox created but key registration failed');
    }

    // A ready-to-run example for the selected vertical: the canonical
    // high-risk action, in OBSERVE mode, pre-filled with this sandbox's org id.
    const EXAMPLES = {
      gov: {
        adapter: '/api/v1/adapters/gov/benefit-bank-change/precheck',
        body: {
          organization_id: entityId,
          enforcement_mode: 'observe',
          recipient_id: 'case_demo_001',
          target_changed_fields: ['bank_account'],
          before_state: { bank_account: '****1111' },
          after_state: { bank_account: '****4021' },
        },
      },
      fin: {
        adapter: '/api/v1/adapters/fin/payment-release/precheck',
        body: {
          organization_id: entityId,
          enforcement_mode: 'observe',
          payment_instruction_id: 'pi_demo_001',
          amount: 82000,
          currency: 'USD',
          before_state: { status: 'pending' },
          after_state: { status: 'released' },
        },
      },
      health: {
        adapter: '/api/v1/adapters/gov/caseworker-override/precheck',
        body: {
          organization_id: entityId,
          enforcement_mode: 'observe',
          case_id: 'case_demo_002',
          before_state: { determination: 'auto_deny' },
          after_state: { determination: 'manual_approve' },
        },
      },
    };
    const example = EXAMPLES[vertical];

    return NextResponse.json({
      sandbox_id: entityId,
      organization_id: entityId,
      api_key: apiKey,
      mode: 'observe',
      note: 'Observe-mode only: nothing here can block a real system. Store this key — it is shown once.',
      report_url: `${BASE}/api/pilot/sandbox/report`,
      try_now: {
        description: `POST your first ${vertical} action through the gate in observe mode, then pull the report.`,
        curl:
          `curl -s ${BASE}${example.adapter} \\\n` +
          `  -H 'authorization: Bearer ${apiKey}' \\\n` +
          `  -H 'content-type: application/json' \\\n` +
          `  -d '${JSON.stringify(example.body)}'`,
        report_curl: `curl -s ${BASE}/api/pilot/sandbox/report -H 'authorization: Bearer ${apiKey}'`,
      },
    }, { status: 201 });
  } catch (err) {
    logger.error('[pilot/sandbox] provision error:', err);
    return epProblem(500, 'internal_error', 'Sandbox provisioning failed');
  }
}
