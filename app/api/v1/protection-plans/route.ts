// SPDX-License-Identifier: Apache-2.0
import {
  PROTECTION_PLAN_VERSION,
  PROTECTION_PRESETS,
  createProtectionPlan,
} from '@emilia-protocol/gate/protection-plan';

const MAX_BODY_BYTES = 64 * 1024;

function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: { 'cache-control': 'no-store' },
  });
}

export async function GET(): Promise<Response> {
  return json({
    '@version': PROTECTION_PLAN_VERSION,
    reference_only: true,
    presets: PROTECTION_PRESETS.map((preset) => ({
      id: preset.id,
      label: preset.label,
      consequence: preset.consequence,
      action_type: preset.action_type,
      assurance_floor: preset.assurance_floor,
      connector: preset.connector,
    })),
    limitation: 'Selecting an action creates local configuration. It does not establish complete mediation or active protection.',
  });
}

export async function POST(request: Request): Promise<Response> {
  if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
    return json({ error: 'content_type_invalid' }, 415);
  }
  const declaredLength = Number(request.headers.get('content-length') || 0);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
    return json({ error: 'request_too_large' }, 413);
  }
  let body: any;
  try {
    const raw = await request.text();
    if (Buffer.byteLength(raw, 'utf8') > MAX_BODY_BYTES) return json({ error: 'request_too_large' }, 413);
    body = JSON.parse(raw);
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).some((key) => !['plan_id', 'owner_label', 'selections'].includes(key))
      || !Array.isArray(body.selections)
      || body.selections.some((selection: any) => !selection
        || typeof selection !== 'object'
        || Array.isArray(selection)
        || Object.keys(selection).some((key) => !['preset_id', 'assurance_class'].includes(key)))
      || body.selections.length > PROTECTION_PRESETS.length) {
    return json({ error: 'protection_request_invalid' }, 400);
  }
  try {
    const plan = createProtectionPlan({
      planId: body.plan_id,
      ownerLabel: body.owner_label,
      selections: body.selections.map((selection: any) => ({
        presetId: selection?.preset_id,
        ...(selection?.assurance_class ? { assuranceClass: selection.assurance_class } : {}),
      })),
    });
    return json({
      reference_only: true,
      plan,
      next: {
        state: 'owner_review_required',
        instruction: 'Review and pin this local draft, install an owning connector for each selected action, then run and verify an active refusal probe before describing the action as protected.',
      },
    }, 201);
  } catch (error) {
    const reason = error instanceof Error ? error.message.split(':')[0] : 'protection_plan_failed';
    return json({ error: reason }, 400);
  }
}
