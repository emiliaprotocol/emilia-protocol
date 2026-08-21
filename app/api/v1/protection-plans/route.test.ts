// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest';
import { GET, POST } from './route';

describe('/api/v1/protection-plans', () => {
  it('publishes the six plain-language protection choices without internal action objects', async () => {
    const response = await GET();
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.reference_only).toBe(true);
    expect(body.presets).toHaveLength(6);
    expect(body.presets.map((preset: any) => preset.id)).toContain('delete-files');
    expect(body.presets.every((preset: any) => preset.action === undefined)).toBe(true);
  });

  it('builds an unsigned local plan and never marks it active', async () => {
    const response = await POST(new Request('https://example.test/api/v1/protection-plans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        plan_id: 'my-laptop',
        owner_label: 'My laptop',
        selections: [{ preset_id: 'spend-money' }, { preset_id: 'delete-files' }],
      }),
    }));
    const body = await response.json();

    expect(response.status).toBe(201);
    expect(body.reference_only).toBe(true);
    expect(body.plan.authority.status).toBe('unsigned_owner_draft');
    expect(body.plan.activation.status).toBe('not_active');
    expect(body.plan.selections).toHaveLength(2);
    expect(body.next.state).toBe('owner_review_required');
  });

  it('refuses unsupported media types and unknown presets', async () => {
    const wrongType = await POST(new Request('https://example.test/api/v1/protection-plans', {
      method: 'POST',
      headers: { 'content-type': 'text/plain' },
      body: '{}',
    }));
    expect(wrongType.status).toBe(415);

    const unknown = await POST(new Request('https://example.test/api/v1/protection-plans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        plan_id: 'unknown',
        selections: [{ preset_id: 'make-me-safe' }],
      }),
    }));
    expect(unknown.status).toBe(400);
    await expect(unknown.json()).resolves.toMatchObject({ error: 'protection_preset_unknown' });

    const smuggled = await POST(new Request('https://example.test/api/v1/protection-plans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        plan_id: 'smuggled',
        selections: [{ preset_id: 'spend-money', activate: true }],
      }),
    }));
    expect(smuggled.status).toBe(400);
    await expect(smuggled.json()).resolves.toMatchObject({ error: 'protection_request_invalid' });
  });
});
