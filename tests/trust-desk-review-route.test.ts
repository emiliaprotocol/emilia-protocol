// SPDX-License-Identifier: Apache-2.0

import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { POST } from '../app/api/trust-desk/review/[engagementId]/route.js';
import { issueTrustDeskSession, TRUST_DESK_SESSION_COOKIE } from '../lib/trust-desk/auth.js';
import { getEngagement, putEngagement, STATUS } from '../lib/trust-desk/store.js';

const ENGAGEMENT_DIR = path.join(process.cwd(), 'data', 'trust-desk', 'engagements');
const created: string[] = [];

afterEach(() => {
  vi.unstubAllEnvs();
  for (const id of created.splice(0)) {
    fs.rmSync(path.join(ENGAGEMENT_DIR, `${id}.json`), { force: true });
  }
});

describe('Trust Desk review API identity binding', () => {
  it('records the reviewer signed into the session, never a body-supplied name', async () => {
    vi.stubEnv('TRUST_DESK_INTERNAL_TOKEN', 'bootstrap-secret');
    vi.stubEnv('TRUST_DESK_SESSION_SECRET', 'independent-session-signing-secret');
    vi.stubEnv('TRUST_DESK_REVIEWER_ID', 'Iman Schrock <team@emiliaprotocol.ai>');
    const session = issueTrustDeskSession();
    expect(session).toBeTruthy();

    const id = `eng_b01be${Date.now().toString(16)}`;
    created.push(id);
    await putEngagement({
      engagement_id: id,
      status: STATUS.AWAITING_REVIEW,
      answers: [{ id: 'q1', status: 'answered', answer: 'x' }],
    });

    const request = new NextRequest(`https://www.emiliaprotocol.ai/api/trust-desk/review/${id}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: `${TRUST_DESK_SESSION_COOKIE}=${session}`,
      },
      body: JSON.stringify({
        decision: 'reject',
        reviewer: 'Mallory',
        reason: 'requires correction',
      }),
    });
    const response = await POST(request, { params: Promise.resolve({ engagementId: id }) });

    expect(response.status).toBe(200);
    const record = await getEngagement(id);
    expect(record?.reviewer).toBe('Iman Schrock <team@emiliaprotocol.ai>');
    expect(record?.reviewer).not.toBe('Mallory');
  });

  it('keeps the reviewer cookie scoped to the whole host for the review API', () => {
    const source = fs.readFileSync(
      path.join(process.cwd(), 'app', 'internal', 'trust-desk', 'auth', 'route.ts'),
      'utf8',
    );
    expect(source).toContain("path: '/'");
    expect(source).not.toContain("path: '/internal/trust-desk'");
  });
});
