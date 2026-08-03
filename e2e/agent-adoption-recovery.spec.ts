// SPDX-License-Identifier: Apache-2.0

import { expect, test, type Page, type Route } from '@playwright/test';

const SESSION_ID = '00000000-0000-4000-8000-000000000001';
const BOND_ID = '00000000-0000-4000-8000-000000000002';
const BOND_DIGEST = `sha256:${'b'.repeat(64)}`;
const ATTEMPT_ID = `arena_attempt_${'a'.repeat(32)}`;
const ACTION_DIGEST = `sha256:${'c'.repeat(64)}`;
const REFUSAL_DIGEST = `sha256:${'d'.repeat(64)}`;
const TRIAL_TOKEN = `epenc:v1:${'e'.repeat(64)}`;

function recoveredSession(overrides: Record<string, unknown> = {}) {
  return {
    session_id: SESSION_ID,
    expires_at: '2099-08-03T00:00:00.000Z',
    authority_state: 'asserted',
    passkey_registered: true,
    passkey_asserted: true,
    bond_id: BOND_ID,
    bond_digest: BOND_DIGEST,
    recovery: {
      label: 'Atlas',
      source_kind: 'local',
      job_template_id: 'job_vendor_intake_v1',
      allowance_template_id: 'allowance_cautious_v1',
    },
    ...overrides,
  };
}

async function seedRecoverableSession(page: Page) {
  await page.addInitScript((sessionId) => {
    if (!window.localStorage.getItem('emilia_agent_adoption_session_id')) {
      window.localStorage.setItem('emilia_agent_adoption_session_id', sessionId);
    }
  }, SESSION_ID);
}

function json(route: Route, body: unknown, status = 200) {
  return route.fulfill({
    status,
    contentType: 'application/json',
    headers: { 'cache-control': 'no-store, max-age=0' },
    body: JSON.stringify(body),
  });
}

test.describe('Agent Adoption committed-response recovery', () => {
  test('promotes a pending client-only owner credential after record commit response loss', async ({ page }) => {
    await seedRecoverableSession(page);
    let committedRecord: null | {
      record_id: string;
      owner_token: string;
      created_at: string;
      retention_expires_at: string;
    } = null;
    const recoveryReads: Array<{
      url: string;
      authorization: string | undefined;
      cookie: string | undefined;
      body: string | null;
    }> = [];

    await page.route('**/api/**', async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const path = url.pathname;

      if (request.method() === 'GET' && path === `/api/adopt/sessions/${SESSION_ID}`) {
        return json(route, recoveredSession());
      }
      if (request.method() === 'POST' && path === `/api/adopt/sessions/${SESSION_ID}/trial`) {
        return json(route, { ...recoveredSession(), trial_token: TRIAL_TOKEN }, 201);
      }
      if (request.method() === 'POST' && path === `/api/adopt/sessions/${SESSION_ID}/attempts`) {
        return json(route, {
          attempt_id: ATTEMPT_ID,
          template_id: 'attempt_over_limit_v1',
          decision: 'refuse',
          reason_code: 'per_action_limit_exceeded',
          synthetic_credits: 900,
          target_template_id: 'vendor.demo',
          action_digest: ACTION_DIGEST,
          refusal_digest: REFUSAL_DIGEST,
        }, 201);
      }
      if (request.method() === 'POST' && path === `/api/adopt/sessions/${SESSION_ID}/records`) {
        const input = request.postDataJSON() as {
          record_id: string;
          owner_token: string;
        };
        committedRecord = {
          record_id: input.record_id,
          owner_token: input.owner_token,
          created_at: '2026-08-03T00:00:00.000Z',
          retention_expires_at: '2027-08-03T00:00:00.000Z',
        };
        // The durable effect happened, but the browser never receives the 201.
        return route.abort('connectionreset');
      }
      if (request.method() === 'GET' && path.startsWith('/api/agent-records/')) {
        recoveryReads.push({
          url: request.url(),
          authorization: request.headers().authorization,
          cookie: request.headers().cookie,
          body: request.postData(),
        });
        if (!committedRecord || path !== `/api/agent-records/${committedRecord.record_id}`) {
          return json(route, { status: 404 }, 404);
        }
        return json(route, {
          record_id: committedRecord.record_id,
          public_projection: {
            '@version': 'EP-AGENT-RECORD-OBSERVATION-v1',
            record: {
              record_id: committedRecord.record_id,
              observed_at: committedRecord.created_at,
              retention_expires_at: committedRecord.retention_expires_at,
            },
          },
          verification: { integrity_verified: true, currently_public: true },
        });
      }
      return route.continue();
    });

    await page.goto('/adopt');
    await expect(page.getByRole('heading', { name: 'Push on the boundary.' })).toBeVisible();
    await page.getByRole('button', { name: /Oversized request/ }).click();
    await expect(page.getByText('The Arena refused the no-egress attempt.')).toBeVisible();
    await page.getByRole('button', { name: /Review & share Operating Bond/ }).click();
    await page.getByLabel(/unlisted public observation of this refusal only/).check();
    await page.getByRole('button', { name: /Create factual Agent Record/ }).click();
    await expect(page.getByText('Failed to fetch', { exact: true })).toBeVisible();

    const pending = await page.evaluate((attemptId) => {
      const key = `emilia_agent_record_pending:${attemptId}`;
      return { key, value: window.localStorage.getItem(key) };
    }, ATTEMPT_ID);
    expect(committedRecord).not.toBeNull();
    expect(pending.value).toContain(committedRecord!.record_id);
    expect(await page.evaluate(
      (recordId) => window.localStorage.getItem(`emilia_agent_record_owner:${recordId}`),
      committedRecord!.record_id,
    )).toBeNull();

    await page.reload();
    await expect.poll(() => page.evaluate(
      (recordId) => window.localStorage.getItem(`emilia_agent_record_owner:${recordId}`),
      committedRecord!.record_id,
    )).toBe(committedRecord!.owner_token);
    await expect(page.getByRole('link', { name: /Open factual Agent Record/ })).toHaveAttribute(
      'href',
      `/agent-record/r/${committedRecord!.record_id}`,
    );
    expect(await page.evaluate((key) => window.localStorage.getItem(key), pending.key)).toBeNull();
    expect(recoveryReads).toHaveLength(1);
    expect(recoveryReads[0]).toEqual({
      url: `http://localhost:3000/api/agent-records/${committedRecord!.record_id}`,
      authorization: undefined,
      cookie: undefined,
      body: null,
    });
    expect(recoveryReads[0].url).not.toContain(committedRecord!.owner_token);
  });

  test('resumes assertion with the existing credential after registration commit response loss', async ({ page }) => {
    await seedRecoverableSession(page);
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });

    let registrationCommitted = false;
    let asserted = false;
    let registeredCredentialId = '';
    let registrationOptionsCount = 0;
    let assertionOptionsCount = 0;
    const challenge = Buffer.from('agent-adoption-recovery-challenge-01').toString('base64url');

    await page.route('**/api/adopt/sessions/**', async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname;
      if (request.method() === 'GET' && path === `/api/adopt/sessions/${SESSION_ID}`) {
        return json(route, recoveredSession({
          authority_state: asserted ? 'asserted' : 'draft',
          passkey_registered: registrationCommitted,
          passkey_asserted: asserted,
          bond_id: asserted ? BOND_ID : undefined,
        }));
      }
      if (request.method() === 'POST' && path.endsWith('/passkey/register/options')) {
        registrationOptionsCount += 1;
        return json(route, {
          ceremony_token: 'registration-ceremony-token',
          options: {
            challenge,
            rp: { id: 'localhost', name: 'EMILIA Agent Adoption' },
            user: {
              id: Buffer.from(SESSION_ID).toString('base64url'),
              name: 'agent-adoption-local',
              displayName: 'Agent Adoption local credential',
            },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            timeout: 60_000,
            attestation: 'none',
            authenticatorSelection: {
              residentKey: 'required',
              requireResidentKey: true,
              userVerification: 'required',
            },
            excludeCredentials: registeredCredentialId
              ? [{ id: registeredCredentialId, type: 'public-key', transports: ['internal'] }]
              : [],
          },
        });
      }
      if (request.method() === 'POST' && path.endsWith('/passkey/register/verify')) {
        const input = request.postDataJSON() as { attestation: { id: string } };
        registeredCredentialId = input.attestation.id;
        registrationCommitted = true;
        // The passkey is durable, but the browser never receives its identifier response.
        return route.abort('connectionreset');
      }
      if (request.method() === 'POST' && path.endsWith('/passkey/assert/options')) {
        assertionOptionsCount += 1;
        const input = request.postDataJSON() as { credential_id?: string };
        expect(input.credential_id).toBe(registeredCredentialId);
        return json(route, {
          ceremony_token: 'assertion-ceremony-token',
          options: {
            challenge: Buffer.from('agent-adoption-recovery-assertion-01').toString('base64url'),
            rpId: 'localhost',
            timeout: 60_000,
            userVerification: 'required',
            allowCredentials: [{
              id: registeredCredentialId,
              type: 'public-key',
              transports: ['internal'],
            }],
          },
        });
      }
      if (request.method() === 'POST' && path.endsWith('/passkey/assert/verify')) {
        asserted = true;
        return json(route, recoveredSession());
      }
      if (request.method() === 'POST' && path.endsWith('/trial')) {
        return json(route, { ...recoveredSession(), trial_token: TRIAL_TOKEN }, 201);
      }
      return route.continue();
    });

    await page.goto('/adopt');
    await expect(page.getByRole('heading', { name: /Put a user-present passkey gesture/ })).toBeVisible();
    await page.getByRole('button', { name: 'Continue with passkey →' }).click();
    await expect(page.getByText('Failed to fetch', { exact: true })).toBeVisible({ timeout: 15_000 });
    expect(registrationCommitted).toBe(true);
    expect(registeredCredentialId).not.toBe('');
    expect(await page.evaluate(
      (sessionId) => window.localStorage.getItem(`emilia_agent_adoption_passkey:${sessionId}`),
      SESSION_ID,
    )).toBe(registeredCredentialId);

    await page.reload();
    await expect(page.getByRole('heading', { name: /Put a user-present passkey gesture/ })).toBeVisible();
    await page.getByRole('button', { name: 'Continue with passkey →' }).click();
    await expect(page.getByRole('heading', { name: 'Push on the boundary.' })).toBeVisible();

    expect(registrationOptionsCount).toBe(1);
    expect(assertionOptionsCount).toBe(1);
    expect(await page.evaluate(
      (sessionId) => window.localStorage.getItem(`emilia_agent_adoption_passkey:${sessionId}`),
      SESSION_ID,
    )).toBeNull();
  });
});
