// SPDX-License-Identifier: Apache-2.0

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { sendAuthorityDemandVerificationEmail } from '../lib/works/demand-email.ts';

const input = {
  to: 'requester@example.com',
  verifyUrl: 'https://www.emiliaprotocol.ai/works/request/verify#token=ardv1_test',
  recordId: 'authority-record-acme-agent',
};

beforeEach(() => {
  vi.restoreAllMocks();
  delete process.env.RESEND_API_KEY;
});

afterEach(() => {
  delete process.env.RESEND_API_KEY;
  vi.unstubAllGlobals();
});

describe('Authority Record demand verification email', () => {
  it('does not attempt delivery without the dedicated Resend credential', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    await expect(sendAuthorityDemandVerificationEmail(input)).resolves.toEqual({ delivered: false });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('sends a bounded verification message and reports provider acceptance', async () => {
    process.env.RESEND_API_KEY = 'resend_authority_records_test';
    const fetchMock = vi.fn(async () => ({ ok: true }));
    vi.stubGlobal('fetch', fetchMock);

    await expect(sendAuthorityDemandVerificationEmail(input)).resolves.toEqual({ delivered: true });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, request] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.resend.com/emails');
    expect(request).toMatchObject({
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: 'Bearer resend_authority_records_test',
      },
    });
    const body = JSON.parse(request.body);
    expect(body).toMatchObject({
      to: input.to,
      subject: 'Confirm your Authority Record request',
    });
    expect(body.text).toContain(input.verifyUrl);
    expect(body.text).toContain(`Record: ${input.recordId}`);
    expect(body.text).toContain('not a purchase or endorsement');
  });

  it('fails closed when the delivery provider refuses or is unavailable', async () => {
    process.env.RESEND_API_KEY = 'resend_authority_records_test';
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false })));
    await expect(sendAuthorityDemandVerificationEmail(input)).resolves.toEqual({ delivered: false });

    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network unavailable'); }));
    await expect(sendAuthorityDemandVerificationEmail(input)).resolves.toEqual({ delivered: false });
  });
});
