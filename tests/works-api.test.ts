// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';

import { worksProblem, worksUnauthorized } from '../lib/works/api';

describe('Works API problem responses', () => {
  it('returns a typed authentication challenge without throwing', async () => {
    const response = worksUnauthorized();
    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toMatchObject({
      type: 'https://emiliaprotocol.ai/errors/unauthorized',
      title: 'Unauthorized',
      status: 401,
      detail: 'A valid Cloud API key is required',
    });
  });

  it('maps known store failures and fails unknown codes closed as client errors', async () => {
    const unavailable = worksProblem({ code: 'store_unavailable', detail: 'offline' });
    expect(unavailable.status).toBe(503);

    const unknown = worksProblem({ code: 'unexpected_store_shape', detail: 'invalid' });
    expect(unknown.status).toBe(400);
  });
});
