// SPDX-License-Identifier: Apache-2.0
//
// Regression: IDOR / broken-authz on POST /api/identity/verify (Sentrix, high).
// Before the fix ANY authenticated entity could flip ANY pending identity
// binding to `verified` by supplying its binding_id. The route now requires a
// named operator holding the host_verifier `binding.verify` permission, and the
// authenticated operator_id is what gets recorded as the verifier.
//
// hasPermission (lib/procedural-justice) is intentionally NOT mocked so the real
// role → permission table is exercised: an entity/reviewer/operator role that
// lacks `binding.verify` is refused; only host_verifier is allowed through.

import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  authenticateOperator: vi.fn(),
  verifyBinding: vi.fn(),
}));

vi.mock('@/lib/operator-auth', () => ({
  authenticateOperator: mocks.authenticateOperator,
}));

vi.mock('@/lib/ep-ix', () => ({
  verifyBinding: mocks.verifyBinding,
}));

const { POST } = await import('../app/api/identity/verify/route.ts');

function request(body) {
  return new Request('https://www.emiliaprotocol.ai/api/identity/verify', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer token' },
    body: JSON.stringify(body),
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.verifyBinding.mockResolvedValue({
    binding: { binding_id: 'ep_bind_victim', status: 'verified' },
  });
});

describe('POST /api/identity/verify — authorization', () => {
  it('ATTACK: an authenticated entity (no operator token) is refused, binding untouched', async () => {
    // requireOperatorIdentity means the shared/entity path returns { valid:false }.
    mocks.authenticateOperator.mockReturnValue({ valid: false, error: 'This action requires a per-operator token, not the shared secret' });

    const response = await POST(request({ binding_id: 'ep_bind_victim' }));

    expect(response.status).toBe(401);
    expect(mocks.verifyBinding).not.toHaveBeenCalled();
  });

  it('ATTACK: a named operator whose role lacks binding.verify is refused (403), binding untouched', async () => {
    // A generic "operator" / "reviewer" role must NOT be able to verify bindings —
    // only host_verifier carries binding.verify.
    mocks.authenticateOperator.mockReturnValue({ valid: true, operator_id: 'reviewer-7', role: 'reviewer' });

    const response = await POST(request({ binding_id: 'ep_bind_victim' }));
    const body = await response.json();

    expect(response.status).toBe(403);
    expect(body.detail).toMatch(/binding\.verify/);
    expect(mocks.verifyBinding).not.toHaveBeenCalled();
  });

  it('LEGIT: a host_verifier operator verifies the binding, recorded under its own operator_id', async () => {
    mocks.authenticateOperator.mockReturnValue({ valid: true, operator_id: 'host-verifier-1', role: 'host_verifier' });

    const response = await POST(request({ binding_id: 'ep_bind_victim' }));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(body.binding).toEqual({ binding_id: 'ep_bind_victim', status: 'verified' });
    // Verifier identity comes from the authenticated operator, not from client input.
    expect(mocks.verifyBinding).toHaveBeenCalledWith('ep_bind_victim', 'host-verifier-1');
  });

  it('requireOperatorIdentity is passed so the anonymous shared cron secret is refused', async () => {
    mocks.authenticateOperator.mockReturnValue({ valid: true, operator_id: 'host-verifier-1', role: 'host_verifier' });

    await POST(request({ binding_id: 'ep_bind_victim' }));

    expect(mocks.authenticateOperator).toHaveBeenCalledWith(
      expect.anything(),
      { requireOperatorIdentity: true },
    );
  });

  it('missing binding_id is a 400 after auth passes', async () => {
    mocks.authenticateOperator.mockReturnValue({ valid: true, operator_id: 'host-verifier-1', role: 'host_verifier' });

    const response = await POST(request({}));

    expect(response.status).toBe(400);
    expect(mocks.verifyBinding).not.toHaveBeenCalled();
  });
});
