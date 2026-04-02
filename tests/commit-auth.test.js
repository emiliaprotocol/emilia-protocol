/**
 * Tests for lib/commit-auth.js
 *
 * Mocks @/lib/delegation so verifyDelegation can be controlled per test.
 */

import { vi } from 'vitest';

const mockVerifyDelegation = vi.fn();

vi.mock('@/lib/delegation', () => ({
  verifyDelegation: (...args) => mockVerifyDelegation(...args),
}));

import {
  authorizeCommitAccess,
  authorizeCommitIssuance,
} from '@/lib/commit-auth.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeAuth(entityId) {
  return { entity: { entity_id: entityId } };
}

function makeCommit(overrides = {}) {
  return {
    entity_id: 'issuer-1',
    principal_id: null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// authorizeCommitAccess
// ---------------------------------------------------------------------------

describe('authorizeCommitAccess', () => {
  it('authorizes the issuing entity', () => {
    const auth = makeAuth('issuer-1');
    const commit = makeCommit({ entity_id: 'issuer-1' });
    const result = authorizeCommitAccess(auth, commit, 'view');
    expect(result.authorized).toBe(true);
  });

  it('authorizes the principal on the commit', () => {
    const auth = makeAuth('principal-1');
    const commit = makeCommit({ entity_id: 'issuer-1', principal_id: 'principal-1' });
    const result = authorizeCommitAccess(auth, commit, 'view');
    expect(result.authorized).toBe(true);
  });

  it('denies a third party who is neither issuer nor principal', () => {
    const auth = makeAuth('outsider');
    const commit = makeCommit({ entity_id: 'issuer-1', principal_id: 'principal-1' });
    const result = authorizeCommitAccess(auth, commit, 'view');
    expect(result.authorized).toBe(false);
  });

  it('denied result includes a reason mentioning the action', () => {
    const auth = makeAuth('outsider');
    const commit = makeCommit({ entity_id: 'issuer-1' });
    const result = authorizeCommitAccess(auth, commit, 'revoke');
    expect(result.reason).toContain('revoke');
  });

  it('denies when commit has no principal_id and caller is not issuer', () => {
    const auth = makeAuth('nobody');
    const commit = makeCommit({ entity_id: 'issuer-1', principal_id: null });
    expect(authorizeCommitAccess(auth, commit, 'update').authorized).toBe(false);
  });

  it('does not authorize based on principal_id when principal_id is null', () => {
    // null === 'entity-x' should be false — no false positive
    const auth = makeAuth('entity-x');
    const commit = makeCommit({ entity_id: 'issuer-1', principal_id: null });
    expect(authorizeCommitAccess(auth, commit, 'read').authorized).toBe(false);
  });

  it('authorizes when entity acts as both issuer and principal', () => {
    const auth = makeAuth('self-1');
    const commit = makeCommit({ entity_id: 'self-1', principal_id: 'self-1' });
    expect(authorizeCommitAccess(auth, commit, 'view').authorized).toBe(true);
  });

  it('returns { authorized: true } with no reason on success', () => {
    const auth = makeAuth('issuer-1');
    const commit = makeCommit({ entity_id: 'issuer-1' });
    const result = authorizeCommitAccess(auth, commit, 'view');
    expect(result).toEqual({ authorized: true });
  });
});

// ---------------------------------------------------------------------------
// authorizeCommitIssuance
// ---------------------------------------------------------------------------

describe('authorizeCommitIssuance', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('allows self-issuance without delegation', async () => {
    const auth = makeAuth('ent-A');
    const result = await authorizeCommitIssuance(auth, 'ent-A', null, null);
    expect(result.authorized).toBe(true);
    expect(mockVerifyDelegation).not.toHaveBeenCalled();
  });

  it('denies cross-entity issuance with no delegation ID', async () => {
    const auth = makeAuth('agent-1');
    const result = await authorizeCommitIssuance(auth, 'other-entity', null, null);
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/delegation/i);
  });

  it('calls verifyDelegation with the provided delegationId and actionType', async () => {
    mockVerifyDelegation.mockResolvedValue({
      valid: true,
      agent_entity_id: 'agent-1',
      principal_id: 'target-1',
      action_permitted: true,
    });

    const auth = makeAuth('agent-1');
    await authorizeCommitIssuance(auth, 'target-1', 'ep_dlg_xyz', 'submit');

    expect(mockVerifyDelegation).toHaveBeenCalledWith('ep_dlg_xyz', 'submit');
  });

  it('authorizes when delegation is valid and agents/principals match', async () => {
    mockVerifyDelegation.mockResolvedValue({
      valid: true,
      agent_entity_id: 'agent-1',
      principal_id: 'target-1',
      action_permitted: true,
    });

    const auth = makeAuth('agent-1');
    const result = await authorizeCommitIssuance(auth, 'target-1', 'ep_dlg_xyz', 'submit');
    expect(result.authorized).toBe(true);
  });

  it('denies when delegation is invalid (expired/revoked)', async () => {
    mockVerifyDelegation.mockResolvedValue({
      valid: false,
      reason: 'Delegation has expired',
    });

    const auth = makeAuth('agent-1');
    const result = await authorizeCommitIssuance(auth, 'target-1', 'ep_dlg_expired', null);
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/expired/i);
  });

  it('uses generic fallback reason when delegation.reason is absent', async () => {
    mockVerifyDelegation.mockResolvedValue({ valid: false });

    const auth = makeAuth('agent-1');
    const result = await authorizeCommitIssuance(auth, 'target-1', 'ep_dlg_xyz', null);
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/delegation verification failed/i);
  });

  it('denies when delegation agent_entity_id does not match caller', async () => {
    mockVerifyDelegation.mockResolvedValue({
      valid: true,
      agent_entity_id: 'different-agent',
      principal_id: 'target-1',
    });

    const auth = makeAuth('agent-1');
    const result = await authorizeCommitIssuance(auth, 'target-1', 'ep_dlg_xyz', null);
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/does not authorize this caller/i);
  });

  it('denies when delegation principal_id does not match target entity', async () => {
    mockVerifyDelegation.mockResolvedValue({
      valid: true,
      agent_entity_id: 'agent-1',
      principal_id: 'wrong-target',
    });

    const auth = makeAuth('agent-1');
    const result = await authorizeCommitIssuance(auth, 'target-1', 'ep_dlg_xyz', null);
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/principal does not match/i);
  });

  it('denies when action is not permitted by delegation scope', async () => {
    mockVerifyDelegation.mockResolvedValue({
      valid: true,
      agent_entity_id: 'agent-1',
      principal_id: 'target-1',
      action_permitted: false,
      reason: 'Action "delete" is not in delegation scope',
    });

    const auth = makeAuth('agent-1');
    const result = await authorizeCommitIssuance(auth, 'target-1', 'ep_dlg_xyz', 'delete');
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/delete/i);
  });

  it('does not check action_permitted when actionType is null', async () => {
    mockVerifyDelegation.mockResolvedValue({
      valid: true,
      agent_entity_id: 'agent-1',
      principal_id: 'target-1',
      // action_permitted is undefined (not checked when actionType is null)
    });

    const auth = makeAuth('agent-1');
    const result = await authorizeCommitIssuance(auth, 'target-1', 'ep_dlg_xyz', null);
    expect(result.authorized).toBe(true);
  });

  it('uses delegation reason when action not permitted and reason exists', async () => {
    mockVerifyDelegation.mockResolvedValue({
      valid: true,
      agent_entity_id: 'agent-1',
      principal_id: 'target-1',
      action_permitted: false,
      reason: 'Custom delegation reason',
    });

    const auth = makeAuth('agent-1');
    const result = await authorizeCommitIssuance(auth, 'target-1', 'ep_dlg_xyz', 'custom');
    expect(result.reason).toContain('Custom delegation reason');
  });

  it('self-issuance ignores any provided delegationId', async () => {
    const auth = makeAuth('ent-A');
    // Even if a delegation is passed, self-issuance short-circuits
    const result = await authorizeCommitIssuance(auth, 'ent-A', 'ep_dlg_xyz', 'submit');
    expect(result.authorized).toBe(true);
    expect(mockVerifyDelegation).not.toHaveBeenCalled();
  });
});
