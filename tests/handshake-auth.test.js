/**
 * Tests for lib/handshake-auth.js
 *
 * Mocks @/lib/handshake/errors.js so HandshakeError is a real inspectable class,
 * and provides a fake supabase builder for party lookups.
 */

import { vi } from 'vitest';

// Use real HandshakeError (it's a plain class with no side effects)
import {
  resolveAuthEntityId,
  authorizeHandshakeRead,
  authorizeHandshakePresent,
  authorizeHandshakeVerify,
  authorizeHandshakeRevoke,
} from '@/lib/handshake-auth.js';

import { HandshakeError } from '@/lib/handshake/errors.js';

// ---------------------------------------------------------------------------
// Supabase stub factory
// ---------------------------------------------------------------------------

function makeSupabase(parties = [], error = null) {
  return {
    from: () => ({
      select: () => ({
        eq: () => ({
          eq: () => Promise.resolve({ data: parties, error }),
          // single .eq chain (only one .eq call)
          then: undefined,
        }),
        // Some chains only call .eq once
        eq: () => Promise.resolve({ data: parties, error }),
      }),
    }),
  };
}

// ---------------------------------------------------------------------------
// resolveAuthEntityId
// ---------------------------------------------------------------------------

describe('resolveAuthEntityId', () => {
  it('returns null for null input', () => {
    expect(resolveAuthEntityId(null)).toBeNull();
  });

  it('returns null for undefined input', () => {
    expect(resolveAuthEntityId(undefined)).toBeNull();
  });

  it('returns a string actor as-is', () => {
    expect(resolveAuthEntityId('ent-123')).toBe('ent-123');
  });

  it('extracts entity_id from an object', () => {
    expect(resolveAuthEntityId({ entity_id: 'ent-abc' })).toBe('ent-abc');
  });

  it('falls back to id when entity_id is absent', () => {
    expect(resolveAuthEntityId({ id: 'ent-xyz' })).toBe('ent-xyz');
  });

  it('falls back to entity_ref when both entity_id and id are absent', () => {
    expect(resolveAuthEntityId({ entity_ref: 'ent-ref' })).toBe('ent-ref');
  });

  it('returns null when object has none of the expected keys', () => {
    expect(resolveAuthEntityId({ foo: 'bar' })).toBeNull();
  });

  it('entity_id takes precedence over id and entity_ref', () => {
    const actor = { entity_id: 'primary', id: 'secondary', entity_ref: 'tertiary' };
    expect(resolveAuthEntityId(actor)).toBe('primary');
  });
});

// ---------------------------------------------------------------------------
// authorizeHandshakeRead
// ---------------------------------------------------------------------------

describe('authorizeHandshakeRead', () => {
  it('allows system actor without querying supabase', async () => {
    const fakeSupabase = { from: vi.fn() };
    await expect(
      authorizeHandshakeRead(fakeSupabase, 'system', 'hs-1')
    ).resolves.toBeUndefined();
    expect(fakeSupabase.from).not.toHaveBeenCalled();
  });

  it('allows a party member on the handshake', async () => {
    const parties = [{ entity_ref: 'ent-A', party_role: 'initiator' }];
    const supabase = makeSupabase(parties);
    await expect(
      authorizeHandshakeRead(supabase, 'ent-A', 'hs-1')
    ).resolves.toBeUndefined();
  });

  it('throws 403 HandshakeError for a non-member', async () => {
    const parties = [{ entity_ref: 'ent-A', party_role: 'initiator' }];
    const supabase = makeSupabase(parties);
    await expect(
      authorizeHandshakeRead(supabase, 'ent-B', 'hs-1')
    ).rejects.toThrow(HandshakeError);
  });

  it('denied error has status 403 and correct code', async () => {
    const supabase = makeSupabase([]);
    try {
      await authorizeHandshakeRead(supabase, 'ent-X', 'hs-1');
    } catch (err) {
      expect(err.status).toBe(403);
      expect(err.code).toBe('UNAUTHORIZED_HANDSHAKE_ACCESS');
    }
  });

  it('throws 500 HandshakeError when supabase returns an error', async () => {
    const supabase = makeSupabase([], { message: 'DB down' });
    await expect(
      authorizeHandshakeRead(supabase, 'ent-A', 'hs-1')
    ).rejects.toThrow(HandshakeError);
  });

  it('DB error has status 500 and HANDSHAKE_PARTY_LOOKUP_FAILED code', async () => {
    const supabase = makeSupabase([], { message: 'timeout' });
    try {
      await authorizeHandshakeRead(supabase, 'ent-A', 'hs-1');
    } catch (err) {
      expect(err.status).toBe(500);
      expect(err.code).toBe('HANDSHAKE_PARTY_LOOKUP_FAILED');
    }
  });
});

// ---------------------------------------------------------------------------
// authorizeHandshakePresent
// ---------------------------------------------------------------------------

describe('authorizeHandshakePresent', () => {
  it('allows system actor without party check', async () => {
    const supabase = { from: vi.fn() };
    await expect(
      authorizeHandshakePresent(supabase, 'system', 'hs-1', 'initiator')
    ).resolves.toBeUndefined();
    expect(supabase.from).not.toHaveBeenCalled();
  });

  it('allows the correct owner of a party role', async () => {
    const parties = [
      { entity_ref: 'ent-A', party_role: 'initiator' },
      { entity_ref: 'ent-B', party_role: 'responder' },
    ];
    const supabase = makeSupabase(parties);
    await expect(
      authorizeHandshakePresent(supabase, 'ent-A', 'hs-1', 'initiator')
    ).resolves.toBeUndefined();
  });

  it('throws 403 when entity does not own the role', async () => {
    const parties = [{ entity_ref: 'ent-A', party_role: 'initiator' }];
    const supabase = makeSupabase(parties);
    await expect(
      authorizeHandshakePresent(supabase, 'ent-B', 'hs-1', 'initiator')
    ).rejects.toThrow(HandshakeError);
  });

  it('throws 403 when the role does not exist on the handshake', async () => {
    const parties = [{ entity_ref: 'ent-A', party_role: 'initiator' }];
    const supabase = makeSupabase(parties);
    await expect(
      authorizeHandshakePresent(supabase, 'ent-A', 'hs-1', 'nonexistent_role')
    ).rejects.toThrow(HandshakeError);
  });
});

// ---------------------------------------------------------------------------
// authorizeHandshakeVerify
// ---------------------------------------------------------------------------

describe('authorizeHandshakeVerify', () => {
  it('allows system actor', async () => {
    const supabase = { from: vi.fn() };
    await expect(
      authorizeHandshakeVerify(supabase, 'system', 'hs-1')
    ).resolves.toBeUndefined();
    expect(supabase.from).not.toHaveBeenCalled();
  });

  it('allows an initiator to verify', async () => {
    const parties = [{ entity_ref: 'ent-A', party_role: 'initiator' }];
    const supabase = makeSupabase(parties);
    await expect(
      authorizeHandshakeVerify(supabase, 'ent-A', 'hs-1')
    ).resolves.toBeUndefined();
  });

  it('allows a responder to verify', async () => {
    const parties = [{ entity_ref: 'ent-B', party_role: 'responder' }];
    const supabase = makeSupabase(parties);
    await expect(
      authorizeHandshakeVerify(supabase, 'ent-B', 'hs-1')
    ).resolves.toBeUndefined();
  });

  it('allows a verifier role to verify', async () => {
    const parties = [{ entity_ref: 'ent-C', party_role: 'verifier' }];
    const supabase = makeSupabase(parties);
    await expect(
      authorizeHandshakeVerify(supabase, 'ent-C', 'hs-1')
    ).resolves.toBeUndefined();
  });

  it('denies an entity with an unauthorized role', async () => {
    const parties = [{ entity_ref: 'ent-D', party_role: 'observer' }];
    const supabase = makeSupabase(parties);
    await expect(
      authorizeHandshakeVerify(supabase, 'ent-D', 'hs-1')
    ).rejects.toThrow(HandshakeError);
  });

  it('denies a non-party entity', async () => {
    const parties = [{ entity_ref: 'ent-A', party_role: 'initiator' }];
    const supabase = makeSupabase(parties);
    await expect(
      authorizeHandshakeVerify(supabase, 'ent-unknown', 'hs-1')
    ).rejects.toThrow(HandshakeError);
  });
});

// ---------------------------------------------------------------------------
// authorizeHandshakeRevoke
// ---------------------------------------------------------------------------

describe('authorizeHandshakeRevoke', () => {
  it('allows system actor', async () => {
    const supabase = { from: vi.fn() };
    await expect(
      authorizeHandshakeRevoke(supabase, 'system', 'hs-1')
    ).resolves.toBeUndefined();
    expect(supabase.from).not.toHaveBeenCalled();
  });

  it('allows the initiator to revoke', async () => {
    const parties = [{ entity_ref: 'ent-A', party_role: 'initiator' }];
    const supabase = makeSupabase(parties);
    await expect(
      authorizeHandshakeRevoke(supabase, 'ent-A', 'hs-1')
    ).resolves.toBeUndefined();
  });

  it('denies the responder from revoking', async () => {
    const parties = [
      { entity_ref: 'ent-A', party_role: 'initiator' },
      { entity_ref: 'ent-B', party_role: 'responder' },
    ];
    const supabase = makeSupabase(parties);
    await expect(
      authorizeHandshakeRevoke(supabase, 'ent-B', 'hs-1')
    ).rejects.toThrow(HandshakeError);
  });

  it('denied revoke error has status 403', async () => {
    const parties = [{ entity_ref: 'ent-A', party_role: 'responder' }];
    const supabase = makeSupabase(parties);
    try {
      await authorizeHandshakeRevoke(supabase, 'ent-A', 'hs-1');
    } catch (err) {
      expect(err.status).toBe(403);
    }
  });

  it('denies a non-party entity from revoking', async () => {
    const parties = [{ entity_ref: 'ent-A', party_role: 'initiator' }];
    const supabase = makeSupabase(parties);
    await expect(
      authorizeHandshakeRevoke(supabase, 'outsider', 'hs-1')
    ).rejects.toThrow(HandshakeError);
  });
});
