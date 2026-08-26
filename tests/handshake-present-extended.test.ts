/**
 * lib/handshake/present.js — extended coverage for uncovered lines.
 *
 * Uncovered lines:
 *   141-142  _handleAddPresentation: no issuer_ref → self_asserted trust
 *   155      _handleAddPresentation: authorities DB error (non-table-missing) → throws
 *   229      _handleAddPresentation: rpcError → throws HandshakeError DB_ERROR
 */

import crypto from 'node:crypto';
import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockGetServiceClient = vi.fn();
const mockProtocolWrite = vi.fn();

vi.mock('@/lib/supabase', () => ({
  getServiceClient: (...args) => mockGetServiceClient(...args),
}));

vi.mock('@/lib/actor', () => ({
  resolveActorRef: (actor) => (typeof actor === 'string' ? actor : 'system'),
}));

vi.mock('@/lib/protocol-write', () => ({
  protocolWrite: (...args) => mockProtocolWrite(...args),
  COMMAND_TYPES: { ADD_PRESENTATION: 'add_presentation' },
}));

vi.mock('./invariants.js', () => ({
  VALID_PARTY_ROLES: new Set(['initiator', 'responder']),
  VALID_DISCLOSURE_MODES: new Set(['full', 'minimal', 'selective']),
  sha256: (s) => 'sha256:' + s,
}));

vi.mock('./normalize.js', () => ({
  normalizeClaims: (c) => c,
  claimsToCanonicalHash: (c) => 'hash:' + JSON.stringify(c),
}));

import { _handleAddPresentation } from '../lib/handshake/present.js';
import {
  HANDSHAKE_ISSUER_PROOF_PROFILE,
  handshakeIssuerProofBytes,
  verifyHandshakeIssuerProof,
} from '../lib/handshake/issuer-proof.js';

beforeEach(() => {
  vi.clearAllMocks();
});

function makeBaseSupabase({ handshake, handshakeError, party, partyError, authorityResult, rpcResult }) {
  return {
    from: vi.fn((table) => {
      if (table === 'handshakes') {
        return {
          select: vi.fn().mockReturnThis(),
          eq: vi.fn().mockReturnThis(),
          maybeSingle: vi.fn().mockResolvedValue({ data: handshake ?? null, error: handshakeError ?? null }),
        };
      }
      if (table === 'handshake_parties') {
        return {
          select: vi.fn().mockReturnThis(),
          eq: vi.fn().mockReturnThis(),
          maybeSingle: vi.fn().mockResolvedValue({ data: party ?? null, error: partyError ?? null }),
        };
      }
      if (table === 'authorities') {
        return {
          select: vi.fn().mockReturnThis(),
          eq: vi.fn().mockReturnThis(),
          maybeSingle: vi.fn().mockResolvedValue(authorityResult ?? { data: null, error: null }),
        };
      }
      return {
        select: vi.fn().mockReturnThis(),
        eq: vi.fn().mockReturnThis(),
        maybeSingle: vi.fn().mockResolvedValue({ data: null, error: null }),
        insert: vi.fn().mockReturnThis(),
        single: vi.fn().mockResolvedValue({ data: null, error: null }),
      };
    }),
    rpc: vi.fn().mockResolvedValue(rpcResult ?? { data: { ok: true }, error: null }),
  };
}

const validHandshake = {
  handshake_id: 'hs-1',
  status: 'initiated',
  policy_id: 'pol-1',
};

const validParty = {
  id: 'party-1',
  party_role: 'initiator',
  entity_ref: 'system',
};

function makeCommand(overrides = {}) {
  return {
    actor: 'system',
    input: {
      handshake_id: 'hs-1',
      party_role: 'initiator',
      presentation_type: 'self_asserted',
      issuer_ref: null,
      presentation_hash: 'sha256:abc',
      disclosure_mode: 'full',
      raw_claims: { name: 'Alice' },
      ...overrides,
    },
  };
}

// ── Lines 141-142: no issuer_ref → self_asserted ─────────────────────────────

describe('_handleAddPresentation — self_asserted trust (lines 141-142)', () => {
  it('sets issuerTrusted=false and issuerTrustReason=self_asserted when no issuer_ref', async () => {
    // Audit-fix H4 (commit 004bb3d): self-asserted presentations are now
    // UNTRUSTED by default. Policies must opt in per-role via
    // rules.required_parties.<role>.allow_self_asserted = true; verify.js
    // checks that flag against the issuer_status. Previous behavior
    // (issuerTrusted=true) was the underlying H4 vulnerability.
    const db = makeBaseSupabase({
      handshake: validHandshake,
      party: validParty,
    });
    mockGetServiceClient.mockReturnValue(db);

    const result = await _handleAddPresentation(makeCommand({ issuer_ref: null }));
    expect(result).toHaveProperty('_protocolEventWritten', true);
    expect(db.rpc).toHaveBeenCalledWith(
      'present_handshake_writes',
      expect.objectContaining({ p_issuer_trusted: false, p_issuer_status: 'self_asserted' })
    );
  });
});

// ── Line 155: authorities DB error (non-table-missing) → throws ──────────────

describe('_handleAddPresentation — authority DB error (line 155)', () => {
  it('throws HandshakeError DB_ERROR when authority query fails with non-table error', async () => {
    const db = makeBaseSupabase({
      handshake: validHandshake,
      party: validParty,
      authorityResult: { data: null, error: { message: 'permission denied for table authorities' } },
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(
      _handleAddPresentation(makeCommand({ issuer_ref: 'key-abc' }))
    ).rejects.toMatchObject({ code: 'DB_ERROR' });
  });

  it('does NOT throw when authority error is a missing-table error', async () => {
    // Audit-fix H4 (commit 004bb3d): present.js now matches PostgreSQL
    // SQLSTATE 42P01 (undefined_table) explicitly instead of substring-
    // matching the error message. The mock must include the explicit
    // `code: '42P01'` field so the matcher fires.
    const db = makeBaseSupabase({
      handshake: validHandshake,
      party: validParty,
      authorityResult: {
        data: null,
        error: {
          code: '42P01',
          message: 'relation "authorities" does not exist',
        },
      },
    });
    mockGetServiceClient.mockReturnValue(db);

    const result = await _handleAddPresentation(makeCommand({ issuer_ref: 'key-abc' }));
    expect(result).toHaveProperty('_protocolEventWritten', true);
    expect(db.rpc).toHaveBeenCalledWith(
      'present_handshake_writes',
      expect.objectContaining({ p_issuer_trusted: false, p_issuer_status: 'authority_table_missing' })
    );
  });
});

describe('_handleAddPresentation — issuer possession proof', () => {
  function authority(keyId, publicKey) {
    return {
      data: {
        authority_id: 'd57a4727-c7a9-4d97-a475-49be9b375f82',
        key_id: keyId,
        public_key: publicKey,
        algorithm: 'Ed25519',
        status: 'active',
        valid_from: '2020-01-01T00:00:00.000Z',
        valid_to: '2099-01-01T00:00:00.000Z',
        revoked_at: null,
      },
      error: null,
    };
  }

  it('does not mark an active registry key as issuer participation without a signature', async () => {
    const keypair = crypto.generateKeyPairSync('ed25519');
    const publicKey = keypair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const db = makeBaseSupabase({
      handshake: validHandshake,
      party: validParty,
      authorityResult: authority('key-abc', publicKey),
    });
    mockGetServiceClient.mockReturnValue(db);

    await _handleAddPresentation(makeCommand({ issuer_ref: 'key-abc', issuer_proof: null }));
    expect(db.rpc).toHaveBeenCalledWith('present_handshake_writes', expect.objectContaining({
      p_verified: false,
      p_issuer_status: 'issuer_proof_missing',
      p_revocation_status: 'unproven',
    }));
  });

  it('verifies a signature over the exact handshake, party, actor, issuer, mode, and claims', async () => {
    const keypair = crypto.generateKeyPairSync('ed25519');
    const keyId = 'key-abc';
    const publicKey = keypair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const statement = {
      handshakeId: 'hs-1',
      partyRole: 'initiator',
      presentationType: 'self_asserted',
      issuerRef: keyId,
      actorEntityRef: 'system',
      disclosureMode: 'full',
      presentationHash: 'sha256:abc',
      canonicalClaimsHash: '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
    };
    const proof = {
      profile: HANDSHAKE_ISSUER_PROOF_PROFILE,
      algorithm: 'Ed25519',
      key_id: keyId,
      signature: crypto.sign(null, handshakeIssuerProofBytes(statement), keypair.privateKey).toString('base64url'),
    };
    const db = makeBaseSupabase({
      handshake: validHandshake,
      party: validParty,
      authorityResult: authority(keyId, publicKey),
    });
    mockGetServiceClient.mockReturnValue(db);

    await _handleAddPresentation(makeCommand({ issuer_ref: keyId, issuer_proof: proof }));
    expect(db.rpc).toHaveBeenCalledWith('present_handshake_writes', expect.objectContaining({
      p_verified: true,
      p_issuer_status: 'authority_signature_valid',
      p_revocation_status: 'good',
      p_event_detail: expect.objectContaining({
        issuer_proof: proof,
        issuer_proof_statement: expect.objectContaining({
          handshake_id: 'hs-1',
          party_role: 'initiator',
          actor_entity_ref: 'system',
          issuer_ref: keyId,
          canonical_claims_hash: '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
        }),
      }),
    }));
  });

  it('refuses a valid signature replayed after any signed field changes', async () => {
    const keypair = crypto.generateKeyPairSync('ed25519');
    const keyId = 'key-abc';
    const publicKey = keypair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    const proof = {
      profile: HANDSHAKE_ISSUER_PROOF_PROFILE,
      algorithm: 'Ed25519',
      key_id: keyId,
      signature: crypto.sign(null, handshakeIssuerProofBytes({
        handshakeId: 'other-handshake',
        partyRole: 'initiator',
        presentationType: 'self_asserted',
        issuerRef: keyId,
        actorEntityRef: 'system',
        disclosureMode: 'full',
        presentationHash: 'sha256:abc',
        canonicalClaimsHash: '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
      }), keypair.privateKey).toString('base64url'),
    };
    const db = makeBaseSupabase({
      handshake: validHandshake,
      party: validParty,
      authorityResult: authority(keyId, publicKey),
    });
    mockGetServiceClient.mockReturnValue(db);

    await _handleAddPresentation(makeCommand({ issuer_ref: keyId, issuer_proof: proof }));
    expect(db.rpc).toHaveBeenCalledWith('present_handshake_writes', expect.objectContaining({
      p_verified: false,
      p_issuer_status: 'issuer_proof_invalid',
    }));
  });

  it.each([
    ['wrong profile', { profile: 'EP-HANDSHAKE-ISSUER-PROOF-v0' }],
    ['wrong algorithm', { algorithm: 'ES256' }],
    ['wrong key id', { key_id: 'key-other' }],
    ['padded signature', { signature: `${Buffer.alloc(64).toString('base64url')}=` }],
    ['short signature', { signature: Buffer.alloc(63).toString('base64url') }],
    ['non-base64url signature', { signature: '***not-base64url***' }],
  ])('rejects invalid proof metadata or encoding: %s', (_label, mutation) => {
    const keypair = crypto.generateKeyPairSync('ed25519');
    const keyId = 'key-abc';
    const statement = {
      handshakeId: 'hs-1',
      partyRole: 'initiator',
      presentationType: 'self_asserted',
      issuerRef: keyId,
      actorEntityRef: 'system',
      disclosureMode: 'full',
      presentationHash: 'sha256:abc',
      canonicalClaimsHash: 'claims-hash',
    };
    const validProof = {
      profile: HANDSHAKE_ISSUER_PROOF_PROFILE,
      algorithm: 'Ed25519',
      key_id: keyId,
      signature: crypto.sign(
        null,
        handshakeIssuerProofBytes(statement),
        keypair.privateKey,
      ).toString('base64url'),
    };
    expect(verifyHandshakeIssuerProof({
      proof: { ...validProof, ...mutation },
      authority: {
        key_id: keyId,
        algorithm: 'Ed25519',
        public_key: keypair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      },
      statement,
    })).toBe(false);
  });

  it.each([
    ['malformed DER', Buffer.from('not-a-der-public-key').toString('base64url'), 'Ed25519'],
    [
      'wrong asymmetric key type',
      crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
        .publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      'Ed25519',
    ],
    [
      'wrong authority algorithm metadata',
      crypto.generateKeyPairSync('ed25519')
        .publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
      'ES256',
    ],
  ])('rejects invalid registry key material: %s', (_label, publicKey, algorithm) => {
    const signer = crypto.generateKeyPairSync('ed25519');
    const keyId = 'key-abc';
    const statement = {
      handshakeId: 'hs-1',
      partyRole: 'initiator',
      presentationType: 'self_asserted',
      issuerRef: keyId,
      actorEntityRef: 'system',
      disclosureMode: 'full',
      presentationHash: 'sha256:abc',
      canonicalClaimsHash: 'claims-hash',
    };
    const proof = {
      profile: HANDSHAKE_ISSUER_PROOF_PROFILE,
      algorithm: 'Ed25519',
      key_id: keyId,
      signature: crypto.sign(
        null,
        handshakeIssuerProofBytes(statement),
        signer.privateKey,
      ).toString('base64url'),
    };
    expect(verifyHandshakeIssuerProof({
      proof,
      authority: { key_id: keyId, public_key: publicKey, algorithm },
      statement,
    })).toBe(false);
  });

  it('persists malformed registry DER as an invalid proof instead of trusted participation', async () => {
    const signer = crypto.generateKeyPairSync('ed25519');
    const keyId = 'key-abc';
    const statement = {
      handshakeId: 'hs-1',
      partyRole: 'initiator',
      presentationType: 'self_asserted',
      issuerRef: keyId,
      actorEntityRef: 'system',
      disclosureMode: 'full',
      presentationHash: 'sha256:abc',
      canonicalClaimsHash: '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
    };
    const proof = {
      profile: HANDSHAKE_ISSUER_PROOF_PROFILE,
      algorithm: 'Ed25519',
      key_id: keyId,
      signature: crypto.sign(
        null,
        handshakeIssuerProofBytes(statement),
        signer.privateKey,
      ).toString('base64url'),
    };
    const db = makeBaseSupabase({
      handshake: validHandshake,
      party: validParty,
      authorityResult: authority(
        keyId,
        Buffer.from('malformed-der-key').toString('base64url'),
      ),
    });
    mockGetServiceClient.mockReturnValue(db);

    await _handleAddPresentation(makeCommand({ issuer_ref: keyId, issuer_proof: proof }));
    expect(db.rpc).toHaveBeenCalledWith('present_handshake_writes', expect.objectContaining({
      p_verified: false,
      p_issuer_status: 'issuer_proof_invalid',
      p_revocation_status: 'invalid_proof',
      p_authority_key_digest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/),
    }));
  });
});

describe('_handleAddPresentation — actor and transactional binding rejection', () => {
  it('rejects an authenticated actor that does not own the selected party before writing', async () => {
    const db = makeBaseSupabase({
      handshake: validHandshake,
      party: { ...validParty, entity_ref: 'entity-owner' },
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(_handleAddPresentation({
      ...makeCommand(),
      actor: { entity_id: 'entity-attacker' },
    })).rejects.toMatchObject({ code: 'ROLE_SPOOFING', status: 403 });
    expect(db.rpc).not.toHaveBeenCalled();
  });

  it('maps a post-read handshake state change to INVALID_STATE', async () => {
    const db = makeBaseSupabase({
      handshake: validHandshake,
      party: validParty,
      rpcResult: { data: { error: 'invalid_state' }, error: null },
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(_handleAddPresentation(makeCommand()))
      .rejects.toMatchObject({ code: 'INVALID_STATE', status: 409 });
  });

  it('maps a post-read party rebind to ROLE_SPOOFING', async () => {
    const db = makeBaseSupabase({
      handshake: validHandshake,
      party: validParty,
      rpcResult: { data: { error: 'party_binding_invalid' }, error: null },
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(_handleAddPresentation(makeCommand()))
      .rejects.toMatchObject({ code: 'ROLE_SPOOFING', status: 403 });
  });
});

// ── Line 229: rpcError → throws HandshakeError DB_ERROR ──────────────────────

describe('_handleAddPresentation — rpcError (line 229)', () => {
  it('throws HandshakeError DB_ERROR when RPC call fails', async () => {
    const db = makeBaseSupabase({
      handshake: validHandshake,
      party: validParty,
      rpcResult: { data: null, error: { message: 'function not found' } },
    });
    mockGetServiceClient.mockReturnValue(db);

    await expect(
      _handleAddPresentation(makeCommand({ issuer_ref: null }))
    ).rejects.toMatchObject({ code: 'DB_ERROR' });
  });
});
