// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from 'vitest';
import { releaseLockRuntimeInternals } from './runtime.js';

const ENV_NAMES = [
  'RELEASE_LOCK_ACROBAT_SIGN_API_ORIGIN',
  'RELEASE_LOCK_ACROBAT_SIGN_OAUTH_ACCESS_TOKEN',
  'RELEASE_LOCK_ESCROW_COM_ENVIRONMENT',
  'RELEASE_LOCK_ESCROW_COM_EMAIL',
  'RELEASE_LOCK_ESCROW_COM_API_KEY',
  'RELEASE_LOCK_ESCROW_COM_DILIGENCE_JSON',
  'RELEASE_LOCK_INVITATION_FROM',
  'RELEASE_LOCK_PUBLIC_ORIGIN',
  'RESEND_API_KEY',
];

afterEach(() => {
  for (const name of ENV_NAMES) vi.unstubAllEnvs(name);
  vi.unstubAllEnvs();
});

describe('Release Lock environment adapter resolution', () => {
  it('constructs only the pinned Acrobat Sign adapter', () => {
    vi.stubEnv(
      'RELEASE_LOCK_ACROBAT_SIGN_API_ORIGIN',
      'https://api.na1.adobesign.com',
    );
    vi.stubEnv('RELEASE_LOCK_ACROBAT_SIGN_OAUTH_ACCESS_TOKEN', 'oauth-token');

    expect(releaseLockRuntimeInternals.resolveEnvironmentDocumentAdapter({
      provider: 'other',
    })).toBeNull();
    expect(releaseLockRuntimeInternals.resolveEnvironmentDocumentAdapter({
      provider: 'acrobat_sign',
    })).toMatchObject({
      kind: 'external_esign_adapter',
      provider: 'acrobat_sign',
      api_origin: 'https://api.na1.adobesign.com',
    });
  });

  it('refuses partial or invalid Acrobat Sign deployment configuration', () => {
    vi.stubEnv(
      'RELEASE_LOCK_ACROBAT_SIGN_API_ORIGIN',
      'https://attacker.example',
    );
    vi.stubEnv('RELEASE_LOCK_ACROBAT_SIGN_OAUTH_ACCESS_TOKEN', 'oauth-token');
    expect(releaseLockRuntimeInternals.resolveEnvironmentDocumentAdapter({
      provider: 'acrobat_sign',
    })).toBeNull();

    vi.stubEnv('RELEASE_LOCK_ACROBAT_SIGN_API_ORIGIN', '');
    expect(releaseLockRuntimeInternals.resolveEnvironmentDocumentAdapter({
      provider: 'acrobat_sign',
    })).toBeNull();
  });

  it('constructs an Escrow.com adapter only for the exact signed environment', () => {
    vi.stubEnv('RELEASE_LOCK_ESCROW_COM_ENVIRONMENT', 'sandbox');
    vi.stubEnv('RELEASE_LOCK_ESCROW_COM_EMAIL', 'operator@example.com');
    vi.stubEnv('RELEASE_LOCK_ESCROW_COM_API_KEY', 'api-key');
    vi.stubEnv(
      'RELEASE_LOCK_ESCROW_COM_DILIGENCE_JSON',
      JSON.stringify({
        review_status: 'customer_complete',
        reviewed_provider: 'escrow.com',
      }),
    );
    const claimEffectBinding = vi.fn(async () => true);

    expect(releaseLockRuntimeInternals.resolveEnvironmentCustodianAdapter({
      provider: 'escrow.com',
      environment: 'production',
      claimEffectBinding,
    })).toBeNull();
    expect(releaseLockRuntimeInternals.resolveEnvironmentCustodianAdapter({
      provider: 'other',
      environment: 'sandbox',
      claimEffectBinding,
    })).toBeNull();
    expect(releaseLockRuntimeInternals.resolveEnvironmentCustodianAdapter({
      provider: 'escrow.com',
      environment: 'sandbox',
      claimEffectBinding,
    })).toMatchObject({
      kind: 'external_custodian',
      provider: 'escrow.com',
      environment: 'sandbox',
      customer_diligence: {
        review_status: 'customer_complete',
        reviewed_provider: 'escrow.com',
      },
    });
  });

  it('refuses malformed diligence or a missing durable effect claim', () => {
    vi.stubEnv('RELEASE_LOCK_ESCROW_COM_ENVIRONMENT', 'sandbox');
    vi.stubEnv('RELEASE_LOCK_ESCROW_COM_EMAIL', 'operator@example.com');
    vi.stubEnv('RELEASE_LOCK_ESCROW_COM_API_KEY', 'api-key');
    vi.stubEnv('RELEASE_LOCK_ESCROW_COM_DILIGENCE_JSON', '[]');

    expect(releaseLockRuntimeInternals.resolveEnvironmentCustodianAdapter({
      provider: 'escrow.com',
      environment: 'sandbox',
      claimEffectBinding: async () => true,
    })).toBeNull();

    vi.stubEnv(
      'RELEASE_LOCK_ESCROW_COM_DILIGENCE_JSON',
      '{"review_status":"customer_complete"}',
    );
    expect(releaseLockRuntimeInternals.resolveEnvironmentCustodianAdapter({
      provider: 'escrow.com',
      environment: 'sandbox',
    })).toBeNull();
  });

  it('parses only bounded environment text and plain JSON objects', () => {
    vi.stubEnv('RELEASE_LOCK_ESCROW_COM_EMAIL', '  operator@example.com  ');
    expect(releaseLockRuntimeInternals.environmentText(
      'RELEASE_LOCK_ESCROW_COM_EMAIL',
      320,
    )).toBe('operator@example.com');
    vi.stubEnv('RELEASE_LOCK_ESCROW_COM_EMAIL', 'x'.repeat(321));
    expect(releaseLockRuntimeInternals.environmentText(
      'RELEASE_LOCK_ESCROW_COM_EMAIL',
      320,
    )).toBeNull();
    vi.stubEnv('RELEASE_LOCK_ESCROW_COM_DILIGENCE_JSON', '{bad');
    expect(releaseLockRuntimeInternals.environmentJsonObject(
      'RELEASE_LOCK_ESCROW_COM_DILIGENCE_JSON',
    )).toBeNull();
    for (const value of ['null', '[]', '"text"']) {
      vi.stubEnv('RELEASE_LOCK_ESCROW_COM_DILIGENCE_JSON', value);
      expect(releaseLockRuntimeInternals.environmentJsonObject(
        'RELEASE_LOCK_ESCROW_COM_DILIGENCE_JSON',
      )).toBeNull();
    }
    vi.stubEnv('RELEASE_LOCK_ESCROW_COM_DILIGENCE_JSON', '{"ok":true}');
    expect(releaseLockRuntimeInternals.environmentJsonObject(
      'RELEASE_LOCK_ESCROW_COM_DILIGENCE_JSON',
    )).toEqual({ ok: true });
  });

  it('refuses invalid custodian deployment configuration inside the adapter', () => {
    vi.stubEnv('RELEASE_LOCK_ESCROW_COM_ENVIRONMENT', 'invalid');
    vi.stubEnv('RELEASE_LOCK_ESCROW_COM_EMAIL', 'operator@example.com');
    vi.stubEnv('RELEASE_LOCK_ESCROW_COM_API_KEY', 'api-key');
    vi.stubEnv('RELEASE_LOCK_ESCROW_COM_DILIGENCE_JSON', '{"review_status":"complete"}');
    expect(releaseLockRuntimeInternals.resolveEnvironmentCustodianAdapter({
      provider: 'escrow.com',
      environment: 'invalid',
      claimEffectBinding: async () => true,
    })).toBeNull();
  });

  it('constructs only a complete pinned Resend invitation adapter', () => {
    expect(releaseLockRuntimeInternals.resolveEnvironmentInvitationAdapter({
      channel: 'sms',
    })).toBeNull();
    expect(releaseLockRuntimeInternals.resolveEnvironmentInvitationAdapter({
      channel: 'email',
    })).toBeNull();

    vi.stubEnv('RESEND_API_KEY', 'resend-key');
    vi.stubEnv('RELEASE_LOCK_INVITATION_FROM', 'EMILIA <team@example.com>');
    vi.stubEnv('RELEASE_LOCK_PUBLIC_ORIGIN', 'https://www.emiliaprotocol.ai');
    const first = releaseLockRuntimeInternals.resolveEnvironmentInvitationAdapter({
      channel: 'email',
    });
    const second = releaseLockRuntimeInternals.resolveEnvironmentInvitationAdapter({
      channel: 'email',
    });
    expect(first).toMatchObject({
      kind: 'verified_contact_delivery',
      provider: 'resend',
      channel: 'email',
    });
    expect(second).toBe(first);
  });
});
