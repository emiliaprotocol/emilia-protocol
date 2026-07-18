/**
 * Service-client isolation regression tests.
 *
 * A service-role Supabase client is mutable. It must be created per request
 * boundary rather than retained in a process-scoped singleton.
 *
 * @license Apache-2.0
 */

import { describe, expect, it, vi } from 'vitest';

const createClient = vi.fn((url, key, options) => ({ url, key, options }));

vi.mock('@supabase/supabase-js', () => ({ createClient }));
vi.mock('../lib/env.js', () => ({
  getSupabaseConfig: () => ({
    url: 'https://test.supabase.co',
    serviceRoleKey: 'test-service-role-key',
  }),
}));
vi.mock('../lib/siem.js', () => ({ siemEvent: vi.fn() }));
vi.mock('../lib/logger.js', () => ({
  logger: { warn: vi.fn(), error: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

const { getServiceClient } = await import('../lib/supabase.js');

describe('service client isolation', () => {
  it('creates a fresh non-persistent client for each call', () => {
    const first = getServiceClient();
    const second = getServiceClient();

    expect(first).not.toBe(second);
    expect(createClient).toHaveBeenCalledWith(
      'https://test.supabase.co',
      'test-service-role-key',
      {
        auth: {
          persistSession: false,
          autoRefreshToken: false,
          detectSessionInUrl: false,
        },
      },
    );
  });
});
