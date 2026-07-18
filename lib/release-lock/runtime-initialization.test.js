// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  adapterBoundary: vi.fn(),
  cryptoSuite: vi.fn(),
  getServiceClient: vi.fn(),
  service: vi.fn(),
}));

vi.mock('../supabase.js', () => ({
  getServiceClient: (...args) => mocks.getServiceClient(...args),
}));
vi.mock('../integrations/action-escrow/acrobat-sign.js', () => ({
  createAcrobatSignAdapter: vi.fn(),
}));
vi.mock('../integrations/action-escrow/escrow-com.js', () => ({
  createEscrowComAdapter: vi.fn(),
}));
vi.mock('./invitation-delivery.js', () => ({
  createResendReleaseLockInvitationAdapter: vi.fn(),
}));
vi.mock('./adapters.js', () => ({
  createReleaseLockAdapterBoundary: (...args) => mocks.adapterBoundary(...args),
}));
vi.mock('./crypto.js', () => ({
  createReleaseLockCrypto: (...args) => mocks.cryptoSuite(...args),
}));
vi.mock('./service.js', () => ({
  createReleaseLockService: (...args) => mocks.service(...args),
}));

const {
  configureReleaseLockAdapters,
  getReleaseLockService,
} = await import('./runtime.js');

describe('Release Lock runtime initialization', () => {
  it('validates resolver injection, initializes once, and reuses one service', () => {
    for (const [name, value] of [
      ['resolveDocumentAdapter', true],
      ['resolveCustodianAdapter', {}],
      ['resolveInvitationAdapter', 'bad'],
    ]) {
      expect(() => configureReleaseLockAdapters({ [name]: value })).toThrow(TypeError);
    }

    configureReleaseLockAdapters({});
    const resolveDocumentAdapter = vi.fn();
    const resolveCustodianAdapter = vi.fn();
    const resolveInvitationAdapter = vi.fn();
    configureReleaseLockAdapters({
      resolveDocumentAdapter,
      resolveCustodianAdapter,
      resolveInvitationAdapter,
    });

    const db = { rpc: vi.fn() };
    const cryptoSuite = { configured: true };
    const adapters = { configured: true };
    const service = { ready: true };
    mocks.getServiceClient.mockReturnValue(db);
    mocks.cryptoSuite.mockReturnValue(cryptoSuite);
    mocks.adapterBoundary.mockReturnValue(adapters);
    mocks.service.mockReturnValue(service);

    expect(getReleaseLockService()).toBe(service);
    expect(getReleaseLockService()).toBe(service);
    expect(mocks.getServiceClient).toHaveBeenCalledTimes(1);
    expect(mocks.adapterBoundary).toHaveBeenCalledWith({
      resolveDocumentAdapter,
      resolveCustodianAdapter,
      resolveInvitationAdapter,
    });
    expect(mocks.service).toHaveBeenCalledWith({
      rpc: expect.any(Function),
      cryptoSuite,
      adapters,
    });
    expect(() => configureReleaseLockAdapters({})).toThrow(
      'Release Lock runtime is already initialized',
    );
  });
});
