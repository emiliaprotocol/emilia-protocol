import { afterEach, describe, expect, it, vi } from 'vitest';
import { logger } from '../lib/logger.js';

describe('structured logger redaction', () => {
  afterEach(() => vi.restoreAllMocks());

  it('redacts sensitive fields even in test passthrough mode', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

    logger.warn('security event', {
      token: 'secret-token',
      nested: { authorization: 'Bearer secret', visible: 'ok' },
    });

    expect(warn).toHaveBeenCalledWith('security event', {
      token: '[REDACTED]',
      nested: { authorization: '[REDACTED]', visible: 'ok' },
    });
  });
});
