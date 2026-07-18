import { afterEach, describe, expect, it, vi } from 'vitest';
import { siemEvent } from '../lib/siem.js';

const KEYS = [
  'SIEM_WEBHOOK_URL',
  'SIEM_AUTH_HEADER',
  'SIEM_FORMAT',
  'SIEM_SOURCE',
  'SIEM_INDEX',
  'SIEM_DISABLED',
  'VERCEL_URL',
  'NODE_ENV',
];
const ORIGINAL = Object.fromEntries(KEYS.map((key) => [key, process.env[key]]));

afterEach(() => {
  vi.unstubAllGlobals();
  for (const key of KEYS) {
    if (ORIGINAL[key] === undefined) delete process.env[key];
    else process.env[key] = ORIGINAL[key];
  }
});

describe('SIEM forwarding configuration', () => {
  it('uses the centralized runtime configuration for the payload and auth header', async () => {
    process.env.SIEM_WEBHOOK_URL = 'https://siem.example.test/ingest';
    process.env.SIEM_AUTH_HEADER = 'Splunk test-token';
    process.env.SIEM_SOURCE = 'sentrix-test';
    process.env.SIEM_INDEX = 'security-test';
    process.env.VERCEL_URL = 'sentrix.example.test';

    const fetchMock = vi.fn(() => Promise.resolve({ ok: true, status: 202 }));
    vi.stubGlobal('fetch', fetchMock);

    await siemEvent('RATE_LIMIT_EXCEEDED', { request_id: 'req-1' });
    const [url, init] = fetchMock.mock.calls[0];
    const body = JSON.parse(init.body);

    expect(url).toBe('https://siem.example.test/ingest');
    expect(init.headers.Authorization).toBe('Splunk test-token');
    expect(body.host).toBe('sentrix.example.test');
    expect(body.source).toBe('sentrix-test');
    expect(body.index).toBe('security-test');
    expect(body.event.severity).toBe('critical');
  });

  it('does not call the sink when forwarding is explicitly disabled', async () => {
    process.env.SIEM_WEBHOOK_URL = 'https://siem.example.test/ingest';
    process.env.SIEM_DISABLED = 'true';
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    await siemEvent('HANDSHAKE_CREATED', { request_id: 'req-2' });

    expect(fetchMock).not.toHaveBeenCalled();
  });
});
