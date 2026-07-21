/**
 * @emilia-protocol/cli — API client
 */

let strictJsonGate;
try { ({ strictJsonGate } = await import('@emilia-protocol/verify/strict-json')); }
catch { ({ strictJsonGate } = await import('../../packages/verify/strict-json.js')); }

const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 15_000;

function isLoopbackHost(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return normalized === 'localhost' || normalized === '::1' || /^127(?:\.\d{1,3}){3}$/.test(normalized);
}

export function normalizeSecureBaseUrl(baseUrl: string): string {
  const parsed = new URL(baseUrl);
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLoopbackHost(parsed.hostname))) {
    throw new Error('EP_BASE_URL must use HTTPS (HTTP is allowed only for loopback development)');
  }
  if (parsed.username || parsed.password) throw new Error('EP_BASE_URL must not contain credentials');
  parsed.hash = '';
  return parsed.toString().replace(/\/+$/, '');
}

export class EPClient {
  baseUrl: string;
  apiKey: string;
  private fetchImpl: typeof fetch;

  constructor(baseUrl: string, apiKey: string = '', fetchImpl: typeof fetch = globalThis.fetch) {
    if (typeof fetchImpl !== 'function') {
      throw new Error('A fetch implementation is required');
    }
    this.baseUrl = normalizeSecureBaseUrl(baseUrl);
    this.apiKey = apiKey;
    this.fetchImpl = fetchImpl;
  }

  async _fetch(path: string, opts: Record<string, any> = {}): Promise<any> {
    const url = new URL(path, `${this.baseUrl}/`).toString();
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.apiKey) headers['Authorization'] = `Bearer ${this.apiKey}`;
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        ...opts,
        redirect: 'error',
        signal: opts.signal || AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        headers: { ...headers, ...opts.headers },
      });
    } catch (error) {
      throw new Error(`API request failed: ${(error as Error).message}`);
    }

    const body = await res.text();
    if (Buffer.byteLength(body, 'utf8') > MAX_RESPONSE_BYTES) {
      throw new Error(`API response exceeds ${MAX_RESPONSE_BYTES} bytes`);
    }
    let data: any = {};
    if (body) {
      const gate = strictJsonGate(body);
      if (!gate.ok) {
        if (!res.ok) throw new Error(`HTTP ${res.status}: ${body.slice(0, 200)}`);
        throw new Error(`Expected unambiguous JSON from ${url}: ${gate.reason}`);
      }
      data = JSON.parse(body);
    }
    if (!res.ok) throw new Error(data.error || data.message || `HTTP ${res.status}`);
    return data;
  }

  async register(entityId: string, displayName: string, entityType: string = 'agent', description: string = ''): Promise<any> {
    return this._fetch('/api/entities/register', {
      method: 'POST',
      body: JSON.stringify({ entity_id: entityId, display_name: displayName, entity_type: entityType, description }),
    });
  }

  async profile(entityId: string): Promise<any> {
    return this._fetch(`/api/trust/profile/${encodeURIComponent(entityId)}`);
  }

  async evaluate(entityId: string, policy: string = 'standard'): Promise<any> {
    return this._fetch('/api/trust/evaluate', {
      method: 'POST',
      body: JSON.stringify({ entity_id: entityId, policy }),
    });
  }

  async submit(entityId: string, transactionRef: string, behavior: string = 'completed', extras: Record<string, any> = {}): Promise<any> {
    return this._fetch('/api/receipts/submit', {
      method: 'POST',
      body: JSON.stringify({
        entity_id: entityId,
        transaction_ref: transactionRef,
        transaction_type: extras.type || 'purchase',
        agent_behavior: behavior,
        ...extras,
      }),
    });
  }

  async preflight(entityId: string, policy: string = 'standard', context: Record<string, any> = {}): Promise<any> {
    return this._fetch('/api/trust/install-preflight', {
      method: 'POST',
      body: JSON.stringify({ entity_id: entityId, policy, context }),
    });
  }

  async score(entityId: string): Promise<any> {
    return this._fetch(`/api/score/${encodeURIComponent(entityId)}`);
  }

  async dispute(disputeId: string): Promise<any> {
    return this._fetch(`/api/disputes/${encodeURIComponent(disputeId)}`);
  }

  async fileDispute(receiptId: string, reason: string): Promise<any> {
    return this._fetch('/api/disputes/file', {
      method: 'POST',
      body: JSON.stringify({ receipt_id: receiptId, reason }),
    });
  }

  async appeal(disputeId: string, reason: string): Promise<any> {
    return this._fetch('/api/disputes/appeal', {
      method: 'POST',
      body: JSON.stringify({ dispute_id: disputeId, reason }),
    });
  }

  async verifyRemote(receiptId: string): Promise<any> {
    return this._fetch(`/api/verify/${encodeURIComponent(receiptId)}`);
  }

  async policies(): Promise<any> {
    return this._fetch('/api/policies');
  }

  async health(): Promise<any> {
    return this._fetch('/api/health');
  }
}
