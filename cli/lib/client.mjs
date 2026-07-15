/**
 * @emilia-protocol/cli — API client
 */

export class EPClient {
  constructor(baseUrl, apiKey = '', fetchImpl = globalThis.fetch) {
    const parsed = new URL(baseUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('EP_BASE_URL must use http or https');
    }
    if (typeof fetchImpl !== 'function') {
      throw new Error('A fetch implementation is required');
    }
    this.baseUrl = parsed.toString().replace(/\/+$/, '');
    this.apiKey = apiKey;
    this.fetch = fetchImpl;
  }

  async _fetch(path, opts = {}) {
    const url = new URL(path, `${this.baseUrl}/`).toString();
    const headers = { 'Content-Type': 'application/json' };
    if (this.apiKey) headers['Authorization'] = `Bearer ${this.apiKey}`;
    let res;
    try {
      res = await this.fetch(url, { ...opts, headers: { ...headers, ...opts.headers } });
    } catch (error) {
      throw new Error(`API request failed: ${error.message}`);
    }

    const body = await res.text();
    let data = {};
    if (body) {
      try {
        data = JSON.parse(body);
      } catch {
        if (!res.ok) throw new Error(`HTTP ${res.status}: ${body.slice(0, 200)}`);
        throw new Error(`Expected JSON from ${url}`);
      }
    }
    if (!res.ok) throw new Error(data.error || data.message || `HTTP ${res.status}`);
    return data;
  }

  async register(entityId, displayName, entityType = 'agent', description = '') {
    return this._fetch('/api/entities/register', {
      method: 'POST',
      body: JSON.stringify({ entity_id: entityId, display_name: displayName, entity_type: entityType, description }),
    });
  }

  async profile(entityId) {
    return this._fetch(`/api/trust/profile/${encodeURIComponent(entityId)}`);
  }

  async evaluate(entityId, policy = 'standard') {
    return this._fetch('/api/trust/evaluate', {
      method: 'POST',
      body: JSON.stringify({ entity_id: entityId, policy }),
    });
  }

  async submit(entityId, transactionRef, behavior = 'completed', extras = {}) {
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

  async preflight(entityId, policy = 'standard', context = {}) {
    return this._fetch('/api/trust/install-preflight', {
      method: 'POST',
      body: JSON.stringify({ entity_id: entityId, policy, context }),
    });
  }

  async score(entityId) {
    return this._fetch(`/api/score/${encodeURIComponent(entityId)}`);
  }

  async dispute(disputeId) {
    return this._fetch(`/api/disputes/${encodeURIComponent(disputeId)}`);
  }

  async fileDispute(receiptId, reason) {
    return this._fetch('/api/disputes/file', {
      method: 'POST',
      body: JSON.stringify({ receipt_id: receiptId, reason }),
    });
  }

  async appeal(disputeId, reason) {
    return this._fetch('/api/disputes/appeal', {
      method: 'POST',
      body: JSON.stringify({ dispute_id: disputeId, reason }),
    });
  }

  async verifyRemote(receiptId) {
    return this._fetch(`/api/verify/${encodeURIComponent(receiptId)}`);
  }

  async policies() {
    return this._fetch('/api/policies');
  }

  async health() {
    return this._fetch('/api/health');
  }
}
