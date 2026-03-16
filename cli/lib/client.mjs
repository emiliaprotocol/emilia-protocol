/**
 * @emilia-protocol/cli — API client
 */

export class EPClient {
  constructor(baseUrl, apiKey) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.apiKey = apiKey;
  }

  async _fetch(path, opts = {}) {
    const url = `${this.baseUrl}${path}`;
    const headers = { 'Content-Type': 'application/json' };
    if (this.apiKey) headers['Authorization'] = `Bearer ${this.apiKey}`;
    const res = await fetch(url, { ...opts, headers: { ...headers, ...opts.headers } });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
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

  async policies() {
    return this._fetch('/api/policies');
  }

  async health() {
    return this._fetch('/api/health');
  }
}
