// Generated from client.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * @emilia-protocol/cli — API client
 */
let strictJsonGate;
try {
    ({ strictJsonGate } = await import('@emilia-protocol/verify/strict-json'));
}
catch {
    ({ strictJsonGate } = await import('../../packages/verify/strict-json.js'));
}
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 15_000;
function isLoopbackHost(hostname) {
    const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, '');
    return normalized === 'localhost' || normalized === '::1' || /^127(?:\.\d{1,3}){3}$/.test(normalized);
}
export function normalizeSecureBaseUrl(baseUrl) {
    const parsed = new URL(baseUrl);
    if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLoopbackHost(parsed.hostname))) {
        throw new Error('EP_BASE_URL must use HTTPS (HTTP is allowed only for loopback development)');
    }
    if (parsed.username || parsed.password)
        throw new Error('EP_BASE_URL must not contain credentials');
    parsed.hash = '';
    return parsed.toString().replace(/\/+$/, '');
}
export class EPClient {
    baseUrl;
    apiKey;
    fetchImpl;
    constructor(baseUrl, apiKey = '', fetchImpl = globalThis.fetch) {
        if (typeof fetchImpl !== 'function') {
            throw new Error('A fetch implementation is required');
        }
        this.baseUrl = normalizeSecureBaseUrl(baseUrl);
        this.apiKey = apiKey;
        this.fetchImpl = fetchImpl;
    }
    async _fetch(path, opts = {}) {
        const url = new URL(path, `${this.baseUrl}/`).toString();
        const headers = { 'Content-Type': 'application/json' };
        if (this.apiKey)
            headers['Authorization'] = `Bearer ${this.apiKey}`;
        let res;
        try {
            res = await this.fetchImpl(url, {
                ...opts,
                redirect: 'error',
                signal: opts.signal || AbortSignal.timeout(REQUEST_TIMEOUT_MS),
                headers: { ...headers, ...opts.headers },
            });
        }
        catch (error) {
            throw new Error(`API request failed: ${error.message}`);
        }
        const body = await res.text();
        if (Buffer.byteLength(body, 'utf8') > MAX_RESPONSE_BYTES) {
            throw new Error(`API response exceeds ${MAX_RESPONSE_BYTES} bytes`);
        }
        let data = {};
        if (body) {
            const gate = strictJsonGate(body);
            if (!gate.ok) {
                if (!res.ok)
                    throw new Error(`HTTP ${res.status}: ${body.slice(0, 200)}`);
                throw new Error(`Expected unambiguous JSON from ${url}: ${gate.reason}`);
            }
            data = JSON.parse(body);
        }
        if (!res.ok)
            throw new Error(data.error || data.message || `HTTP ${res.status}`);
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
