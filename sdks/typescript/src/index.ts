/** EMILIA Protocol — Minimal SDK. Zero dependencies, native fetch. @license Apache-2.0 */

// -- Params -----------------------------------------------------------------

export interface EPClientOptions {
  baseUrl: string;
  apiKey?: string;
  timeout?: number;
  retries?: number;
}

export interface Party {
  entityRef: string;
  role: 'initiator' | 'responder';
}

export interface InitiateHandshakeParams {
  mode: 'mutual' | 'one-way' | 'delegated';
  policyId: string;
  parties: Party[];
  binding?: Record<string, unknown>;
  interactionId?: string;
}

export interface PresentParams {
  partyRole: string;
  presentationType: 'ep_trust_profile' | 'verifiable_credential' | 'attestation';
  claims: Record<string, unknown>;
  issuerRef?: string;
  disclosureMode?: 'full' | 'selective' | 'zk';
}

export interface GateParams {
  entityId: string;
  action: string;
  policy?: 'strict' | 'standard' | 'permissive' | string;
  handshakeId?: string;
  valueUsd?: number;
  delegationId?: string;
}

export interface ConsumeParams {
  receiptData?: Record<string, unknown>;
}

export interface IssueChallengeParams {
  entityId: string;
  scope: string;
  context?: Record<string, unknown>;
}

export interface AttestParams {
  signature: string;
  payload: Record<string, unknown>;
}

export interface ConsumeSignoffParams {
  action: string;
  context?: Record<string, unknown>;
}

// -- Responses --------------------------------------------------------------

export interface Policy {
  name: string;
  family: string;
  description: string;
  minConfidence?: string;
  minScore?: number;
}

export interface Handshake {
  id: string;
  status: string;
  mode: string;
  policyId: string;
  parties: Party[];
  createdAt: string;
}

export interface Presentation {
  presentationId: string;
  partyRole: string;
  status: string;
  createdAt: string;
}

export interface VerificationResult {
  handshakeId: string;
  result: 'accepted' | 'rejected' | 'partial';
  reasonCodes: string[];
  evaluatedAt: string;
}

export interface GateResult {
  decision: 'allow' | 'deny' | 'review';
  commitRef?: string;
  reasons: string[];
  appealPath?: string;
}

export interface SignoffChallenge {
  challengeId: string;
  entityId: string;
  scope: string;
  nonce: string;
  expiresAt: string;
}

export interface SignoffAttestation {
  attestationId: string;
  challengeId: string;
  status: 'valid' | 'invalid' | 'expired';
  signoffId?: string;
  createdAt: string;
}

export interface SignoffConsumption {
  signoffId: string;
  consumed: boolean;
  action: string;
  consumedAt?: string;
}

export interface Consumption {
  handshakeId: string;
  consumed: boolean;
  receiptId?: string;
  consumedAt?: string;
}

// -- Error ------------------------------------------------------------------

export class EPError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
    public readonly code?: string,
  ) {
    super(message);
    this.name = 'EPError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// -- Client -----------------------------------------------------------------

export class EPClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;
  private readonly retries: number;

  constructor(options: EPClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.apiKey = options.apiKey ?? '';
    this.timeout = options.timeout ?? 10_000;
    this.retries = options.retries ?? 2;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    auth = false,
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': '@emilia-protocol/sdk/0.9.0',
    };
    if (auth && this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    let lastErr: unknown;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), this.timeout);
      try {
        const res = await fetch(url, {
          method,
          headers,
          body: body !== undefined ? JSON.stringify(body) : undefined,
          signal: ctrl.signal,
        });
        const data: unknown = await res.json().catch(() => undefined);
        if (!res.ok) {
          const p = data as Record<string, unknown> | undefined;
          const msg = typeof p?.['error'] === 'string' ? p['error'] : `EP API error: ${res.status}`;
          const code = typeof p?.['code'] === 'string' ? p['code'] : undefined;
          throw new EPError(msg, res.status, code);
        }
        return data as T;
      } catch (err) {
        lastErr = err;
        if (err instanceof EPError) {
          // Only retry on 5xx
          if (err.status && err.status < 500) throw err;
        }
        if (err instanceof Error && err.name === 'AbortError') {
          lastErr = new EPError(`Request timed out after ${this.timeout}ms`, undefined, 'timeout');
        }
        if (attempt === this.retries) break;
      } finally {
        clearTimeout(timer);
      }
    }
    if (lastErr instanceof EPError) throw lastErr;
    throw new EPError(
      lastErr instanceof Error ? lastErr.message : 'Unknown network error',
      undefined,
      'network_error',
    );
  }

  /** List available trust policies. */
  async listPolicies(params?: { scope?: string }): Promise<Policy[]> {
    const qs = params?.scope ? `?scope=${encodeURIComponent(params.scope)}` : '';
    return this.request<Policy[]>('GET', `/api/policies${qs}`);
  }

  /** Initiate a trust handshake between parties. */
  async initiateHandshake(params: InitiateHandshakeParams): Promise<Handshake> {
    return this.request<Handshake>('POST', '/api/handshake/initiate', params, true);
  }

  /** Present credentials to a handshake. */
  async present(handshakeId: string, params: PresentParams): Promise<Presentation> {
    return this.request<Presentation>(
      'POST',
      `/api/handshake/${encodeURIComponent(handshakeId)}/present`,
      params,
      true,
    );
  }

  /** Verify a handshake — evaluate all presentations against policy. */
  async verify(handshakeId: string): Promise<VerificationResult> {
    return this.request<VerificationResult>(
      'POST',
      `/api/handshake/${encodeURIComponent(handshakeId)}/verify`,
      undefined,
      true,
    );
  }

  /** Pre-action trust gate. Returns allow/deny/review with commit ref. */
  async gate(params: GateParams): Promise<GateResult> {
    return this.request<GateResult>('POST', '/api/gate', {
      entity_id: params.entityId,
      action: params.action,
      policy: params.policy ?? 'standard',
      handshake_id: params.handshakeId,
      value_usd: params.valueUsd,
      delegation_id: params.delegationId,
    }, true);
  }

  /** Issue a signoff challenge for an entity. */
  async issueChallenge(params: IssueChallengeParams): Promise<SignoffChallenge> {
    return this.request<SignoffChallenge>('POST', '/api/signoff/challenge', {
      entity_id: params.entityId,
      scope: params.scope,
      context: params.context,
    }, true);
  }

  /** Attest to a signoff challenge with a cryptographic signature. */
  async attest(challengeId: string, params: AttestParams): Promise<SignoffAttestation> {
    return this.request<SignoffAttestation>(
      'POST',
      `/api/signoff/${encodeURIComponent(challengeId)}/attest`,
      params,
      true,
    );
  }

  /** Consume a signoff — mark it as used for a specific action. */
  async consumeSignoff(signoffId: string, params: ConsumeSignoffParams): Promise<SignoffConsumption> {
    return this.request<SignoffConsumption>(
      'POST',
      `/api/signoff/${encodeURIComponent(signoffId)}/consume`,
      params,
      true,
    );
  }

  /** Consume a handshake -- finalize and optionally bind a receipt. */
  async consume(handshakeId: string, params?: ConsumeParams): Promise<Consumption> {
    return this.request<Consumption>(
      'POST',
      `/api/handshake/${encodeURIComponent(handshakeId)}/consume`,
      params,
      true,
    );
  }
}
