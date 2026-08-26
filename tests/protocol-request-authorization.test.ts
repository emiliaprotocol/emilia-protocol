// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  authorizeProtocolRequest,
  OBSERVE_PRECHECK_PATHS,
} from '../lib/auth/protocol-request-authorization.js';

const tenant = (permissions: string[]) => ({
  entity: { entity_id: 'entity-1', organization_id: 'org-1' },
  permissions,
});

const pilot = (permissions: string[] = ['observe']) => ({
  entity: {
    entity_id: 'pilot-1',
    organization_id: 'pilot-1',
    metadata: { pilot_sandbox: true, scope: 'observe' },
  },
  permissions,
});

const request = (path?: string, method = 'POST') => ({
  method,
  ...(path === undefined ? {} : { url: `https://www.emiliaprotocol.ai${path}` }),
});

describe('protocol request authorization floor', () => {
  it('leaves non-mutating methods unchanged', () => {
    for (const method of ['GET', 'HEAD', 'OPTIONS', undefined]) {
      expect(authorizeProtocolRequest(tenant([]), {
        url: 'https://www.emiliaprotocol.ai/api/audit',
        ...(method === undefined ? {} : { method }),
      })).toEqual({ allowed: true });
    }
  });

  it('requires write or admin on generic mutations, including missing paths', () => {
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      expect(authorizeProtocolRequest(tenant(['read']), request('/api/delegations/create', method)))
        .toMatchObject({ allowed: false, status: 403, code: 'insufficient_permissions' });
      expect(authorizeProtocolRequest(tenant(['write']), request('/api/delegations/create', method)))
        .toEqual({ allowed: true });
    }
    expect(authorizeProtocolRequest(tenant(['read']), request(undefined, 'PATCH')))
      .toMatchObject({ allowed: false, status: 403, code: 'insufficient_permissions' });
    expect(authorizeProtocolRequest(tenant(['admin']), request(undefined, 'PATCH')))
      .toEqual({ allowed: true });
  });

  it.each([
    ['/api/keys/rotate', 'keys.rotate'],
    ['/api/sso/connections', 'sso.manage'],
    ['/api/scim/v2/provisioning-token', 'scim.manage'],
    ['/api/v1/approvers/webauthn/register-options', 'approver.enroll'],
    ['/api/v1/approvers/webauthn/register-verify', 'approver.enroll'],
    ['/api/v1/mobile/pairings', 'approver.enroll'],
    ['/api/identity/continuity/resolve', 'dispute.review'],
    ['/api/v1/trust-receipts/tr_123/consume', 'receipt.consume'],
    ['/api/v1/trust-receipts/tr_123/execution', 'receipt.execute'],
  ])('requires the exact named capability on POST %s', (path, capability) => {
    expect(authorizeProtocolRequest(tenant([capability]), request(path))).toEqual({ allowed: true });
    expect(authorizeProtocolRequest(tenant(['admin']), request(path))).toEqual({ allowed: true });
    const writeResult = authorizeProtocolRequest(tenant(['write']), request(path));
    if (capability.startsWith('receipt.')) {
      expect(writeResult).toEqual({ allowed: true });
    } else {
      expect(writeResult).toMatchObject({ allowed: false, status: 403, code: 'insufficient_permissions' });
    }
  });

  it('does not extend named capabilities to near-match paths or other methods', () => {
    expect(authorizeProtocolRequest(tenant(['keys.rotate']), request('/api/keys/rotate/')))
      .toMatchObject({ allowed: false, code: 'insufficient_permissions' });
    expect(authorizeProtocolRequest(tenant(['receipt.consume']), request('/api/v1/trust-receipts/tr_1/consume/extra')))
      .toMatchObject({ allowed: false, code: 'insufficient_permissions' });
    expect(authorizeProtocolRequest(tenant(['sso.manage']), request('/api/sso/connections', 'PATCH')))
      .toMatchObject({ allowed: false, code: 'insufficient_permissions' });
  });

  it.each([
    '/api/trust/evaluate',
    '/api/trust/install-preflight',
    '/api/v1/rx-reliance/evaluate',
    '/api/v1/rx-reliance/profiles',
  ])('allows read on the explicit read-only POST %s', (path) => {
    expect(authorizeProtocolRequest(tenant(['read']), request(path))).toEqual({ allowed: true });
    expect(authorizeProtocolRequest(tenant(['write']), request(path))).toEqual({ allowed: true });
    expect(authorizeProtocolRequest(tenant([]), request(path)))
      .toMatchObject({ allowed: false, code: 'insufficient_permissions' });
  });

  it('treats identity verification as a write, not a read-only POST', () => {
    expect(authorizeProtocolRequest(tenant(['read']), request('/api/identity/verify')))
      .toMatchObject({ allowed: false, code: 'insufficient_permissions' });
    expect(authorizeProtocolRequest(tenant(['write']), request('/api/identity/verify')))
      .toEqual({ allowed: true });
  });

  it('allows a marked observe pilot only on the exact reviewed Gov/Fin prechecks', () => {
    expect(OBSERVE_PRECHECK_PATHS).toHaveLength(11);
    for (const path of OBSERVE_PRECHECK_PATHS) {
      expect(authorizeProtocolRequest(pilot(), request(path))).toEqual({ allowed: true });
    }
  });

  it('lets a marked observe pilot read only its sandbox report', () => {
    expect(authorizeProtocolRequest(
      pilot(),
      request('/api/pilot/sandbox/report', 'GET'),
    )).toEqual({ allowed: true });

    for (const path of [
      '/api/feed',
      '/api/stats',
      '/api/entities/search',
      '/api/leaderboard',
      '/api/handshake/policies',
      '/api/v1/trust-receipts/tr_other',
    ]) {
      expect(authorizeProtocolRequest(
        pilot(['observe', 'read', 'write', 'admin']),
        request(path, 'GET'),
      )).toMatchObject({ allowed: false, status: 403, code: 'insufficient_permissions' });
    }
  });

  it('does not turn HEAD, OPTIONS, or a missing method into observe-key read authority', () => {
    for (const method of ['HEAD', 'OPTIONS', undefined]) {
      expect(authorizeProtocolRequest(pilot(['observe', 'admin']), {
        url: 'https://www.emiliaprotocol.ai/api/pilot/sandbox/report',
        ...(method === undefined ? {} : { method }),
      })).toMatchObject({ allowed: false, status: 403, code: 'insufficient_permissions' });
    }
  });

  it.each([
    '/api/v1/adapters/health/hospice-claim/precheck',
    '/api/v1/adapters/fin/payment-release/reconcile',
    '/api/delegations/create',
    '/api/receipts/submit',
    '/api/signoff/challenge',
    '/api/commit/issue',
    '/api/handshake',
    '/api/disputes/file',
    '/api/needs/broadcast',
    '/api/v1/mobile/demo/actions',
    '/api/works/authority-records/drafts',
    '/api/trust/gate',
  ])('denies an observe pilot on %s even when stale write/admin bits exist', (path) => {
    expect(authorizeProtocolRequest(pilot(['observe', 'read', 'write', 'admin']), request(path)))
      .toMatchObject({ allowed: false, status: 403, code: 'insufficient_permissions' });
  });

  it('requires both the server marker and explicit observe permission', () => {
    const path = OBSERVE_PRECHECK_PATHS[0];
    expect(authorizeProtocolRequest(pilot([]), request(path)))
      .toMatchObject({ allowed: false, code: 'insufficient_permissions' });
    expect(authorizeProtocolRequest({
      entity: {
        entity_id: 'legacy-pilot',
        organization_id: 'legacy-pilot',
        display_name: 'Pilot · Legacy',
        description: 'Observe-mode pilot sandbox for Legacy',
        entity_type: 'agent',
      },
      permissions: ['observe', 'write', 'admin'],
    }, request(path))).toMatchObject({ allowed: false, code: 'insufficient_permissions' });

    expect(authorizeProtocolRequest(pilot([]), request('/api/pilot/sandbox/report', 'GET')))
      .toMatchObject({ allowed: false, code: 'insufficient_permissions' });
  });
});
