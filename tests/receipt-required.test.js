// SPDX-License-Identifier: Apache-2.0
//
// Receipt Required v0.1: the Action Risk Manifest and the 428 challenge shape
// are the public "no receipt, no irreversible action" rail. These tests keep
// the additive rail honest while preserving the original 402 compatibility path.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  ACTION_RISK_MANIFEST_VERSION,
  DEFAULT_ACTION_RISK_MANIFEST,
  LEGACY_RECEIPT_REQUIRED_STATUS,
  RECEIPT_REQUIRED_HEADER,
  RECEIPT_REQUIRED_STATUS,
  findActionRequirement,
  receiptChallenge,
  receiptRequiredHeader,
  requireEmiliaReceipt,
  validateActionRiskManifest,
} from '../packages/require-receipt/index.js';

const root = resolve(import.meta.dirname, '..');
const readJson = (rel) => JSON.parse(readFileSync(resolve(root, rel), 'utf8'));

function fakeResponse() {
  return {
    headers: {},
    statusCode: null,
    body: null,
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

describe('Action Risk Manifest', () => {
  const manifest = readJson('public/.well-known/agent-actions.json');

  it('publishes the v0.1 manifest and validates cleanly', () => {
    expect(manifest['@version']).toBe(ACTION_RISK_MANIFEST_VERSION);
    expect(validateActionRiskManifest(manifest)).toEqual({ ok: true, errors: [] });
  });

  it('is advertised from ep-trust discovery', () => {
    const discovery = readJson('public/.well-known/ep-trust.json');
    expect(discovery.agent_actions_url).toBe('https://emiliaprotocol.ai/.well-known/agent-actions.json');
  });

  it('resolves dangerous MCP tools to receipt requirements', () => {
    const payment = findActionRequirement(manifest, { protocol: 'mcp', tool: 'release_payment' });
    expect(payment.action_type).toBe('payment.release');
    expect(payment.receipt_required).toBe(true);
    expect(payment.assurance_class).toBe('class_a');

    const deploy = findActionRequirement(manifest, { protocol: 'mcp', tool: 'deploy_production' });
    expect(deploy.risk).toBe('critical');
    expect(deploy.quorum.required).toBe(true);
  });
});

describe('Receipt Required challenge', () => {
  it('keeps the legacy 402 status by default', () => {
    const body = receiptChallenge('payment.release', 'No receipt.');
    expect(body.status).toBe(LEGACY_RECEIPT_REQUIRED_STATUS);
    expect(body.required.proof_header).toBe('X-EMILIA-Receipt');
  });

  it('can emit the 428 Receipt Required rail', () => {
    const body = receiptChallenge('payment.release', 'No receipt.', {
      status: RECEIPT_REQUIRED_STATUS,
      manifestUrl: DEFAULT_ACTION_RISK_MANIFEST,
      assuranceClass: 'class_a',
      maxAgeSec: 900,
    });
    expect(body.status).toBe(RECEIPT_REQUIRED_STATUS);
    expect(body.required.manifest).toBe(DEFAULT_ACTION_RISK_MANIFEST);
    expect(body.required.assurance_class).toBe('class_a');
    expect(body.required.max_age_sec).toBe(900);

    const header = receiptRequiredHeader({
      action: 'payment.release',
      manifestUrl: DEFAULT_ACTION_RISK_MANIFEST,
      assuranceClass: 'class_a',
      maxAgeSec: 900,
    });
    expect(header).toContain('action="payment.release"');
    expect(header).toContain('manifest="/.well-known/agent-actions.json"');
    expect(header).toContain('proof="X-EMILIA-Receipt"');
  });

  it('middleware emits 428 + Receipt-Required when opted in', () => {
    const res = fakeResponse();
    const gate = requireEmiliaReceipt({
      action: 'payment.release',
      statusCode: RECEIPT_REQUIRED_STATUS,
      manifestUrl: DEFAULT_ACTION_RISK_MANIFEST,
      assuranceClass: 'class_a',
      maxAgeSec: 900,
    });

    gate({ headers: {} }, res, () => {
      throw new Error('next() should not run without a receipt');
    });

    expect(res.statusCode).toBe(RECEIPT_REQUIRED_STATUS);
    expect(res.headers[RECEIPT_REQUIRED_HEADER]).toContain('action="payment.release"');
    expect(res.headers['WWW-Authenticate']).toBeUndefined();
    expect(res.body.required.manifest).toBe(DEFAULT_ACTION_RISK_MANIFEST);
  });

  it('middleware remains 402-compatible by default', () => {
    const res = fakeResponse();
    requireEmiliaReceipt({ action: 'payment.release' })({ headers: {} }, res, () => {
      throw new Error('next() should not run without a receipt');
    });

    expect(res.statusCode).toBe(LEGACY_RECEIPT_REQUIRED_STATUS);
    expect(res.headers[RECEIPT_REQUIRED_HEADER]).toContain('action="payment.release"');
    expect(res.headers['WWW-Authenticate']).toContain('EMILIA realm="agent-actions"');
  });
});
