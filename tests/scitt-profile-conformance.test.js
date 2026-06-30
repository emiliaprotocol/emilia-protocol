// SPDX-License-Identifier: Apache-2.0

import { describe, expect, test } from 'vitest';
import {
  buildArtifacts,
  inspectCoseSign1,
  verifyProfileArtifacts,
} from '../examples/scitt/ep-receipt-scitt-conformance.mjs';
import { runEndToEnd } from '../examples/scitt/ep-receipt-scitt-end-to-end.mjs';
import { verifyMockTransparencyReceipt } from '../examples/scitt/mock-scrapi-transparency-service.mjs';

describe('EP-SCITT profile conformance harness', () => {
  test('passes the local EP/COSE/SCRAPI profile checks', () => {
    const artifacts = buildArtifacts();
    const checks = verifyProfileArtifacts(artifacts);
    const byId = Object.fromEntries(checks.map((c) => [c.id, c.pass]));

    expect(byId).toMatchObject({
      native_ep_signature: true,
      cose_sign1_tag: true,
      protected_alg: true,
      protected_cty: true,
      protected_kid: true,
      payload_byte_identity: true,
      sig_structure_signature: true,
      scrapi_request_shape: true,
    });
    expect(checks.every((c) => c.pass)).toBe(true);
  });

  test('carries the EP payload bytes and profile headers inside COSE_Sign1', () => {
    const artifacts = buildArtifacts();
    const parsed = inspectCoseSign1(artifacts.coseSign1);

    expect(Buffer.compare(parsed.payloadBytes, artifacts.payloadBytes)).toBe(0);
    expect(parsed.protected.get(1)).toBe(-8);
    expect(parsed.protected.get(3)).toBe('application/ep-receipt+json');
    expect(Buffer.compare(parsed.protected.get(4), artifacts.kid)).toBe(0);
  });

  test('registers with the mock transparency service and verifies inclusion', async () => {
    const result = await runEndToEnd({ useMockFallback: true });

    expect(result.target).toBe('mock');
    expect(result.registration.ok).toBe(true);
    expect(result.profileChecks.every((c) => c.pass)).toBe(true);
    expect(result.transparencyChecks.every((c) => c.pass)).toBe(true);
    expect(result.passed).toBe(true);
  });

  test('mock transparency receipt refuses statement-byte tampering', async () => {
    const result = await runEndToEnd({ useMockFallback: true });
    const tamperedStatement = Buffer.from(result.artifacts.coseSign1);
    tamperedStatement[tamperedStatement.length - 1] ^= 0x01;
    const checks = verifyMockTransparencyReceipt(result.receipt, tamperedStatement);
    const byId = Object.fromEntries(checks.map((c) => [c.id, c.pass]));

    expect(byId.mock_receipt_signature).toBe(true);
    expect(byId.statement_hash_binding).toBe(false);
    expect(byId.leaf_hash_binding).toBe(false);
  });
});
