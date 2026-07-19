#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Offline incident-response drill: key compromise -> revocation -> old
// authorization rejected. This gives reviewers a runnable proof of the
// procedure before a real incident.

import {
  buildRevocation,
  verifyRevocation,
  isRevoked,
} from '../../lib/revocation/revocation.js';
import { generateEd25519KeyPair } from '../../packages/issue/index.js';

export function runKeyCompromiseDrill({ now = '2026-06-28T12:00:00.000Z' } = {}) {
  const compromised = generateEd25519KeyPair();
  const target = {
    target_type: 'receipt',
    target_id: 'rcpt_gov_drill_001',
    action_hash: `sha256:${'a'.repeat(64)}`,
  };
  const revokerId = 'ep:key:incident-commander#1';
  const statement = buildRevocation({
    target,
    revoker_id: revokerId,
    revoked_at: now,
    reason: 'drill: signing key compromise',
    signer: {
      privateKey: compromised.privateKey,
      publicKeyB64u: compromised.publicKeyB64u,
    },
  });
  const revokerKeys = { [revokerId]: { public_key: compromised.publicKeyB64u } };
  const before = isRevoked(target, [], { revokerKeys });
  const verification = verifyRevocation(target, statement, { revokerKeys, now });
  const after = isRevoked(target, [statement], { revokerKeys, now });
  return {
    drill: 'key-compromise',
    target,
    before_revocation_seen: before,
    revocation_statement_valid: verification.valid,
    after_revocation_seen: after,
    accepted_after_revocation: !after,
    checks: verification.checks,
  };
}

if (process.argv[1]?.endsWith('key-compromise-drill.mjs')) {
  const result = runKeyCompromiseDrill();
  console.log(JSON.stringify(result, null, 2));
  if (result.accepted_after_revocation || !result.revocation_statement_valid) process.exit(1);
}
