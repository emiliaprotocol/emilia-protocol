import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import {
  computePayloadHash,
  applyEvent,
  rebuildProjections,
  diffProjections,
  verifyEvents,
  reconstitute,
  verifyCommitChainIntegrity,
} from '../scripts/replay-protocol.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEvent(overrides = {}) {
  const payload = overrides.payload_json ?? { receipt_id: 'r1', entity_id: 'e1' };
  const payloadHash = computePayloadHash(payload);
  return {
    event_id: overrides.event_id ?? crypto.randomUUID(),
    aggregate_type: overrides.aggregate_type ?? 'receipt',
    aggregate_id: overrides.aggregate_id ?? 'r1',
    command_type: overrides.command_type ?? 'receipt.submitted',
    parent_event_hash: overrides.parent_event_hash ?? null,
    payload_json: payload,
    payload_hash: overrides.payload_hash ?? payloadHash,
    actor_authority_id: overrides.actor_authority_id ?? null,
    signature: overrides.signature ?? null,
    signed_at: overrides.signed_at ?? null,
    idempotency_key: overrides.idempotency_key ?? null,
    created_at: overrides.created_at ?? '2026-01-01T00:00:00Z',
  };
}

/** Build a minimal commit event with signature and nonce. */
function makeCommitEvent(overrides = {}) {
  const commitId = overrides.aggregate_id ?? `cmt_${crypto.randomUUID().slice(0, 8)}`;
  const nonce = overrides.nonce ?? crypto.randomBytes(16).toString('hex');
  const sig = overrides.signature ?? Buffer.from('test-signature').toString('base64');
  const pubKey = overrides.public_key ?? Buffer.from(crypto.randomBytes(32)).toString('base64');

  return makeEvent({
    aggregate_type: 'commit',
    aggregate_id: commitId,
    command_type: overrides.command_type ?? 'commit.created',
    payload_json: {
      entity_id: overrides.entity_id ?? 'ent-1',
      action_type: overrides.action_type ?? 'transact',
      decision: overrides.decision ?? 'allow',
      nonce,
      signature: sig,
      public_key: pubKey,
      expires_at: overrides.expires_at ?? '2026-02-01T00:00:00Z',
      ...(overrides.extra_payload ?? {}),
    },
    created_at: overrides.created_at ?? '2026-01-01T00:00:00Z',
    ...overrides,
  });
}

// ---------------------------------------------------------------------------
// Empty event log produces empty projections
// ---------------------------------------------------------------------------

describe('Reconstitution — empty event log', () => {
  it('produces empty projections from zero events', () => {
    const report = reconstitute([], {});

    expect(report.deterministic).toBe(true);
    expect(report.totalEventsReplayed).toBe(0);
    expect(Object.keys(report.projectionsRebuilt)).toHaveLength(0);
    expect(report.exactMatches).toBe(0);
    expect(report.driftedRecords).toHaveLength(0);
    expect(report.orphanedInCurrent).toHaveLength(0);
    expect(report.orphanedInReplay).toHaveLength(0);
  });

  it('detects orphans when current state has records but event log is empty', () => {
    const currentState = {
      receipt: {
        r_orphan: { receipt_id: 'r_orphan', entity_id: 'e1' },
      },
    };

    const report = reconstitute([], currentState);

    expect(report.deterministic).toBe(false);
    expect(report.orphanedInCurrent).toHaveLength(1);
    expect(report.orphanedInCurrent[0].aggregate_id).toBe('r_orphan');
  });
});

// ---------------------------------------------------------------------------
// Single receipt event produces correct projection
// ---------------------------------------------------------------------------

describe('Reconstitution — single receipt event', () => {
  it('produces correct projection from a single receipt.submitted event', () => {
    const evt = makeEvent({
      aggregate_type: 'receipt',
      aggregate_id: 'r_single',
      command_type: 'receipt.submitted',
      payload_json: {
        entity_id: 'ent-1',
        submitted_by: 'ent-2',
        transaction_ref: 'txn-001',
        transaction_type: 'purchase',
        delivery_accuracy: 95,
        product_accuracy: 90,
        price_integrity: 88,
        composite_score: 91,
        receipt_hash: 'hash123',
        provenance_tier: 'self_attested',
      },
      created_at: '2026-01-01T00:00:00Z',
    });

    // Build expected current state to match
    const projections = {};
    applyEvent(projections, evt);
    const currentState = { receipt: { ...projections.receipt } };

    const report = reconstitute([evt], currentState);

    expect(report.deterministic).toBe(true);
    expect(report.totalEventsReplayed).toBe(1);
    expect(report.projectionsRebuilt.receipt).toBe(1);
    expect(report.exactMatches).toBe(1);
    expect(report.driftedRecords).toHaveLength(0);
  });

  it('detects drift when current state differs from replayed projection', () => {
    const evt = makeEvent({
      aggregate_type: 'receipt',
      aggregate_id: 'r_drift',
      command_type: 'receipt.submitted',
      payload_json: {
        entity_id: 'ent-1',
        submitted_by: 'ent-2',
        composite_score: 85,
        provenance_tier: 'self_attested',
      },
    });

    // Current state has a different composite_score
    const currentState = {
      receipt: {
        r_drift: {
          receipt_id: 'r_drift',
          entity_id: 'ent-1',
          submitted_by: 'ent-2',
          composite_score: 99, // drifted!
          provenance_tier: 'self_attested',
          dispute_status: null,
          graph_weight: 1.0,
          auto_generated: false,
          created_at: '2026-01-01T00:00:00Z',
        },
      },
    };

    const report = reconstitute([evt], currentState);

    expect(report.deterministic).toBe(false);
    expect(report.driftedRecords.length).toBeGreaterThan(0);
    const driftedRecord = report.driftedRecords.find(
      (d) => d.aggregate_id === 'r_drift',
    );
    expect(driftedRecord).toBeDefined();
    const scoreDiff = driftedRecord.diffs.find(
      (d) => d.field === 'composite_score',
    );
    expect(scoreDiff).toBeDefined();
    expect(scoreDiff.replayed).toBe(85);
    expect(scoreDiff.current).toBe(99);
  });
});

// ---------------------------------------------------------------------------
// Multi-event sequence produces correct final state
// ---------------------------------------------------------------------------

describe('Reconstitution — multi-event sequence', () => {
  it('replays receipt submit + bilateral confirm + dispute lifecycle', () => {
    const events = [
      // Submit receipt
      makeEvent({
        aggregate_type: 'receipt',
        aggregate_id: 'r_multi',
        command_type: 'receipt.submitted',
        payload_json: {
          entity_id: 'ent-1',
          submitted_by: 'ent-2',
          composite_score: 80,
          provenance_tier: 'self_attested',
          bilateral_status: 'pending_confirmation',
        },
        created_at: '2026-01-01T00:00:00Z',
      }),
      // Bilateral confirm
      makeEvent({
        aggregate_type: 'receipt',
        aggregate_id: 'r_multi',
        command_type: 'receipt.bilateral.confirmed',
        payload_json: {
          confirmed_by: 'ent-1',
          confirmed_at: '2026-01-02T00:00:00Z',
        },
        created_at: '2026-01-02T00:00:00Z',
      }),
      // File dispute
      makeEvent({
        aggregate_type: 'dispute',
        aggregate_id: 'disp_multi',
        command_type: 'dispute.filed',
        payload_json: {
          receipt_id: 'r_multi',
          entity_id: 'ent-1',
          filed_by: 'ent-3',
          filed_by_type: 'third_party',
          reason: 'inaccurate_signals',
        },
        created_at: '2026-01-03T00:00:00Z',
      }),
      // Resolve dispute
      makeEvent({
        aggregate_type: 'dispute',
        aggregate_id: 'disp_multi',
        command_type: 'dispute.resolved',
        payload_json: {
          resolution: 'upheld',
          resolution_rationale: 'Verified.',
          resolved_by: 'op-1',
          resolved_at: '2026-01-04T00:00:00Z',
        },
        created_at: '2026-01-04T00:00:00Z',
      }),
      // Register entity
      makeEvent({
        aggregate_type: 'entity',
        aggregate_id: 'ent-1',
        command_type: 'entity.registered',
        payload_json: {
          display_name: 'Entity One',
          entity_type: 'agent',
          description: 'Test entity',
        },
        created_at: '2026-01-01T00:00:00Z',
      }),
      // Create delegation
      makeEvent({
        aggregate_type: 'delegation',
        aggregate_id: 'del_1',
        command_type: 'delegation.created',
        payload_json: {
          principal_id: 'user-1',
          agent_entity_id: 'ent-1',
          scope: { actions: ['transact'] },
        },
        created_at: '2026-01-01T00:00:00Z',
      }),
      // Create commit
      makeCommitEvent({
        aggregate_id: 'cmt_multi',
        created_at: '2026-01-05T00:00:00Z',
      }),
    ];

    // Build expected state by replaying
    const { projections } = rebuildProjections(events);
    const currentState = {};
    for (const aggType of Object.keys(projections)) {
      currentState[aggType] = { ...projections[aggType] };
    }

    const report = reconstitute(events, currentState);

    expect(report.deterministic).toBe(true);
    expect(report.totalEventsReplayed).toBe(7);
    expect(report.projectionsRebuilt.receipt).toBe(1);
    expect(report.projectionsRebuilt.dispute).toBe(1);
    expect(report.projectionsRebuilt.entity).toBe(1);
    expect(report.projectionsRebuilt.delegation).toBe(1);
    expect(report.projectionsRebuilt.commit).toBe(1);
    expect(report.driftedRecords).toHaveLength(0);
    expect(report.orphanedInCurrent).toHaveLength(0);
    expect(report.orphanedInReplay).toHaveLength(0);

    // Verify final state values
    expect(projections.receipt['r_multi'].provenance_tier).toBe('bilateral');
    expect(projections.dispute['disp_multi'].status).toBe('upheld');
    expect(projections.entity['ent-1'].emilia_score).toBe(50.0);
    expect(projections.delegation['del_1'].status).toBe('active');
  });
});

// ---------------------------------------------------------------------------
// Events applied in wrong order are detected
// ---------------------------------------------------------------------------

describe('Reconstitution — event ordering', () => {
  it('produces different state when events are applied out of order', () => {
    // Create two events that produce different results depending on order:
    // First: submit receipt with score 80
    // Second: submit a NEW receipt with same ID and score 95 (overwrites)
    const evt1 = makeEvent({
      aggregate_type: 'receipt',
      aggregate_id: 'r_order',
      command_type: 'receipt.submitted',
      payload_json: {
        entity_id: 'ent-1',
        submitted_by: 'ent-2',
        composite_score: 80,
        provenance_tier: 'self_attested',
      },
      created_at: '2026-01-01T00:00:00Z',
    });

    const evt2 = makeEvent({
      aggregate_type: 'receipt',
      aggregate_id: 'r_order',
      command_type: 'receipt.submitted',
      payload_json: {
        entity_id: 'ent-1',
        submitted_by: 'ent-2',
        composite_score: 95,
        provenance_tier: 'self_attested',
      },
      created_at: '2026-01-02T00:00:00Z',
    });

    // Correct order: evt1 then evt2 -> score = 95
    const { projections: correctState } = rebuildProjections([evt1, evt2]);
    expect(correctState.receipt['r_order'].composite_score).toBe(95);

    // Wrong order: evt2 then evt1 -> score = 80 (evt1 overwrites evt2)
    // Manually apply in wrong order
    const projWrong = {};
    applyEvent(projWrong, evt2);
    applyEvent(projWrong, evt1);
    expect(projWrong.receipt['r_order'].composite_score).toBe(80);

    // Reconstitution with correct-order events against wrong-order state
    // should detect drift
    const report = reconstitute([evt1, evt2], {
      receipt: { r_order: projWrong.receipt['r_order'] },
    });

    expect(report.deterministic).toBe(false);
    expect(report.driftedRecords.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Tampered event hash is detected
// ---------------------------------------------------------------------------

describe('Reconstitution — tampered event hash', () => {
  it('detects a tampered payload hash in the event integrity check', () => {
    const evt = makeEvent({
      aggregate_type: 'receipt',
      aggregate_id: 'r_tampered',
      command_type: 'receipt.submitted',
      payload_json: {
        entity_id: 'ent-1',
        submitted_by: 'ent-2',
        composite_score: 90,
      },
      payload_hash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    });

    const { projections } = rebuildProjections([evt]);
    const currentState = { receipt: { ...projections.receipt } };

    const report = reconstitute([evt], currentState);

    expect(report.deterministic).toBe(false);
    expect(report.eventIntegrity.invalidHashes.length).toBe(1);
    expect(report.eventIntegrity.invalidHashes[0].event_id).toBe(evt.event_id);
  });

  it('detects a broken parent chain reference', () => {
    const evt = makeEvent({
      aggregate_type: 'receipt',
      aggregate_id: 'r_broken_chain',
      command_type: 'receipt.submitted',
      payload_json: {
        entity_id: 'ent-1',
        submitted_by: 'ent-2',
      },
      parent_event_hash: 'nonexistent_parent_hash_that_does_not_exist',
    });

    const { projections } = rebuildProjections([evt]);
    const currentState = { receipt: { ...projections.receipt } };

    const report = reconstitute([evt], currentState);

    expect(report.deterministic).toBe(false);
    expect(report.eventIntegrity.brokenChains.length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// Full lifecycle reconstitutes correctly
// ---------------------------------------------------------------------------

describe('Reconstitution — full lifecycle', () => {
  it('create, update, dispute, resolve lifecycle reconstitutes correctly', () => {
    const events = [
      // 1. Register entity
      makeEvent({
        aggregate_type: 'entity',
        aggregate_id: 'ent-lifecycle',
        command_type: 'entity.registered',
        payload_json: {
          display_name: 'Lifecycle Entity',
          entity_type: 'vendor',
          description: 'For lifecycle test',
        },
        created_at: '2026-01-01T00:00:00Z',
      }),
      // 2. Submit receipt
      makeEvent({
        aggregate_type: 'receipt',
        aggregate_id: 'r_lifecycle',
        command_type: 'receipt.submitted',
        payload_json: {
          entity_id: 'ent-lifecycle',
          submitted_by: 'ent-other',
          transaction_ref: 'txn-lifecycle',
          transaction_type: 'service',
          composite_score: 75,
          provenance_tier: 'self_attested',
          bilateral_status: 'pending_confirmation',
        },
        created_at: '2026-01-02T00:00:00Z',
      }),
      // 3. Bilateral confirm receipt
      makeEvent({
        aggregate_type: 'receipt',
        aggregate_id: 'r_lifecycle',
        command_type: 'receipt.bilateral.confirmed',
        payload_json: {
          confirmed_by: 'ent-lifecycle',
          confirmed_at: '2026-01-03T00:00:00Z',
        },
        created_at: '2026-01-03T00:00:00Z',
      }),
      // 4. File dispute
      makeEvent({
        aggregate_type: 'dispute',
        aggregate_id: 'disp_lifecycle',
        command_type: 'dispute.filed',
        payload_json: {
          receipt_id: 'r_lifecycle',
          entity_id: 'ent-lifecycle',
          filed_by: 'ent-other',
          filed_by_type: 'affected_entity',
          reason: 'inaccurate_signals',
          description: 'Scores seem wrong',
        },
        created_at: '2026-01-04T00:00:00Z',
      }),
      // 5. Respond to dispute
      makeEvent({
        aggregate_type: 'dispute',
        aggregate_id: 'disp_lifecycle',
        command_type: 'dispute.responded',
        payload_json: {
          response: 'Scores are accurate',
          responded_at: '2026-01-05T00:00:00Z',
        },
        created_at: '2026-01-05T00:00:00Z',
      }),
      // 6. Resolve dispute
      makeEvent({
        aggregate_type: 'dispute',
        aggregate_id: 'disp_lifecycle',
        command_type: 'dispute.resolved',
        payload_json: {
          resolution: 'dismissed',
          resolution_rationale: 'Signals verified independently',
          resolved_by: 'operator-1',
          resolved_at: '2026-01-06T00:00:00Z',
        },
        created_at: '2026-01-06T00:00:00Z',
      }),
      // 7. Trust recomputation
      makeEvent({
        aggregate_type: 'entity',
        aggregate_id: 'ent-lifecycle',
        command_type: 'trust.recomputed',
        payload_json: {
          new_score: 82.5,
        },
        created_at: '2026-01-07T00:00:00Z',
      }),
      // 8. Create commit
      makeCommitEvent({
        aggregate_id: 'cmt_lifecycle',
        entity_id: 'ent-lifecycle',
        created_at: '2026-01-08T00:00:00Z',
      }),
      // 9. Fulfill commit
      makeEvent({
        aggregate_type: 'commit',
        aggregate_id: 'cmt_lifecycle',
        command_type: 'commit.fulfilled',
        payload_json: {
          receipt_id: 'r_lifecycle',
          fulfilled_at: '2026-01-09T00:00:00Z',
        },
        created_at: '2026-01-09T00:00:00Z',
      }),
      // 10. Create and revoke delegation
      makeEvent({
        aggregate_type: 'delegation',
        aggregate_id: 'del_lifecycle',
        command_type: 'delegation.created',
        payload_json: {
          principal_id: 'user-lifecycle',
          agent_entity_id: 'ent-lifecycle',
          scope: { actions: ['transact', 'connect'] },
        },
        created_at: '2026-01-10T00:00:00Z',
      }),
      makeEvent({
        aggregate_type: 'delegation',
        aggregate_id: 'del_lifecycle',
        command_type: 'delegation.revoked',
        payload_json: {
          revoked_at: '2026-01-11T00:00:00Z',
        },
        created_at: '2026-01-11T00:00:00Z',
      }),
    ];

    // Build expected state
    const { projections } = rebuildProjections(events);
    const currentState = {};
    for (const aggType of Object.keys(projections)) {
      currentState[aggType] = { ...projections[aggType] };
    }

    const report = reconstitute(events, currentState);

    expect(report.deterministic).toBe(true);
    expect(report.totalEventsReplayed).toBe(11);
    expect(report.driftedRecords).toHaveLength(0);
    expect(report.orphanedInCurrent).toHaveLength(0);
    expect(report.orphanedInReplay).toHaveLength(0);

    // Verify specific state
    expect(projections.entity['ent-lifecycle'].emilia_score).toBe(82.5);
    expect(projections.receipt['r_lifecycle'].provenance_tier).toBe('bilateral');
    expect(projections.receipt['r_lifecycle'].bilateral_status).toBe('confirmed');
    expect(projections.dispute['disp_lifecycle'].status).toBe('dismissed');
    expect(projections.dispute['disp_lifecycle'].response).toBe('Scores are accurate');
    expect(projections.commit['cmt_lifecycle'].status).toBe('fulfilled');
    expect(projections.commit['cmt_lifecycle'].receipt_id).toBe('r_lifecycle');
    expect(projections.delegation['del_lifecycle'].status).toBe('revoked');
  });
});

// ---------------------------------------------------------------------------
// Reconstitution is deterministic (same events -> same state, every time)
// ---------------------------------------------------------------------------

describe('Reconstitution — determinism guarantee', () => {
  it('same events produce identical state across multiple runs', () => {
    const events = [
      makeEvent({
        aggregate_type: 'entity',
        aggregate_id: 'ent-det',
        command_type: 'entity.registered',
        payload_json: {
          display_name: 'Deterministic Entity',
          entity_type: 'agent',
          description: 'Testing determinism',
        },
        created_at: '2026-01-01T00:00:00Z',
      }),
      makeEvent({
        aggregate_type: 'receipt',
        aggregate_id: 'r_det_1',
        command_type: 'receipt.submitted',
        payload_json: {
          entity_id: 'ent-det',
          submitted_by: 'ent-other',
          composite_score: 70,
          provenance_tier: 'self_attested',
        },
        created_at: '2026-01-02T00:00:00Z',
      }),
      makeEvent({
        aggregate_type: 'receipt',
        aggregate_id: 'r_det_2',
        command_type: 'receipt.submitted',
        payload_json: {
          entity_id: 'ent-det',
          submitted_by: 'ent-another',
          composite_score: 85,
          provenance_tier: 'self_attested',
        },
        created_at: '2026-01-03T00:00:00Z',
      }),
      makeEvent({
        aggregate_type: 'entity',
        aggregate_id: 'ent-det',
        command_type: 'trust.recomputed',
        payload_json: { new_score: 77.5 },
        created_at: '2026-01-04T00:00:00Z',
      }),
      makeCommitEvent({
        aggregate_id: 'cmt_det',
        entity_id: 'ent-det',
        created_at: '2026-01-05T00:00:00Z',
      }),
    ];

    // Run reconstitution 5 times and verify identical results
    const results = [];
    for (let i = 0; i < 5; i++) {
      const { projections } = rebuildProjections(events);
      results.push(projections);
    }

    // Compare each run to the first
    const reference = JSON.stringify(results[0], Object.keys(results[0]).sort());
    for (let i = 1; i < results.length; i++) {
      const current = JSON.stringify(results[i], Object.keys(results[i]).sort());
      expect(current).toBe(reference);
    }

    // Also verify the full reconstitute report is deterministic
    const { projections: refProj } = rebuildProjections(events);
    const currentState = {};
    for (const aggType of Object.keys(refProj)) {
      currentState[aggType] = { ...refProj[aggType] };
    }

    const report1 = reconstitute(events, currentState);
    const report2 = reconstitute(events, currentState);

    expect(report1.deterministic).toBe(true);
    expect(report2.deterministic).toBe(true);
    expect(report1.totalEventsReplayed).toBe(report2.totalEventsReplayed);
    expect(report1.exactMatches).toBe(report2.exactMatches);
    expect(report1.driftedRecords.length).toBe(report2.driftedRecords.length);
  });
});

// ---------------------------------------------------------------------------
// Commit chain integrity verification
// ---------------------------------------------------------------------------

describe('Reconstitution — commit chain integrity', () => {
  it('validates commits with unique nonces and valid signatures', () => {
    const commits = [
      {
        commit_id: 'cmt_1',
        entity_id: 'ent-1',
        nonce: 'nonce_aaa',
        signature: Buffer.from('sig1').toString('base64'),
        public_key: Buffer.from(crypto.randomBytes(32)).toString('base64'),
      },
      {
        commit_id: 'cmt_2',
        entity_id: 'ent-2',
        nonce: 'nonce_bbb',
        signature: Buffer.from('sig2').toString('base64'),
        public_key: Buffer.from(crypto.randomBytes(32)).toString('base64'),
      },
    ];

    const report = verifyCommitChainIntegrity(commits);

    expect(report.totalCommits).toBe(2);
    expect(report.validSignatures).toBe(2);
    expect(report.invalidSignatures).toHaveLength(0);
    expect(report.duplicateNonces).toHaveLength(0);
    expect(report.invalidAuthorities).toHaveLength(0);
  });

  it('detects duplicate nonces across commits', () => {
    const commits = [
      {
        commit_id: 'cmt_dup1',
        entity_id: 'ent-1',
        nonce: 'same_nonce',
        signature: Buffer.from('sig1').toString('base64'),
        public_key: Buffer.from(crypto.randomBytes(32)).toString('base64'),
      },
      {
        commit_id: 'cmt_dup2',
        entity_id: 'ent-2',
        nonce: 'same_nonce', // duplicate!
        signature: Buffer.from('sig2').toString('base64'),
        public_key: Buffer.from(crypto.randomBytes(32)).toString('base64'),
      },
    ];

    const report = verifyCommitChainIntegrity(commits);

    expect(report.duplicateNonces).toHaveLength(1);
    expect(report.duplicateNonces[0].commit_id).toBe('cmt_dup2');
    expect(report.duplicateNonces[0].conflicting_commit_id).toBe('cmt_dup1');
  });

  it('detects commits without signatures', () => {
    const commits = [
      {
        commit_id: 'cmt_nosig',
        entity_id: 'ent-1',
        nonce: 'nonce_x',
        signature: null,
        public_key: null,
      },
    ];

    const report = verifyCommitChainIntegrity(commits);

    expect(report.invalidSignatures).toHaveLength(1);
    expect(report.invalidSignatures[0].reason).toBe('no_signature');
  });

  it('detects commits without entity_id (invalid authority)', () => {
    const commits = [
      {
        commit_id: 'cmt_noauth',
        entity_id: null,
        nonce: 'nonce_y',
        signature: Buffer.from('sig').toString('base64'),
        public_key: Buffer.from(crypto.randomBytes(32)).toString('base64'),
      },
    ];

    const report = verifyCommitChainIntegrity(commits);

    expect(report.invalidAuthorities).toHaveLength(1);
    expect(report.invalidAuthorities[0].reason).toBe('missing_entity_id');
  });

  it('reconstitute catches commit chain issues in the full report', () => {
    // Create commit events with duplicate nonces
    const nonce = 'shared_nonce_for_test';
    const events = [
      makeCommitEvent({
        aggregate_id: 'cmt_chain1',
        nonce,
        created_at: '2026-01-01T00:00:00Z',
      }),
      makeCommitEvent({
        aggregate_id: 'cmt_chain2',
        nonce, // same nonce!
        created_at: '2026-01-02T00:00:00Z',
      }),
    ];

    const { projections } = rebuildProjections(events);
    const currentState = { commit: { ...projections.commit } };

    const report = reconstitute(events, currentState);

    expect(report.deterministic).toBe(false);
    expect(report.commitChainIntegrity.duplicateNonces.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Orphan and missing record detection
// ---------------------------------------------------------------------------

describe('Reconstitution — orphan and missing records', () => {
  it('detects records in replay but not in current state (missing)', () => {
    const events = [
      makeEvent({
        aggregate_type: 'receipt',
        aggregate_id: 'r_missing',
        command_type: 'receipt.submitted',
        payload_json: {
          entity_id: 'ent-1',
          submitted_by: 'ent-2',
        },
      }),
    ];

    // Current state is empty — the replayed record is "missing" from current
    const report = reconstitute(events, {});

    expect(report.deterministic).toBe(false);
    expect(report.orphanedInReplay).toHaveLength(1);
    expect(report.orphanedInReplay[0].aggregate_id).toBe('r_missing');
  });

  it('detects records in current state but not in replay (orphaned)', () => {
    const currentState = {
      entity: {
        'ent-phantom': {
          entity_id: 'ent-phantom',
          display_name: 'Phantom',
          entity_type: 'agent',
          status: 'active',
        },
      },
    };

    const report = reconstitute([], currentState);

    expect(report.deterministic).toBe(false);
    expect(report.orphanedInCurrent).toHaveLength(1);
    expect(report.orphanedInCurrent[0].aggregate_id).toBe('ent-phantom');
  });
});
