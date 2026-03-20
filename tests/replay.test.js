import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import {
  computePayloadHash,
  verifyEvents,
  applyEvent,
  rebuildProjections,
  diffProjections,
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

// ---------------------------------------------------------------------------
// Hash verification
// ---------------------------------------------------------------------------

describe('computePayloadHash', () => {
  it('produces a deterministic sha256 hex digest', () => {
    const payload = { foo: 'bar', baz: 1 };
    const hash1 = computePayloadHash(payload);
    const hash2 = computePayloadHash(payload);
    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^[a-f0-9]{64}$/);
  });

  it('produces the same hash regardless of key order', () => {
    const a = computePayloadHash({ z: 1, a: 2 });
    const b = computePayloadHash({ a: 2, z: 1 });
    expect(a).toBe(b);
  });
});

describe('verifyEvents — hash verification', () => {
  it('marks valid hashes as valid', () => {
    const evt = makeEvent();
    const report = verifyEvents([evt]);
    expect(report.totalEvents).toBe(1);
    expect(report.validHashes).toBe(1);
    expect(report.invalidHashes).toHaveLength(0);
  });

  it('detects tampered payloads', () => {
    const payload = { receipt_id: 'r1', entity_id: 'e1' };
    const correctHash = computePayloadHash(payload);

    // Tamper with the payload after hashing
    const tamperedPayload = { receipt_id: 'r1', entity_id: 'e1_TAMPERED' };
    const evt = makeEvent({
      payload_json: tamperedPayload,
      payload_hash: correctHash, // hash of original, not tampered
    });

    const report = verifyEvents([evt]);
    expect(report.validHashes).toBe(0);
    expect(report.invalidHashes).toHaveLength(1);
    expect(report.invalidHashes[0].event_id).toBe(evt.event_id);
  });

  it('detects a completely fabricated hash', () => {
    const evt = makeEvent({
      payload_hash: 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
    });
    const report = verifyEvents([evt]);
    expect(report.invalidHashes).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Chain verification
// ---------------------------------------------------------------------------

describe('verifyEvents — chain verification', () => {
  it('validates a correct parent chain', () => {
    const evt1 = makeEvent({
      event_id: 'e1',
      payload_json: { step: 1 },
    });
    // Recompute hash for evt1 since payload changed
    evt1.payload_hash = computePayloadHash(evt1.payload_json);

    const evt2 = makeEvent({
      event_id: 'e2',
      payload_json: { step: 2 },
      parent_event_hash: evt1.payload_hash,
    });
    evt2.payload_hash = computePayloadHash(evt2.payload_json);

    const report = verifyEvents([evt1, evt2]);
    expect(report.validChains).toBe(1);
    expect(report.brokenChains).toHaveLength(0);
  });

  it('detects a missing parent event', () => {
    const evt = makeEvent({
      parent_event_hash: 'nonexistent_hash_that_matches_no_event',
    });
    const report = verifyEvents([evt]);
    expect(report.brokenChains).toHaveLength(1);
    expect(report.brokenChains[0].event_id).toBe(evt.event_id);
  });

  it('does not report broken chain when parent_event_hash is null', () => {
    const evt = makeEvent({ parent_event_hash: null });
    const report = verifyEvents([evt]);
    expect(report.brokenChains).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Projection rebuild — receipts
// ---------------------------------------------------------------------------

describe('applyEvent — receipt projections', () => {
  it('creates a receipt projection from receipt.submitted', () => {
    const projections = {};
    const evt = makeEvent({
      aggregate_type: 'receipt',
      aggregate_id: 'r_100',
      command_type: 'receipt.submitted',
      payload_json: {
        entity_id: 'ent-1',
        submitted_by: 'ent-2',
        transaction_ref: 'txn-abc',
        transaction_type: 'purchase',
        delivery_accuracy: 90,
        product_accuracy: 85,
        price_integrity: 95,
        composite_score: 88,
        receipt_hash: 'abc123',
        provenance_tier: 'self_attested',
      },
    });

    applyEvent(projections, evt);

    const receipt = projections.receipt['r_100'];
    expect(receipt).toBeDefined();
    expect(receipt.receipt_id).toBe('r_100');
    expect(receipt.entity_id).toBe('ent-1');
    expect(receipt.submitted_by).toBe('ent-2');
    expect(receipt.delivery_accuracy).toBe(90);
    expect(receipt.provenance_tier).toBe('self_attested');
    expect(receipt.dispute_status).toBeNull();
    expect(receipt.graph_weight).toBe(1.0);
  });

  it('upgrades provenance_tier on bilateral confirmation', () => {
    const projections = {};

    // Submit
    applyEvent(projections, makeEvent({
      aggregate_type: 'receipt',
      aggregate_id: 'r_200',
      command_type: 'receipt.submitted',
      payload_json: {
        entity_id: 'ent-1',
        submitted_by: 'ent-2',
        provenance_tier: 'self_attested',
        bilateral_status: 'pending_confirmation',
      },
      created_at: '2026-01-01T00:00:00Z',
    }));

    // Confirm
    applyEvent(projections, makeEvent({
      aggregate_type: 'receipt',
      aggregate_id: 'r_200',
      command_type: 'receipt.bilateral.confirmed',
      payload_json: {
        confirmed_by: 'ent-1',
        confirmed_at: '2026-01-01T01:00:00Z',
      },
      created_at: '2026-01-01T01:00:00Z',
    }));

    const receipt = projections.receipt['r_200'];
    expect(receipt.bilateral_status).toBe('confirmed');
    expect(receipt.provenance_tier).toBe('bilateral');
    expect(receipt.confirmed_by).toBe('ent-1');
  });
});

// ---------------------------------------------------------------------------
// Projection rebuild — disputes
// ---------------------------------------------------------------------------

describe('applyEvent — dispute projections', () => {
  it('creates and resolves a dispute through full lifecycle', () => {
    const projections = {};

    // File
    applyEvent(projections, makeEvent({
      aggregate_type: 'dispute',
      aggregate_id: 'disp_1',
      command_type: 'dispute.filed',
      payload_json: {
        receipt_id: 'r_100',
        entity_id: 'ent-1',
        filed_by: 'ent-2',
        filed_by_type: 'affected_entity',
        reason: 'inaccurate_signals',
      },
      created_at: '2026-01-01T00:00:00Z',
    }));

    expect(projections.dispute['disp_1'].status).toBe('open');

    // Respond
    applyEvent(projections, makeEvent({
      aggregate_type: 'dispute',
      aggregate_id: 'disp_1',
      command_type: 'dispute.responded',
      payload_json: {
        response: 'The signals are accurate.',
        responded_at: '2026-01-02T00:00:00Z',
      },
      created_at: '2026-01-02T00:00:00Z',
    }));

    expect(projections.dispute['disp_1'].status).toBe('under_review');

    // Resolve
    applyEvent(projections, makeEvent({
      aggregate_type: 'dispute',
      aggregate_id: 'disp_1',
      command_type: 'dispute.resolved',
      payload_json: {
        resolution: 'upheld',
        resolution_rationale: 'Signals were verified.',
        resolved_by: 'operator-1',
        resolved_at: '2026-01-03T00:00:00Z',
      },
      created_at: '2026-01-03T00:00:00Z',
    }));

    expect(projections.dispute['disp_1'].status).toBe('upheld');
    expect(projections.dispute['disp_1'].resolution).toBe('upheld');
  });

  it('handles appeal lifecycle', () => {
    const projections = {};

    // File + resolve
    applyEvent(projections, makeEvent({
      aggregate_type: 'dispute',
      aggregate_id: 'disp_2',
      command_type: 'dispute.filed',
      payload_json: {
        receipt_id: 'r_200',
        entity_id: 'ent-1',
        filed_by: 'ent-2',
        filed_by_type: 'affected_entity',
        reason: 'fraudulent_receipt',
      },
    }));

    applyEvent(projections, makeEvent({
      aggregate_type: 'dispute',
      aggregate_id: 'disp_2',
      command_type: 'dispute.resolved',
      payload_json: { resolution: 'reversed' },
    }));

    // Appeal
    applyEvent(projections, makeEvent({
      aggregate_type: 'dispute',
      aggregate_id: 'disp_2',
      command_type: 'dispute.appealed',
      payload_json: {
        appeal_reason: 'The reversal was unjust.',
        appealed_by: 'ent-1',
      },
    }));

    expect(projections.dispute['disp_2'].status).toBe('appealed');

    // Resolve appeal
    applyEvent(projections, makeEvent({
      aggregate_type: 'dispute',
      aggregate_id: 'disp_2',
      command_type: 'dispute.appeal.resolved',
      payload_json: {
        resolution: 'appeal_reversed',
        appeal_rationale: 'Original reversal was in error.',
      },
    }));

    expect(projections.dispute['disp_2'].status).toBe('appeal_reversed');
    expect(projections.dispute['disp_2'].appeal_resolution).toBe('appeal_reversed');
  });
});

// ---------------------------------------------------------------------------
// Projection rebuild — commits
// ---------------------------------------------------------------------------

describe('applyEvent — commit projections', () => {
  it('creates and fulfills a commit', () => {
    const projections = {};

    applyEvent(projections, makeEvent({
      aggregate_type: 'commit',
      aggregate_id: 'cmt_1',
      command_type: 'commit.created',
      payload_json: {
        entity_id: 'ent-1',
        action_type: 'transact',
        decision: 'allow',
        nonce: 'abc123',
        signature: 'sig_xyz',
        public_key: 'pk_xyz',
        expires_at: '2026-02-01T00:00:00Z',
      },
    }));

    expect(projections.commit['cmt_1'].status).toBe('active');
    expect(projections.commit['cmt_1'].decision).toBe('allow');

    applyEvent(projections, makeEvent({
      aggregate_type: 'commit',
      aggregate_id: 'cmt_1',
      command_type: 'commit.fulfilled',
      payload_json: {
        receipt_id: 'r_300',
        fulfilled_at: '2026-01-15T00:00:00Z',
      },
    }));

    expect(projections.commit['cmt_1'].status).toBe('fulfilled');
    expect(projections.commit['cmt_1'].receipt_id).toBe('r_300');
  });
});

// ---------------------------------------------------------------------------
// Projection rebuild — reports
// ---------------------------------------------------------------------------

describe('applyEvent — report projections', () => {
  it('creates a report projection', () => {
    const projections = {};

    applyEvent(projections, makeEvent({
      aggregate_type: 'report',
      aggregate_id: 'rpt_1',
      command_type: 'report.filed',
      payload_json: {
        entity_id: 'ent-1',
        report_type: 'fraudulent_entity',
        description: 'Suspected fake entity.',
      },
    }));

    expect(projections.report['rpt_1'].status).toBe('received');
    expect(projections.report['rpt_1'].report_type).toBe('fraudulent_entity');
  });
});

// ---------------------------------------------------------------------------
// rebuildProjections
// ---------------------------------------------------------------------------

describe('rebuildProjections', () => {
  it('replays a sequence of events and produces expected state', () => {
    const events = [
      makeEvent({
        aggregate_type: 'receipt',
        aggregate_id: 'r_1',
        command_type: 'receipt.submitted',
        payload_json: {
          entity_id: 'ent-1',
          submitted_by: 'ent-2',
          composite_score: 80,
          provenance_tier: 'self_attested',
        },
        created_at: '2026-01-01T00:00:00Z',
      }),
      makeEvent({
        aggregate_type: 'dispute',
        aggregate_id: 'd_1',
        command_type: 'dispute.filed',
        payload_json: {
          receipt_id: 'r_1',
          entity_id: 'ent-1',
          filed_by: 'ent-3',
          filed_by_type: 'third_party',
          reason: 'inaccurate_signals',
        },
        created_at: '2026-01-02T00:00:00Z',
      }),
      makeEvent({
        aggregate_type: 'dispute',
        aggregate_id: 'd_1',
        command_type: 'dispute.resolved',
        payload_json: { resolution: 'reversed' },
        created_at: '2026-01-03T00:00:00Z',
      }),
    ];

    const { projections, replayed, errors } = rebuildProjections(events);
    expect(replayed).toBe(3);
    expect(errors).toHaveLength(0);

    expect(projections.receipt['r_1'].composite_score).toBe(80);
    expect(projections.dispute['d_1'].status).toBe('reversed');
    expect(projections.dispute['d_1'].resolution).toBe('reversed');
  });

  it('filters by aggregate type when specified', () => {
    const events = [
      makeEvent({
        aggregate_type: 'receipt',
        aggregate_id: 'r_1',
        command_type: 'receipt.submitted',
        payload_json: { entity_id: 'ent-1' },
      }),
      makeEvent({
        aggregate_type: 'dispute',
        aggregate_id: 'd_1',
        command_type: 'dispute.filed',
        payload_json: {
          receipt_id: 'r_1',
          entity_id: 'ent-1',
          filed_by: 'ent-2',
          filed_by_type: 'third_party',
          reason: 'other',
        },
      }),
    ];

    const { projections, replayed } = rebuildProjections(events, 'receipt');
    expect(replayed).toBe(1);
    expect(projections.receipt).toBeDefined();
    expect(projections.dispute).toBeUndefined();
  });

  it('captures errors per-event without crashing', () => {
    const badEvent = makeEvent({
      aggregate_type: 'receipt',
      aggregate_id: 'r_bad',
      command_type: 'receipt.submitted',
      payload_json: 'THIS_IS_NOT_VALID_JSON{{{',
    });

    const { errors } = rebuildProjections([badEvent]);
    expect(errors).toHaveLength(1);
    expect(errors[0].event_id).toBe(badEvent.event_id);
  });
});

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

describe('diffProjections', () => {
  it('identifies matching records', () => {
    const state = {
      receipt: {
        r1: { receipt_id: 'r1', entity_id: 'e1', status: 'submitted' },
      },
    };
    const result = diffProjections(state, state);
    expect(result.matching).toHaveLength(1);
    expect(result.drifted).toHaveLength(0);
    expect(result.orphanedInCurrent).toHaveLength(0);
    expect(result.orphanedInReplay).toHaveLength(0);
  });

  it('detects drifted records', () => {
    const replayed = {
      receipt: {
        r1: { receipt_id: 'r1', entity_id: 'e1', graph_weight: 1.0 },
      },
    };
    const current = {
      receipt: {
        r1: { receipt_id: 'r1', entity_id: 'e1', graph_weight: 0.0 },
      },
    };

    const result = diffProjections(replayed, current);
    expect(result.drifted).toHaveLength(1);
    expect(result.drifted[0].aggregate_id).toBe('r1');
    expect(result.drifted[0].diffs[0].field).toBe('graph_weight');
    expect(result.drifted[0].diffs[0].replayed).toBe(1.0);
    expect(result.drifted[0].diffs[0].current).toBe(0.0);
  });

  it('detects orphaned records in current state (not in replay)', () => {
    const replayed = { receipt: {} };
    const current = {
      receipt: {
        r_orphan: { receipt_id: 'r_orphan', entity_id: 'e1' },
      },
    };

    const result = diffProjections(replayed, current);
    expect(result.orphanedInCurrent).toHaveLength(1);
    expect(result.orphanedInCurrent[0].aggregate_id).toBe('r_orphan');
  });

  it('detects orphaned records in replay (not in current state)', () => {
    const replayed = {
      receipt: {
        r_extra: { receipt_id: 'r_extra', entity_id: 'e1' },
      },
    };
    const current = { receipt: {} };

    const result = diffProjections(replayed, current);
    expect(result.orphanedInReplay).toHaveLength(1);
    expect(result.orphanedInReplay[0].aggregate_id).toBe('r_extra');
  });

  it('ignores updated_at differences', () => {
    const replayed = {
      entity: {
        e1: { entity_id: 'e1', status: 'active', updated_at: '2026-01-01T00:00:00Z' },
      },
    };
    const current = {
      entity: {
        e1: { entity_id: 'e1', status: 'active', updated_at: '2026-03-01T00:00:00Z' },
      },
    };

    const result = diffProjections(replayed, current);
    expect(result.matching).toHaveLength(1);
    expect(result.drifted).toHaveLength(0);
  });

  it('handles aggregate types present in only one side', () => {
    const replayed = {
      receipt: { r1: { receipt_id: 'r1' } },
    };
    const current = {
      dispute: { d1: { dispute_id: 'd1' } },
    };

    const result = diffProjections(replayed, current);
    expect(result.orphanedInReplay).toHaveLength(1);
    expect(result.orphanedInCurrent).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Entity + delegation projections
// ---------------------------------------------------------------------------

describe('applyEvent — entity projections', () => {
  it('creates an entity and applies trust recomputation', () => {
    const projections = {};

    applyEvent(projections, makeEvent({
      aggregate_type: 'entity',
      aggregate_id: 'my-agent',
      command_type: 'entity.registered',
      payload_json: {
        display_name: 'My Agent',
        entity_type: 'agent',
        description: 'A test agent.',
      },
    }));

    expect(projections.entity['my-agent'].emilia_score).toBe(50.0);
    expect(projections.entity['my-agent'].status).toBe('active');

    applyEvent(projections, makeEvent({
      aggregate_type: 'entity',
      aggregate_id: 'my-agent',
      command_type: 'trust.recomputed',
      payload_json: { new_score: 78.5 },
    }));

    expect(projections.entity['my-agent'].emilia_score).toBe(78.5);
  });
});

describe('applyEvent — delegation projections', () => {
  it('creates and revokes a delegation', () => {
    const projections = {};

    applyEvent(projections, makeEvent({
      aggregate_type: 'delegation',
      aggregate_id: 'del_1',
      command_type: 'delegation.created',
      payload_json: {
        principal_id: 'user-1',
        agent_entity_id: 'agent-1',
        scope: { actions: ['transact'] },
      },
    }));

    expect(projections.delegation['del_1'].status).toBe('active');

    applyEvent(projections, makeEvent({
      aggregate_type: 'delegation',
      aggregate_id: 'del_1',
      command_type: 'delegation.revoked',
      payload_json: { revoked_at: '2026-02-01T00:00:00Z' },
    }));

    expect(projections.delegation['del_1'].status).toBe('revoked');
  });
});
