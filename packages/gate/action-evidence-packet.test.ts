// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import { buildOutcomeObservationV2 } from '@emilia-protocol/verify/outcome-binding';
import {
  ACTION_EVIDENCE_COMPONENT_ROLES,
  ACTION_EVIDENCE_MANIFEST_VERSION,
  ACTION_EVIDENCE_PACKET_CLAIM_BOUNDARY,
  actionEvidenceArtifactDigest,
  buildActionEvidencePacket,
  verifyActionEvidencePacket,
  type ActionEvidenceComponentRole,
  type ActionEvidenceManifest,
  type ActionEvidenceNativeVerification,
  type ActionEvidencePacket,
} from './action-evidence-packet.js';
import {
  PROVIDER_OUTCOME_CONTEXT_VERSION,
  buildProviderOutcomeBinding,
  providerOutcomeContextDigest,
  providerOutcomeObservationEffects,
  type ProviderOutcomeContext,
} from './provider-outcome-binding.js';

const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');
const D = (character: string) => `sha256:${character.repeat(64)}`;
const CAID = `caid:1:payment.release.1:jcs-sha256:${'C'.repeat(43)}`;
const NOW = '2026-09-04T12:03:00.000Z';
const PROVIDER_ENTRY_AT = '2026-09-04T12:00:00.000Z';
const SOURCES = [{
  role: 'independent_observer' as const,
  source_id: 'source:independent-ledger',
  source_class: 'observer.external',
}, {
  role: 'system_of_record' as const,
  source_id: 'source:provider-ledger',
  source_class: 'provider.system-of-record',
}] as const;
const OUTCOME_REQUIREMENTS = {
  required_sources: SOURCES.map(({ role, source_class }) => ({ role, source_class })),
  quorum: 2,
  observation_window: {
    opens_before_provider_entry_sec: 0,
    closes_after_provider_entry_sec: 180,
    max_observation_age_sec: 180,
  },
  require_control_domain_independence: true as const,
};

const signers = SOURCES.map(() => {
  const ed = crypto.generateKeyPairSync('ed25519');
  const pq = ml_dsa65.keygen(crypto.randomBytes(32));
  return {
    ed,
    edPublic: ed.publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
    pqPublic: Buffer.from(pq.publicKey).toString('base64url'),
    pqSecret: Buffer.from(pq.secretKey).toString('base64url'),
  };
});

const sourceKeys = Object.fromEntries(SOURCES.map((source, index) => [
  source.source_id,
  {
    public_key: signers[index].edPublic,
    pq_public_key: signers[index].pqPublic,
    role: source.role,
    source_class: source.source_class,
    valid_from: '2026-01-01T00:00:00.000Z',
    valid_to: '2027-01-01T00:00:00.000Z',
    status: 'active',
    control_domain_id: index === 0 ? 'domain:independent' : 'domain:provider',
  },
]));

function providerContext(outcome: ProviderOutcomeContext['outcome'] = 'COMMITTED'):
ProviderOutcomeContext {
  return {
    '@version': PROVIDER_OUTCOME_CONTEXT_VERSION,
    tenant_id: 'tenant:alpha',
    admission_id: 'admission:001',
    operation_id: 'operation:001',
    snapshot_digest: D('1'),
    caid: CAID,
    action_digest: D('2'),
    effect_request_digest: D('3'),
    provider: 'provider:stripe',
    account: 'account:merchant',
    environment: 'production',
    adapter_id: 'adapter:stripe:v1',
    idempotency_key: 'idempotency:operation:001',
    outcome,
    observed_at: '2026-09-04T12:01:00.000Z',
  };
}

const DEFAULT_STATES: Record<ActionEvidenceComponentRole, string | null> = {
  aeb: 'SATISFIED',
  admission_snapshot: 'IMMUTABLE',
  admission_decision: 'ALLOW',
  qualification_statement: 'QUALIFIED',
  qualification_status_head: 'CURRENT',
  open_exposure_ceiling: 'ACTIVE',
  open_exposure_record: 'CLOSED_COMMITTED',
  open_exposure_history: 'CLOSED_COMMITTED',
  observed_effect_relation: 'OBSERVED_AS_REQUESTED',
  coverage_surface: 'gated',
  refusal_probe: 'blocked_without_receipt',
  supplied_population_report: 'VERIFIED_SUPPLIED_POPULATION',
  loss_report: null,
  recourse: null,
  loss_allocation: null,
};

async function makeFixture(input: {
  outcome?: ProviderOutcomeContext['outcome'];
  states?: Partial<Record<ActionEvidenceComponentRole, string | null>>;
  scheduleEvaluation?: 'ELIGIBLE' | 'NOT_ELIGIBLE' | 'INDETERMINATE';
  secondObservedUntil?: string;
  observedAt?: string;
  assembledAt?: string;
} = {}) {
  const context = {
    ...providerContext(input.outcome),
    ...(input.observedAt === undefined ? {} : { observed_at: input.observedAt }),
  } as ProviderOutcomeContext;
  const observations = await Promise.all(SOURCES.map((source, index) => (
    buildOutcomeObservationV2({
      receipt_id: `receipt:00${index + 1}`,
      receipt_digest: D(String(index + 4)),
      action_hash: context.action_digest,
      action_caid: context.caid,
      consumption_nonce: `consumption:00${index + 1}`,
      operation_id: context.operation_id,
      source,
      observed_from: index === 0
        ? '2026-09-04T12:00:00.000Z'
        : '2026-09-04T12:00:30.000Z',
      observed_until: index === 0
        ? '2026-09-04T12:01:00.000Z'
        : (input.secondObservedUntil ?? '2026-09-04T12:01:30.000Z'),
      attested_at: index === 0
        ? '2026-09-04T12:02:00.000Z'
        : '2026-09-04T12:02:15.000Z',
      observed_effects: providerOutcomeObservationEffects(context),
      signer: {
        privateKey: signers[index].ed.privateKey,
        pqPrivateKey: signers[index].pqSecret,
        pqPublicKey: signers[index].pqPublic,
      },
    })
  )));
  const providerBindings = observations.map((observation) => buildProviderOutcomeBinding({
    provider_context: context,
    outcome_observation: observation,
  }));
  const schedule = {
    '@version': 'TEST-SIGNED-ACTION-RISK-CONTROL-SCHEDULE-v1',
    schedule_id: 'schedule:001',
    proof: { test_fixture: true },
  };
  const states = { ...DEFAULT_STATES, ...(input.states ?? {}) };
  const artifacts = Object.fromEntries(
    ACTION_EVIDENCE_COMPONENT_ROLES
      .filter((role) => states[role] !== null)
      .map((role) => [role, {
        '@version': `TEST-${role}-v1`,
        artifact_id: `artifact:${role}`,
        native_state: states[role],
      }]),
  ) as Record<ActionEvidenceComponentRole, unknown>;
  const components = Object.fromEntries(
    ACTION_EVIDENCE_COMPONENT_ROLES.map((role) => [
      role,
      states[role] === null ? null : {
        artifact_digest: actionEvidenceArtifactDigest(artifacts[role]),
        expected_state: states[role],
      },
    ]),
  ) as ActionEvidenceManifest['components'];
  const manifest: ActionEvidenceManifest = {
    '@version': ACTION_EVIDENCE_MANIFEST_VERSION,
    packet_id: 'packet:001',
    assembled_at: input.assembledAt ?? '2026-09-04T12:02:30.000Z',
    subject: context,
    subject_digest: providerOutcomeContextDigest(context),
    schedule: {
      artifact_digest: actionEvidenceArtifactDigest(schedule),
      evaluation: input.scheduleEvaluation ?? 'ELIGIBLE',
    },
    components,
    provider_outcomes: SOURCES.map((source, index) => ({
      binding_artifact_digest: actionEvidenceArtifactDigest(providerBindings[index]),
      outcome_observation_artifact_digest: actionEvidenceArtifactDigest(observations[index]),
      expected_source: source,
    })),
    claim_boundary: ACTION_EVIDENCE_PACKET_CLAIM_BOUNDARY,
  };
  const attachments = [
    schedule,
    ...providerBindings,
    ...observations,
    ...ACTION_EVIDENCE_COMPONENT_ROLES
      .filter((role) => states[role] !== null)
      .map((role) => artifacts[role]),
  ];
  const packet = buildActionEvidencePacket({ manifest, attachments });
  return { context, schedule, artifacts, observations, providerBindings, manifest, packet };
}

function componentVerifiers(overrides: Partial<Record<
  ActionEvidenceComponentRole,
  Partial<ActionEvidenceNativeVerification>
>> = {}) {
  return Object.fromEntries(ACTION_EVIDENCE_COMPONENT_ROLES.map((role) => [
    role,
    async (request: {
      artifact: unknown;
      subject_digest: string;
      expected_state: string;
    }) => ({
      verification: 'VERIFIED',
      currentness: 'CURRENT',
      artifact_digest: actionEvidenceArtifactDigest(request.artifact),
      subject_digest: request.subject_digest,
      state: request.expected_state,
      reason: null,
      ...(overrides[role] ?? {}),
    }),
  ]));
}

function options(
  context: ProviderOutcomeContext,
  input: {
    components?: ReturnType<typeof componentVerifiers>;
    schedule?: (request: any) => any;
    source_keys?: Record<string, any>;
    provider_entry_at?: string;
    maximum_observation_age_ms?: number;
  } = {},
) {
  return {
    expected_context: context,
    now: NOW,
    verify_schedule: input.schedule ?? (async (request: any) => ({
      verification: 'VERIFIED',
      currentness: 'CURRENT',
      artifact_digest: actionEvidenceArtifactDigest(request.artifact),
      subject_digest: request.subject_digest,
      evaluation: request.expected_evaluation,
      outcome_requirements: OUTCOME_REQUIREMENTS,
      reason: null,
    })),
    component_verifiers: input.components ?? componentVerifiers(),
    provider_outcome: {
      source_keys: input.source_keys ?? sourceKeys,
      provider_entry_at: input.provider_entry_at ?? PROVIDER_ENTRY_AT,
      maximum_observation_age_ms: input.maximum_observation_age_ms ?? 120_000,
    },
  };
}

test('returns TECHNICALLY_COMPLETE only after every trusted adapter reports an exact current binding', async () => {
  const fixture = await makeFixture();
  const verified = await verifyActionEvidencePacket(
    fixture.packet,
    options(fixture.context),
  );
  assert.equal(verified.result, 'TECHNICALLY_COMPLETE', verified.reasons.join(' | '));
  assert.equal(verified.reasons.length, 0);
  assert.equal(verified.verified_components.length, 12);
  assert.equal(verified.claim_boundary, ACTION_EVIDENCE_PACKET_CLAIM_BOUNDARY);
  assert.notEqual(
    fixture.observations[0].observed_until,
    fixture.observations[1].observed_until,
    'independent sources may use different signed observation intervals',
  );
});

test('the published schema accepts a built packet and preserves the source-cardinality bound', async () => {
  const fixture = await makeFixture();
  const schema = JSON.parse(readFileSync(new URL(
    '../../public/schemas/ep-action-evidence-packet.schema.json',
    import.meta.url,
  ), 'utf8'));
  const validate = new Ajv2020({ allErrors: true, strict: false, validateFormats: false })
    .compile(schema);
  assert.equal(validate(fixture.packet), true, JSON.stringify(validate.errors));
  assert.equal(schema.properties.attachments.maxProperties, 64);
  assert.ok(schema.properties.attachments.maxProperties >= (16 * 2) + 15 + 1);
});

test('missing artifacts and missing native verifiers are INCOMPLETE', async (t) => {
  const fixture = await makeFixture();
  await t.test('missing attachment', async () => {
    const packet = structuredClone(fixture.packet) as ActionEvidencePacket;
    delete (packet.attachments as Record<string, unknown>)[
      fixture.manifest.components.aeb.artifact_digest
    ];
    const verified = await verifyActionEvidencePacket(packet, options(fixture.context));
    assert.equal(verified.result, 'INCOMPLETE');
    assert.ok(verified.incomplete_components.includes('aeb'));
  });
  await t.test('missing verifier', async () => {
    const verifiers = componentVerifiers();
    delete (verifiers as Record<string, unknown>).qualification_status_head;
    const verified = await verifyActionEvidencePacket(
      fixture.packet,
      options(fixture.context, { components: verifiers }),
    );
    assert.equal(verified.result, 'INCOMPLETE');
    assert.ok(verified.incomplete_components.includes('qualification_status_head'));
  });
});

test('manifest, attachment, role, and expected-context substitutions are CONFLICTED', async (t) => {
  const fixture = await makeFixture();
  await t.test('attachment changed under its old key', async () => {
    const packet = structuredClone(fixture.packet) as ActionEvidencePacket;
    const digest = fixture.manifest.components.admission_decision.artifact_digest;
    (packet.attachments as Record<string, unknown>)[digest] = {
      '@version': 'TEST-admission-decision-v1',
      artifact_id: 'artifact:substituted',
      native_state: 'ALLOW',
    };
    const verified = await verifyActionEvidencePacket(packet, options(fixture.context));
    assert.equal(verified.result, 'CONFLICTED');
    assert.ok(verified.reasons.includes('attachment_digest_mismatch'));
  });
  await t.test('subject changed outside the relying party', async () => {
    const changed = { ...fixture.context, tenant_id: 'tenant:other' };
    const verified = await verifyActionEvidencePacket(
      fixture.packet,
      options(changed),
    );
    assert.equal(verified.result, 'CONFLICTED');
    assert.ok(verified.reasons.includes('expected_context_mismatch'));
  });
  await t.test('unreferenced attachment smuggling', async () => {
    const packet = structuredClone(fixture.packet) as ActionEvidencePacket;
    const extra = { '@version': 'TEST-EXTRA-v1', value: 'unreferenced' };
    (packet.attachments as Record<string, unknown>)[actionEvidenceArtifactDigest(extra)] = extra;
    const verified = await verifyActionEvidencePacket(packet, options(fixture.context));
    assert.equal(verified.result, 'CONFLICTED');
    assert.ok(verified.reasons.includes('unreferenced_attachment'));
  });
  await t.test('presenter trust-key injection', async () => {
    const injected = {
      ...structuredClone(fixture.packet),
      source_keys: sourceKeys,
    };
    const verified = await verifyActionEvidencePacket(injected, options(fixture.context));
    assert.equal(verified.result, 'CONFLICTED');
    assert.ok(verified.reasons.includes('packet_structure_invalid'));
  });
});

test('schedule evaluation and normalized native-state conflicts fail closed', async (t) => {
  const fixture = await makeFixture();
  await t.test('schedule evaluation mismatch', async () => {
    const verified = await verifyActionEvidencePacket(
      fixture.packet,
      options(fixture.context, {
        schedule: async (request: any) => ({
          verification: 'VERIFIED',
          currentness: 'CURRENT',
          artifact_digest: actionEvidenceArtifactDigest(request.artifact),
          subject_digest: request.subject_digest,
          evaluation: 'NOT_ELIGIBLE',
          outcome_requirements: OUTCOME_REQUIREMENTS,
          reason: null,
        }),
      }),
    );
    assert.equal(verified.result, 'CONFLICTED');
    assert.ok(verified.reasons.includes('schedule_binding_conflict'));
  });
  await t.test('native adapter reports different action state', async () => {
    const verified = await verifyActionEvidencePacket(
      fixture.packet,
      options(fixture.context, {
        components: componentVerifiers({
          admission_decision: { state: 'REFUSE' },
        }),
      }),
    );
    assert.equal(verified.result, 'CONFLICTED');
    assert.ok(verified.reasons.includes('admission_decision_binding_conflict'));
  });
});

test('uncertain currentness and a coherent indeterminate outcome remain INDETERMINATE', async (t) => {
  const fixture = await makeFixture();
  await t.test('native currentness is indeterminate', async () => {
    const verified = await verifyActionEvidencePacket(
      fixture.packet,
      options(fixture.context, {
        components: componentVerifiers({
          qualification_status_head: { currentness: 'INDETERMINATE' },
        }),
      }),
    );
    assert.equal(verified.result, 'INDETERMINATE');
    assert.ok(verified.indeterminate_components.includes('qualification_status_head'));
  });
  await t.test('provider, OEL, and observed effect remain indeterminate together', async () => {
    const pending = await makeFixture({
      outcome: 'INDETERMINATE',
      states: {
        open_exposure_record: 'INDETERMINATE',
        open_exposure_history: 'INDETERMINATE',
        observed_effect_relation: 'INDETERMINATE',
      },
    });
    const verified = await verifyActionEvidencePacket(
      pending.packet,
      options(pending.context),
    );
    assert.equal(verified.result, 'INDETERMINATE');
    assert.ok(verified.indeterminate_components.includes('provider_outcome'));
  });
});

test('provider/OEL conflict, observed divergence, and a bypassing refusal probe are CONFLICTED', async (t) => {
  await t.test('provider and OEL terminal states conflict', async () => {
    const fixture = await makeFixture({ states: {
      open_exposure_record: 'CLOSED_PROVEN_NOT_COMMITTED',
      open_exposure_history: 'CLOSED_PROVEN_NOT_COMMITTED',
    } });
    const verified = await verifyActionEvidencePacket(fixture.packet, options(fixture.context));
    assert.equal(verified.result, 'CONFLICTED');
    assert.ok(verified.reasons.includes('provider_and_exposure_outcome_conflict'));
  });
  await t.test('observed effect divergence', async () => {
    const fixture = await makeFixture({ states: {
      observed_effect_relation: 'DIVERGED',
    } });
    const verified = await verifyActionEvidencePacket(fixture.packet, options(fixture.context));
    assert.equal(verified.result, 'CONFLICTED');
    assert.ok(verified.reasons.includes('observed_effect_diverged'));
  });
  await t.test('refusal probe observed a bypass', async () => {
    const fixture = await makeFixture({ states: {
      refusal_probe: 'executed_without_receipt',
    } });
    const verified = await verifyActionEvidencePacket(fixture.packet, options(fixture.context));
    assert.equal(verified.result, 'CONFLICTED');
    assert.ok(verified.reasons.includes('refusal_probe_observed_bypass'));
  });
});

test('TECHNICALLY_COMPLETE requires a gated coverage surface', async (t) => {
  await t.test('ungated is CONFLICTED', async () => {
    const fixture = await makeFixture({ states: { coverage_surface: 'ungated' } });
    const verified = await verifyActionEvidencePacket(fixture.packet, options(fixture.context));
    assert.equal(verified.result, 'CONFLICTED');
    assert.ok(verified.reasons.includes('coverage_surface_ungated'));
  });
  await t.test('witness-only is INCOMPLETE', async () => {
    const fixture = await makeFixture({ states: { coverage_surface: 'witness_only' } });
    const verified = await verifyActionEvidencePacket(fixture.packet, options(fixture.context));
    assert.equal(verified.result, 'INCOMPLETE');
    assert.ok(verified.reasons.includes('coverage_surface_witness_only'));
  });
});

test('the verified schedule controls provider observation windows and freshness', async (t) => {
  const scheduleVerifier = (requirements: unknown) => async (request: any) => ({
    verification: 'VERIFIED',
    currentness: 'CURRENT',
    artifact_digest: actionEvidenceArtifactDigest(request.artifact),
    subject_digest: request.subject_digest,
    evaluation: request.expected_evaluation,
    outcome_requirements: requirements,
    reason: null,
  });

  await t.test('a caller cannot widen the signed maximum age', async () => {
    const fixture = await makeFixture();
    const requirements = {
      ...OUTCOME_REQUIREMENTS,
      observation_window: {
        ...OUTCOME_REQUIREMENTS.observation_window,
        max_observation_age_sec: 60,
      },
    };
    const verified = await verifyActionEvidencePacket(
      fixture.packet,
      options(fixture.context, {
        schedule: scheduleVerifier(requirements),
        maximum_observation_age_ms: 600_000,
      }),
    );
    assert.equal(verified.result, 'INCOMPLETE');
    assert.ok(verified.reasons.includes('provider_outcome_outcome_observation_stale'));
  });

  await t.test('a caller may tighten the signed maximum age', async () => {
    const fixture = await makeFixture();
    const verified = await verifyActionEvidencePacket(
      fixture.packet,
      options(fixture.context, { maximum_observation_age_ms: 30_000 }),
    );
    assert.equal(verified.result, 'INCOMPLETE');
    assert.ok(verified.reasons.includes('provider_outcome_outcome_observation_stale'));
  });

  await t.test('the signed opening boundary is enforced around provider entry', async () => {
    const fixture = await makeFixture();
    const verified = await verifyActionEvidencePacket(
      fixture.packet,
      options(fixture.context, { provider_entry_at: fixture.context.observed_at }),
    );
    assert.equal(verified.result, 'CONFLICTED');
    assert.ok(verified.reasons.includes('provider_observation_outside_schedule_window'));
  });

  await t.test('a source interval must contain the shared signed provider event', async () => {
    const fixture = await makeFixture({
      secondObservedUntil: '2026-09-04T12:00:45.000Z',
    });
    const verified = await verifyActionEvidencePacket(
      fixture.packet,
      options(fixture.context, { maximum_observation_age_ms: 180_000 }),
    );
    assert.equal(verified.result, 'CONFLICTED');
    assert.ok(verified.reasons.includes('provider_observation_outside_schedule_window'));
  });

  await t.test('future shared event and assembly chronology are refused', async () => {
    const fixture = await makeFixture({
      observedAt: '2026-09-04T12:04:00.000Z',
      assembledAt: '2026-09-04T12:04:30.000Z',
    });
    const verified = await verifyActionEvidencePacket(fixture.packet, options(fixture.context));
    assert.equal(verified.result, 'CONFLICTED');
    assert.ok(verified.reasons.includes('provider_event_outside_schedule_window'));
    assert.ok(verified.reasons.includes('packet_assembled_after_verification_time'));
  });

  await t.test('a schedule result without its signed window is invalid', async () => {
    const fixture = await makeFixture();
    const malformed = structuredClone(OUTCOME_REQUIREMENTS) as Record<string, unknown>;
    delete malformed.observation_window;
    const verified = await verifyActionEvidencePacket(
      fixture.packet,
      options(fixture.context, { schedule: scheduleVerifier(malformed) }),
    );
    assert.equal(verified.result, 'INCOMPLETE');
    assert.ok(verified.reasons.includes('schedule_verification_result_invalid'));
  });
});

test('packet chronology is internally consistent without treating assembled_at as authenticated freshness', async (t) => {
  const fixture = await makeFixture();
  await t.test('provider event cannot occur after assembly', () => {
    const manifest = {
      ...structuredClone(fixture.manifest),
      assembled_at: '2026-09-04T12:00:30.000Z',
    };
    assert.throws(
      () => buildActionEvidencePacket({
        manifest: manifest as ActionEvidenceManifest,
        attachments: Object.values(fixture.packet.attachments),
      }),
      /manifest is invalid/,
    );
  });
  await t.test('source attestation cannot occur after assembly', async () => {
    const manifest = {
      ...structuredClone(fixture.manifest),
      assembled_at: '2026-09-04T12:02:05.000Z',
    } as ActionEvidenceManifest;
    const packet = buildActionEvidencePacket({
      manifest,
      attachments: Object.values(fixture.packet.attachments),
    });
    const verified = await verifyActionEvidencePacket(packet, options(fixture.context));
    assert.equal(verified.result, 'CONFLICTED');
    assert.ok(verified.reasons.includes('provider_observation_attested_after_assembly'));
  });
});

test('optional loss, recourse, and loss-allocation artifacts are verified when present', async () => {
  const fixture = await makeFixture({ states: {
    loss_report: 'LOSS_REPORTED',
    recourse: 'AVAILABLE',
    loss_allocation: 'VERIFIED',
  } });
  const verified = await verifyActionEvidencePacket(fixture.packet, options(fixture.context));
  assert.equal(verified.result, 'TECHNICALLY_COMPLETE', verified.reasons.join(' | '));
  assert.ok(verified.verified_components.includes('loss_report'));
  assert.ok(verified.verified_components.includes('recourse'));
  assert.ok(verified.verified_components.includes('loss_allocation'));
});

test('TECHNICALLY_COMPLETE requires the schedule quorum and independent control domains', async (t) => {
  const fixture = await makeFixture();
  await t.test('one missing pinned source cannot satisfy two-of-two', async () => {
    const oneSource = {
      [SOURCES[0].source_id]: sourceKeys[SOURCES[0].source_id],
    };
    const verified = await verifyActionEvidencePacket(
      fixture.packet,
      options(fixture.context, { source_keys: oneSource }),
    );
    assert.equal(verified.result, 'INCOMPLETE');
    assert.ok(verified.reasons.includes('provider_outcome_quorum_not_met'));
  });
  await t.test('two verified sources in one control domain are not independent', async () => {
    const sameDomain = structuredClone(sourceKeys);
    sameDomain[SOURCES[1].source_id].control_domain_id =
      sameDomain[SOURCES[0].source_id].control_domain_id;
    const verified = await verifyActionEvidencePacket(
      fixture.packet,
      options(fixture.context, { source_keys: sameDomain }),
    );
    assert.equal(verified.result, 'INCOMPLETE');
    assert.ok(verified.reasons.includes('provider_control_domain_independence_not_met'));
  });
  await t.test('a schedule quorum larger than the verified source set is not met', async () => {
    const threeOfThree = {
      required_sources: [
        { role: 'executor' as const, source_class: 'executor.adapter' },
        ...OUTCOME_REQUIREMENTS.required_sources,
      ],
      quorum: 3,
      observation_window: OUTCOME_REQUIREMENTS.observation_window,
      require_control_domain_independence: true as const,
    };
    const verified = await verifyActionEvidencePacket(
      fixture.packet,
      options(fixture.context, {
        schedule: async (request: any) => ({
          verification: 'VERIFIED',
          currentness: 'CURRENT',
          artifact_digest: actionEvidenceArtifactDigest(request.artifact),
          subject_digest: request.subject_digest,
          evaluation: request.expected_evaluation,
          outcome_requirements: threeOfThree,
          reason: null,
        }),
      }),
    );
    assert.equal(verified.result, 'INCOMPLETE');
    assert.ok(verified.reasons.includes('provider_outcome_quorum_not_met'));
  });
});
