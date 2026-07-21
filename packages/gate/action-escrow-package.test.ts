// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  ACTION_ESCROW_PROFILE_VERSION,
  computeActionEscrowReleaseBindingMomentDigest,
  computeActionEscrowResolutionNonce,
  createActionEscrowKernel,
} from './action-escrow.js';
import {
  assembleActionEscrowEvidencePackage,
  buildActionEscrowEvidencePackageFromKernel,
} from './action-escrow-package.js';
import { signActionEscrowStateStatement } from './action-escrow-state.js';
import { computeActionEscrowAgreementDigest } from './action-escrow-verifiers.js';
import { hashCanonical } from './execution-binding.js';
import {
  computeDocumentActionBindingDigest,
  computeReleaseActionDigest,
  signDocumentActionBinding,
} from '../verify/document-action-binding.js';

const NOW = '2026-07-17T12:00:00.000Z';
const PDF = Buffer.from(
  '%PDF-1.7\n% Action Escrow final agreement\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n',
  'utf8',
);
const AGREEMENT_ID = 'agreement:package-assembler-001';
const MILESTONE_ID = 'milestone:cabinet-installation';
const PARTIES = Object.freeze([
  Object.freeze({ party_id: 'party:contractor', role: 'contractor' }),
  Object.freeze({ party_id: 'party:homeowner', role: 'homeowner' }),
]);

const canonicalDigest = (value) => `sha256:${hashCanonical(value)}`;
const partySuffix = (partyId) => partyId.split(':').at(-1);

function durableStore() {
  const values = new Map();
  return {
    durable: true,
    atomicExpectedRevisionCas: true,
    linearizableReads: true,
    monotonicRevisions: true,
    nonExpiring: true,
    async read(key) {
      const entry = values.get(key);
      return entry ? { ...entry } : null;
    },
    async compareAndSwap(key, expectedRevision, value) {
      const current = values.get(key);
      if ((current?.revision ?? null) !== expectedRevision) {
        return { applied: false, revision: current?.revision ?? null };
      }
      const revision = expectedRevision === null ? 0 : expectedRevision + 1;
      values.set(key, { revision, value });
      return { applied: true, revision };
    },
  };
}

function materialTerms(amount) {
  return [
    { term_id: 'amendment_version', type: 'integer', value: 1 },
    {
      term_id: 'completion_requirements_digest',
      type: 'digest',
      value: canonicalDigest({ requirement: 'installed cabinets' }),
    },
    {
      term_id: 'document_authorizes_payment',
      type: 'boolean',
      value: false,
    },
    {
      term_id: 'milestone_name',
      type: 'string',
      value: 'Cabinet installation',
    },
    {
      term_id: 'payee_id',
      type: 'identifier',
      value: 'payee:contractor',
    },
    {
      term_id: 'release.amount',
      type: 'amount',
      value: amount,
      currency: 'USD',
    },
    {
      term_id: 'release.destination_id',
      type: 'identifier',
      value: 'destination:contractor-operating',
    },
    {
      term_id: 'release.milestone_id',
      type: 'identifier',
      value: MILESTONE_ID,
    },
    {
      term_id: 'release_requires_mutual_approval',
      type: 'boolean',
      value: true,
    },
    {
      term_id: 'retainage_amount',
      type: 'amount',
      value: '0.00',
      currency: 'USD',
    },
  ];
}

function releaseTemplate(
  profileDigest,
  agreementDigest,
  terms,
  amount = '18400.00',
) {
  return {
    action_type: 'escrow.milestone.release',
    action_escrow_profile_digest: profileDigest,
    agreement_id: AGREEMENT_ID,
    agreement_digest: agreementDigest,
    milestone_id: MILESTONE_ID,
    amount,
    currency: 'USD',
    destination_id: 'destination:contractor-operating',
    payee_id: 'payee:contractor',
    custodian_provider: 'custodian.test',
    custodian_environment: 'sandbox',
    custodian_transaction_id: 'transaction:package-assembler-001',
    custodian_milestone_id: 'provider-milestone:cabinets',
    document_sha256: `sha256:${crypto.createHash('sha256').update(PDF).digest('hex')}`,
    material_terms_sha256: canonicalDigest(terms),
    completion_evidence_sha256: canonicalDigest({
      evidence: 'cabinet-installation',
    }),
    amendment_version: 1,
  };
}

function signedBinding({
  issuerKey,
  profileDigest,
  agreementDigest,
  bindingId = 'binding:package-assembler:v1',
  amount = '18400.00',
  supersedesDigest,
} = {}) {
  const terms = materialTerms(amount);
  const template = releaseTemplate(profileDigest, agreementDigest, terms, amount);
  return signDocumentActionBinding({
    binding_id: bindingId,
    agreement_id: AGREEMENT_ID,
    document: {
      bytes: PDF,
      media_type: 'application/pdf',
    },
    material_terms: terms,
    release_action_template: template,
    parties: PARTIES,
    required_parties: PARTIES,
    validity: {
      not_before: '2026-07-01T00:00:00.000Z',
      not_after: '2027-07-01T00:00:00.000Z',
    },
    ...(supersedesDigest === undefined ? {} : { supersedes_digest: supersedesDigest }),
  }, {
    issuer_id: 'issuer:package-assembler',
    key_id: 'key:issuer:package-assembler',
    privateKey: issuerKey.privateKey,
  });
}

function acceptanceArtifact(partyId, bindingDigest) {
  return {
    kind: 'agreement_acceptance',
    party_id: partyId,
    principal_key_id: `key:${partyId}:${bindingDigest.slice(-8)}`,
    binding_digest: bindingDigest,
    accepts_agreement: true,
    authorizes_action: false,
  };
}

function milestoneArtifact(bindingDigest) {
  return {
    kind: 'milestone_evidence',
    binding_digest: bindingDigest,
    evidence_digest: canonicalDigest({ evidence: 'cabinet-installation' }),
    submitter_party_id: 'party:contractor',
    observed_at: '2026-07-17T11:55:00.000Z',
  };
}

function resolutionArtifact(party, bindingInput) {
  return {
    profile: 'EP-RESOLUTION-v1',
    signoff: {
      context: {
        principal: party.party_id,
        principal_key_id: `release-key:${party.party_id}`,
        initiator: 'party:contractor',
        envelope_hash: computeActionEscrowReleaseBindingMomentDigest(bindingInput),
        action_hash: bindingInput.release_action_digest,
        nonce: computeActionEscrowResolutionNonce(bindingInput, party.party_id),
        issued_at: '2026-07-17T11:56:00.000Z',
        expires_at: '2026-07-17T12:30:00.000Z',
        resolution: {
          outcome: 'approved',
          selected_option: 0,
        },
      },
    },
  };
}

function fundingArtifact() {
  return {
    kind: 'custodian_funding_statement',
    provider_id: 'custodian.test',
    statement_type: 'funding',
    status: 'funded',
  };
}

function releaseStatement(request, status = 'released') {
  return {
    kind: 'custodian_release_statement',
    provider_id: request.provider_id,
    provider_idempotency_key: request.idempotency_key,
    provider_request_digest: request.request_digest,
    statement_type: 'release',
    status,
  };
}

function commandArtifact(command, partyId) {
  return {
    kind: 'state_command_authorization',
    command,
    party_id: partyId,
  };
}

function verifierCore(expected) {
  return {
    agreement_digest: expected.agreement_digest,
    document_action_binding_digest: expected.document_action_binding_digest,
    milestone_id: expected.milestone_id,
    release_action_digest: expected.release_action_digest,
    parties_digest: expected.parties_digest,
    profile_digest: expected.profile_digest,
  };
}

function harness() {
  const issuerKey = crypto.generateKeyPairSync('ed25519');
  const operatorKey = crypto.generateKeyPairSync('ed25519');
  const profile = {
    '@version': ACTION_ESCROW_PROFILE_VERSION,
    profile_id: 'profile:package-assembler',
    provider_id: 'custodian.test',
    required_acceptance_party_ids: PARTIES.map((party) => party.party_id),
    required_release_approver_party_ids: PARTIES.map((party) => party.party_id),
    prohibit_self_approval: false,
  };
  const profileDigest = canonicalDigest(profile);
  const agreementDigest = computeActionEscrowAgreementDigest(AGREEMENT_ID);
  const binding = signedBinding({
    issuerKey,
    profileDigest,
    agreementDigest,
  });
  const bindingDigest = computeDocumentActionBindingDigest(binding);
  const actionDigest = computeReleaseActionDigest(binding.release_action.template);
  const resolutionBindingInput = (evidenceDigest) => ({
    agreement_digest: agreementDigest,
    document_action_binding_digest: bindingDigest,
    milestone_id: MILESTONE_ID,
    release_action_digest: actionDigest,
    profile_digest: profileDigest,
    evidence_digest: evidenceDigest,
    release_action_template: binding.release_action.template,
  });
  let authoritativeRequest = null;

  const provider = {
    async release(request) {
      authoritativeRequest = request;
      return {
        authenticated: true,
        statement: releaseStatement(request),
      };
    },
    async getRelease(request) {
      authoritativeRequest = request;
      return {
        authenticated: true,
        statement: releaseStatement(request),
      };
    },
  };
  const kernel = createActionEscrowKernel({
    store: durableStore(),
    provider,
    profilesById: { [profile.profile_id]: profile },
    now: () => NOW,
    async verifyDocumentActionBinding(artifact, expected) {
      const computedBinding = computeDocumentActionBindingDigest(artifact);
      const computedAction = computeReleaseActionDigest(artifact?.release_action?.template);
      return {
        valid: computedBinding === expected.document_action_binding_digest
          && computedAction === expected.release_action_digest,
        verification_digest: computedBinding,
        document_digest: artifact?.document?.digest,
        agreement_id: artifact?.agreement_id,
        binding_id: artifact?.binding_id,
        release_action_template: artifact?.release_action?.template,
        ...verifierCore(expected),
        document_action_binding_digest: computedBinding,
        release_action_digest: computedAction,
        ...(artifact?.supersedes_digest === undefined
          ? {}
          : {
            supersedes_document_action_binding_digest:
              artifact.supersedes_digest,
          }),
      };
    },
    async verifyAgreementAcceptance(artifact, expected) {
      return {
        valid: artifact?.kind === 'agreement_acceptance'
          && artifact.binding_digest === expected.document_action_binding_digest,
        acceptance_digest: canonicalDigest(artifact),
        party_id: artifact?.party_id,
        principal_key_id: artifact?.principal_key_id,
        ...verifierCore(expected),
      };
    },
    async verifyMilestoneEvidence(artifact, expected) {
      return {
        valid: artifact?.kind === 'milestone_evidence',
        evidence_digest: artifact?.evidence_digest,
        submitter_party_id: artifact?.submitter_party_id,
        observed_at: artifact?.observed_at,
        ...verifierCore(expected),
      };
    },
    async verifyResolutionReceipt(artifact, expected) {
      const context = artifact?.signoff?.context;
      const party = PARTIES.find((entry) => entry.party_id === context?.principal);
      return {
        valid: artifact?.profile === 'EP-RESOLUTION-v1'
          && context?.envelope_hash === expected.binding_moment_digest
          && context?.initiator === expected.expected_initiator
          && context?.nonce === expected.expected_nonce
          && context?.resolution?.selected_option === expected.expected_selected_option
          && expected.evaluation_time === NOW,
        authorizes_action: context?.resolution?.outcome === 'approved'
          && context?.envelope_hash === expected.binding_moment_digest,
        outcome: context?.resolution?.outcome,
        party_id: context?.principal,
        party_role: party?.role,
        principal_key_id: context?.principal_key_id,
        nonce: context?.nonce,
        issued_at: context?.issued_at,
        expires_at: context?.expires_at,
        evidence_digest: expected.evidence_digest,
        ...verifierCore(expected),
      };
    },
    async verifyProviderStatement(statement, expected) {
      return {
        valid: statement?.kind?.startsWith('custodian_') === true,
        authenticated: true,
        statement_type: statement?.statement_type,
        status: statement?.status,
        statement_digest: canonicalDigest(statement),
        provider_id: expected.provider_id,
        provider_transaction_id: expected.provider_transaction_id,
        provider_milestone_id: expected.provider_milestone_id,
        amount: expected.amount,
        currency: expected.currency,
        destination_id: expected.destination_id,
        ...verifierCore(expected),
        ...(expected.provider_idempotency_key === undefined
          ? {}
          : { provider_idempotency_key: expected.provider_idempotency_key }),
        ...(expected.provider_request_digest === undefined
          ? {}
          : { provider_request_digest: expected.provider_request_digest }),
      };
    },
    async verifyStateCommand(artifact, expected) {
      return {
        valid: artifact?.kind === 'state_command_authorization'
          && artifact.command === expected.command
          && artifact.party_id === expected.party_id,
        authorizes_command: true,
        command: artifact?.command,
        party_id: artifact?.party_id,
        details_digest: expected.details_digest,
        command_digest: expected.command_digest,
        ...verifierCore(expected),
      };
    },
  });

  const bindingsFor = (selectedBinding = binding) => ({
    agreement_digest: agreementDigest,
    document_action_binding_digest:
      computeDocumentActionBindingDigest(selectedBinding),
    milestone_id: MILESTONE_ID,
    release_action_digest:
      computeReleaseActionDigest(selectedBinding.release_action.template),
    parties: PARTIES,
    profile,
  });
  const inputFor = (idempotencyKey, overrides = {}, selectedBinding = binding) => ({
    ...bindingsFor(selectedBinding),
    idempotency_key: idempotencyKey,
    ...overrides,
  });

  function documentExecutionFor(record) {
    return {
      provider: 'document-execution.test',
      mode: 'provider-neutral-test',
      agreement_id: AGREEMENT_ID,
      binding_digest: record.document_action_binding_digest,
      document_digest: record.document_action_binding.verification.document_digest,
      authorizes_action: false,
      state: 'executed',
      evidence: {
        agreement_status: 'SIGNED',
      },
    };
  }

  function stateStatementFor(record) {
    return signActionEscrowStateStatement({
      statementId: `statement:${record.state}:${record.revision}`,
      agreementId: AGREEMENT_ID,
      bindingDigest: record.document_action_binding_digest,
      actionDigest: record.release_action_digest,
      profileDigest: record.profile_digest,
      state: record.state,
      revision: record.revision,
      amendmentDigests: record.superseded_bindings.map(canonicalDigest),
      stateRecord: record,
      previousStatementDigest: null,
      occurredAt: NOW,
    }, {
      operatorId: 'operator:package-assembler',
      keyId: 'key:operator:package-assembler',
      privateKey: operatorKey.privateKey,
    });
  }

  function assemblyInput(record, overrides = {}) {
    return {
      kernelRecord: record,
      finalPdfBytes: PDF,
      documentFileName: 'cabinet-installation-agreement.pdf',
      documentExecution: [
        'draft',
        'awaiting_acceptance',
        'cancelled',
      ].includes(record.state)
        ? null
        : documentExecutionFor(record),
      operatorStateStatement: stateStatementFor(record),
      verificationProfile: {
        id: profile.profile_id,
        digest: profileDigest,
      },
      ...overrides,
    };
  }

  return {
    actionDigest,
    agreementDigest,
    assemblyInput,
    binding,
    bindingDigest,
    bindingsFor,
    inputFor,
    issuerKey,
    kernel,
    profile,
    profileDigest,
    resolutionBindingInput,
    stateStatementFor,
    get authoritativeRequest() {
      return authoritativeRequest;
    },
  };
}

async function lifecycle(fixture) {
  const records = [];
  let result = await fixture.kernel.create(fixture.inputFor('create', {
    document_action_binding: fixture.binding,
  }));
  assert.equal(result.ok, true, result.code);
  records.push(result.record);

  result = await fixture.kernel.beginAcceptance(
    fixture.inputFor('begin-acceptance'),
  );
  assert.equal(result.state, 'awaiting_acceptance');

  result = await fixture.kernel.acceptAgreement(fixture.inputFor('accept-contractor', {
    party_id: 'party:contractor',
    agreement_acceptance: acceptanceArtifact(
      'party:contractor',
      fixture.bindingDigest,
    ),
  }));
  records.push(result.record);

  result = await fixture.kernel.acceptAgreement(fixture.inputFor('accept-homeowner', {
    party_id: 'party:homeowner',
    agreement_acceptance: acceptanceArtifact(
      'party:homeowner',
      fixture.bindingDigest,
    ),
  }));
  records.push(result.record);

  result = await fixture.kernel.requestFunding(fixture.inputFor('request-funding'));
  records.push(result.record);

  result = await fixture.kernel.recordFunding(fixture.inputFor('record-funding', {
    provider_statement: fundingArtifact(),
  }));
  assert.equal(result.ok, true, result.code);
  assert.equal(result.state, 'funded', result.code);
  records.push(result.record);

  const evidence = milestoneArtifact(fixture.bindingDigest);
  result = await fixture.kernel.submitMilestone(fixture.inputFor('submit-milestone', {
    milestone_evidence: evidence,
  }));
  assert.equal(result.ok, true, result.code);
  assert.equal(result.state, 'milestone_submitted', result.code);
  records.push(result.record);

  for (const party of PARTIES) {
    result = await fixture.kernel.approveRelease(fixture.inputFor(
      `approve-${partySuffix(party.party_id)}`,
      {
        party_id: party.party_id,
        resolution: resolutionArtifact(
          party,
          fixture.resolutionBindingInput(evidence.evidence_digest),
        ),
      },
    ));
    assert.equal(result.ok, true, result.code);
  }
  records.push(result.record);

  result = await fixture.kernel.release(fixture.inputFor('release'));
  assert.equal(result.ok, true, result.code);
  records.push(result.record);

  result = await fixture.kernel.complete(fixture.inputFor('complete', {
    party_id: 'party:homeowner',
    command_authorization: commandArtifact('complete', 'party:homeowner'),
  }));
  assert.equal(result.ok, true, result.code);
  records.push(result.record);

  return { records, released: records.at(-2), completed: records.at(-1) };
}

test('assembles lifecycle snapshots mechanically into the shipped evidence package', async () => {
  const fixture = harness();
  const { records } = await lifecycle(fixture);
  assert.deepEqual(records.map((record) => record.state), [
    'draft',
    'awaiting_acceptance',
    'effective',
    'awaiting_funding',
    'funded',
    'milestone_submitted',
    'milestone_submitted',
    'released',
    'completed',
  ]);

  for (const record of records) {
    const pkg = assembleActionEscrowEvidencePackage(
      fixture.assemblyInput(record),
      { now: NOW },
    );
    assert.equal(pkg.version, 'EP-ACTION-ESCROW-EVIDENCE-PACKAGE-v1');
    assert.equal(pkg.stage, record.state);
    assert.equal(pkg.agreement_id, AGREEMENT_ID);
    assert.equal(pkg.binding.binding_digest, record.document_action_binding_digest);
    assert.equal(pkg.document.file_name, 'cabinet-installation-agreement.pdf');
    assert.deepEqual(pkg.state_record.snapshot, record);
    assert.deepEqual(pkg.agreement_acceptances, record.agreement_acceptances.map((entry) => ({
      party_id: entry.party_id,
      role: PARTIES.find((party) => party.party_id === entry.party_id).role,
      evidence: entry.artifact,
    })));
    assert.equal(pkg.document_execution === null, [
      'draft',
      'awaiting_acceptance',
    ].includes(record.state));
  }

  const released = records.at(-2);
  const releasedPackage = buildActionEscrowEvidencePackageFromKernel(
    fixture.assemblyInput(released),
    { now: NOW },
  );
  const releaseOperation = released.operations.find(
    (entry) => entry.operation === 'release',
  );
  assert.deepEqual(
    releasedPackage.release.reservation,
    {
      release_key: released.release.release_key,
      provider_idempotency_key: released.release.provider_idempotency_key,
      reserved_at: released.release.reserved_at,
    },
  );
  assert.deepEqual(
    releasedPackage.release.provider_request,
    released.release.provider_request,
  );
  assert.deepEqual(
    releasedPackage.release.provider_statement,
    released.release.provider_statement,
  );
  assert.deepEqual(releasedPackage.release.execution_record, releaseOperation);
  assert.equal(Object.hasOwn(releasedPackage.release, 'provider_verification'), false);
});

test('derives pending and effective amendment evidence from the kernel chain', async () => {
  const fixture = harness();
  await fixture.kernel.create(fixture.inputFor('create', {
    document_action_binding: fixture.binding,
  }));
  await fixture.kernel.beginAcceptance(fixture.inputFor('begin'));
  for (const party of PARTIES) {
    await fixture.kernel.acceptAgreement(fixture.inputFor(
      `accept-${partySuffix(party.party_id)}`,
      {
        party_id: party.party_id,
        agreement_acceptance: acceptanceArtifact(
          party.party_id,
          fixture.bindingDigest,
        ),
      },
    ));
  }

  const amendedBinding = signedBinding({
    issuerKey: fixture.issuerKey,
    profileDigest: fixture.profileDigest,
    agreementDigest: fixture.agreementDigest,
    bindingId: 'binding:package-assembler:v2',
    amount: '19200.00',
    supersedesDigest: fixture.bindingDigest,
  });
  const amendedBindingDigest = computeDocumentActionBindingDigest(amendedBinding);
  const amendedActionDigest = computeReleaseActionDigest(
    amendedBinding.release_action.template,
  );
  let result = await fixture.kernel.proposeAmendment(fixture.inputFor(
    'propose-amendment',
    {
      party_id: 'party:homeowner',
      command_authorization: commandArtifact(
        'propose_amendment',
        'party:homeowner',
      ),
      next_document_action_binding_digest: amendedBindingDigest,
      next_release_action_digest: amendedActionDigest,
      next_document_action_binding: amendedBinding,
    },
  ));
  assert.equal(result.state, 'amendment_pending');
  const pendingPackage = assembleActionEscrowEvidencePackage(
    fixture.assemblyInput(result.record),
    { now: NOW },
  );
  assert.equal(pendingPackage.stage, 'amendment_pending');
  assert.deepEqual(pendingPackage.amendments, []);
  assert.deepEqual(
    pendingPackage.state_record.snapshot.pending_amendment.document_action_binding.artifact,
    amendedBinding,
  );

  const amendedInput = (id, party) => fixture.inputFor(id, {
    party_id: party.party_id,
    agreement_acceptance: acceptanceArtifact(
      party.party_id,
      amendedBindingDigest,
    ),
  }, amendedBinding);
  result = await fixture.kernel.acceptAmendment(
    amendedInput('amend-contractor', PARTIES[0]),
  );
  assert.equal(result.state, 'amendment_pending');
  result = await fixture.kernel.acceptAmendment(
    amendedInput('amend-homeowner', PARTIES[1]),
  );
  assert.equal(result.state, 'effective');

  const pkg = assembleActionEscrowEvidencePackage(
    fixture.assemblyInput(result.record),
    { now: NOW },
  );
  assert.equal(pkg.binding.binding_digest, amendedBindingDigest);
  assert.deepEqual(pkg.amendments, result.record.superseded_bindings);
  assert.deepEqual(
    pkg.state_record.statement.payload.amendment_digests,
    result.record.superseded_bindings.map(canonicalDigest),
  );
});

test('refuses malformed stages, missing artifacts, overrides, and state mismatch', async (t) => {
  const fixture = harness();
  const { records, released } = await lifecycle(fixture);
  const funded = records.find((record) => record.state === 'funded');
  const milestone = records.find((record) => (
    record.state === 'milestone_submitted'
      && record.release_approvals.length === 0
  ));

  await t.test('stage substitution', () => {
    const record = structuredClone(funded);
    record.state = 'released';
    assert.throws(
      () => assembleActionEscrowEvidencePackage(
        fixture.assemblyInput(record, {
          operatorStateStatement: fixture.stateStatementFor(record),
        }),
        { now: NOW },
      ),
      /state does not match its history/,
    );
  });

  await t.test('missing required artifact', () => {
    const record = structuredClone(released);
    record.funding = null;
    assert.throws(
      () => assembleActionEscrowEvidencePackage(
        fixture.assemblyInput(record, {
          operatorStateStatement: fixture.stateStatementFor(record),
        }),
        { now: NOW },
      ),
      /required funding statement is missing/,
    );
  });

  await t.test('caller override', () => {
    assert.throws(
      () => assembleActionEscrowEvidencePackage({
        ...fixture.assemblyInput(released),
        stage: 'draft',
      }, { now: NOW }),
      /caller overrides are not accepted/,
    );
  });

  await t.test('operator statement from another revision', () => {
    assert.throws(
      () => assembleActionEscrowEvidencePackage({
        ...fixture.assemblyInput(released),
        operatorStateStatement: fixture.stateStatementFor(milestone),
      }, { now: NOW }),
      /operator state statement mismatch/,
    );
  });
});

test('hostile artifact and provider substitutions fail before package construction', async (t) => {
  const fixture = harness();
  const { released } = await lifecycle(fixture);

  await t.test('final PDF substitution', () => {
    const changedPdf = Buffer.from(
      '%PDF-1.7\n% changed payment destination\n%%EOF\n',
      'utf8',
    );
    assert.throws(
      () => assembleActionEscrowEvidencePackage({
        ...fixture.assemblyInput(released),
        finalPdfBytes: changedPdf,
      }, { now: NOW }),
      /final PDF does not match/,
    );
  });

  await t.test('binding substitution', () => {
    const record = structuredClone(released);
    const other = signedBinding({
      issuerKey: fixture.issuerKey,
      profileDigest: fixture.profileDigest,
      agreementDigest: fixture.agreementDigest,
      bindingId: 'binding:attacker',
      amount: '1.00',
    });
    record.document_action_binding.artifact = other;
    assert.throws(
      () => assembleActionEscrowEvidencePackage(
        fixture.assemblyInput(record, {
          operatorStateStatement: fixture.stateStatementFor(record),
        }),
        { now: NOW },
      ),
      /document-action binding is inconsistent/,
    );
  });

  await t.test('agreement acceptance substitution', () => {
    const record = structuredClone(released);
    record.agreement_acceptances[0].artifact.party_id = 'party:attacker';
    assert.throws(
      () => assembleActionEscrowEvidencePackage(
        fixture.assemblyInput(record, {
          operatorStateStatement: fixture.stateStatementFor(record),
        }),
        { now: NOW },
      ),
      /agreement acceptance is malformed or inconsistent/,
    );
  });

  await t.test('release statement substitution', () => {
    const record = structuredClone(released);
    record.release.provider_statement.status = 'not_released';
    assert.throws(
      () => assembleActionEscrowEvidencePackage(
        fixture.assemblyInput(record, {
          operatorStateStatement: fixture.stateStatementFor(record),
        }),
        { now: NOW },
      ),
      /provider release statement is malformed or inconsistent/,
    );
  });

  await t.test('party role substitution', () => {
    const record = structuredClone(released);
    record.parties[0].role = 'homeowner';
    assert.throws(
      () => assembleActionEscrowEvidencePackage(
        fixture.assemblyInput(record, {
          operatorStateStatement: fixture.stateStatementFor(record),
        }),
        { now: NOW },
      ),
      /parties digest mismatch/,
    );
  });

  await t.test('verification profile substitution', () => {
    assert.throws(
      () => assembleActionEscrowEvidencePackage({
        ...fixture.assemblyInput(released),
        verificationProfile: {
          id: fixture.profile.profile_id,
          digest: `sha256:${'00'.repeat(32)}`,
        },
      }, { now: NOW }),
      /verification-profile reference mismatch/,
    );
  });

  await t.test('provider credential leakage', () => {
    assert.throws(
      () => assembleActionEscrowEvidencePackage({
        ...fixture.assemblyInput(released),
        documentExecution: {
          ...fixture.assemblyInput(released).documentExecution,
          access_token: 'provider-secret',
        },
      }, { now: NOW }),
      /provider credentials or secrets/,
    );
    const record = structuredClone(released);
    record.release.provider_request.api_key = 'provider-secret';
    assert.throws(
      () => assembleActionEscrowEvidencePackage(
        fixture.assemblyInput(record, {
          operatorStateStatement: fixture.stateStatementFor(record),
        }),
        { now: NOW },
      ),
      /provider credentials or secrets/,
    );
    for (const field of ['api_token', 'session_token']) {
      const secretRecord = structuredClone(released);
      secretRecord.release.provider_request[field] = 'provider-secret';
      assert.throws(
        () => assembleActionEscrowEvidencePackage(
          fixture.assemblyInput(secretRecord, {
            operatorStateStatement: fixture.stateStatementFor(secretRecord),
          }),
          { now: NOW },
        ),
        /provider credentials or secrets/,
      );
    }
  });
});

test('assembler refuses pruned operation history and regressing timestamps', async (t) => {
  const fixture = harness();
  const { released } = await lifecycle(fixture);

  await t.test('pruned operation', () => {
    const record = structuredClone(released);
    record.operations.splice(2, 1);
    assert.throws(
      () => assembleActionEscrowEvidencePackage(
        fixture.assemblyInput(record, {
          operatorStateStatement: fixture.stateStatementFor(record),
        }),
        { now: NOW },
      ),
      /revision does not match its complete operation history/,
    );
  });

  await t.test('compensated approval-operation pruning', () => {
    const record = structuredClone(released);
    const approvalIndex = record.operations.findIndex(
      (operation) => operation.operation === 'approve_release',
    );
    record.operations.splice(approvalIndex, 1);
    record.revision -= 1;
    assert.throws(
      () => assembleActionEscrowEvidencePackage(
        fixture.assemblyInput(record, {
          operatorStateStatement: fixture.stateStatementFor(record),
        }),
        { now: NOW },
      ),
      /approve_release operation coverage does not match its artifacts/,
    );
  });

  await t.test('operation time regression', () => {
    const record = structuredClone(released);
    record.operations[2].at = '2026-07-17T11:59:59.000Z';
    assert.throws(
      () => assembleActionEscrowEvidencePackage(
        fixture.assemblyInput(record, {
          operatorStateStatement: fixture.stateStatementFor(record),
        }),
        { now: NOW },
      ),
      /operation history is not time-monotonic/,
    );
  });

  await t.test('state-history time regression', () => {
    const record = structuredClone(released);
    record.history[2].at = '2026-07-17T11:59:59.000Z';
    assert.throws(
      () => assembleActionEscrowEvidencePackage(
        fixture.assemblyInput(record, {
          operatorStateStatement: fixture.stateStatementFor(record),
        }),
        { now: NOW },
      ),
      /state history is not bound to its operation log/,
    );
  });

  await t.test('milestone evidence observed after submission', () => {
    const record = structuredClone(released);
    record.milestone_evidence.artifact.observed_at = '2026-07-17T12:00:01.000Z';
    record.milestone_evidence.verification.observed_at =
      '2026-07-17T12:00:01.000Z';
    assert.throws(
      () => assembleActionEscrowEvidencePackage(
        fixture.assemblyInput(record, {
          operatorStateStatement: fixture.stateStatementFor(record),
        }),
        { now: '2026-07-17T12:00:02.000Z' },
      ),
      /milestone evidence was not valid at its submission operation/,
    );
  });

  await t.test('approval expired before release reservation', () => {
    const record = structuredClone(released);
    const approval = record.release_approvals[0];
    approval.resolution.signoff.context.expires_at = '2026-07-17T11:59:00.000Z';
    approval.verification.expires_at = '2026-07-17T11:59:00.000Z';
    approval.verification.resolution_digest = canonicalDigest(approval.resolution);
    assert.throws(
      () => assembleActionEscrowEvidencePackage(
        fixture.assemblyInput(record, {
          operatorStateStatement: fixture.stateStatementFor(record),
        }),
        { now: NOW },
      ),
      /release approval was not valid at its operation/,
    );
  });
});
