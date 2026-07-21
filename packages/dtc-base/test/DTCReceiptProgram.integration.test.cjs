const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
const { expect } = require('chai');
const { ethers } = require('hardhat');

describe('DTC Base x EMILIA receipt-program kernel', function () {
  async function fixture(label) {
    const gateApi = await import('../../gate/index.js');
    const { computeCaid } = await import('../../../caid/impl/js/caid.mjs');
    const { createReceiptProgramBaseBridge } = await import('../lib/receipt-program-bridge.mjs');
    const nowMs = Date.parse('2026-07-20T22:00:00.000Z');
    const operationId = `dtc_receipt_program_${label}`;
    const beneficiary = `sha256:${'a'.repeat(64)}`;
    const action = Object.freeze({
      action_type: 'payment.release',
      amount: '1.00',
      amount_usd: 1,
      currency: 'USD',
      beneficiary_account: beneficiary,
      beneficiary_account_hash: beneficiary,
      payment_instruction_id: operationId,
    });
    const definitions = [{
      action_type: 'payment.release.1',
      required_fields: [
        { name: 'amount', type: 'amount-string' },
        { name: 'currency', type: 'enum', values_ref: 'ISO 4217 alpha-3' },
        { name: 'beneficiary_account', type: 'digest' },
        { name: 'payment_instruction_id', type: 'string' },
      ],
      optional_fields: [],
    }];
    const resolveCaid = (observed) => {
      const material = {
        action_type: 'payment.release.1',
        amount: observed.amount,
        currency: observed.currency,
        beneficiary_account: observed.beneficiary_account,
        payment_instruction_id: observed.payment_instruction_id,
      };
      const computed = computeCaid(material, { suite: 'jcs-sha256', definitions });
      if (!computed.caid) throw new Error(`CAID refused: ${computed.refusals?.join(',')}`);
      return computed.caid;
    };
    const caid = resolveCaid(action);
    const receiptHarness = gateApi.createEg1Harness({ action, now: () => nowMs, idPrefix: `dtc-${label}` });
    const capabilityIssuer = generateKeyPairSync('ed25519');
    const capabilityIssuerKey = capabilityIssuer.publicKey
      .export({ type: 'spki', format: 'der' }).toString('base64url');
    const certificateOperator = generateKeyPairSync('ed25519');
    const baseReceipt = receiptHarness.mint({ outcome: 'allow_with_signoff', extra: { capability_only: true } });
    const capability = gateApi.mintCapabilityReceipt(baseReceipt, {
      issuerPrivateKey: capabilityIssuer.privateKey,
      budget: { amount: 10, currency: 'USD' },
      expiry: nowMs + 24 * 60 * 60 * 1000,
      capabilityId: `cap_dtc_${label}`,
      secret: Buffer.alloc(32, 7),
      scope: {
        profile: gateApi.CAPABILITY_CAID_SCOPE_PROFILE,
        operation_id_field: 'payment_instruction_id',
        caids: [caid],
      },
    });
    const capabilityStore = gateApi.createMemoryCapabilityStore();
    assert.equal(capabilityStore.registerCapability(capability.capabilityReceipt), true);
    const gate = gateApi.createGate({
      manifest: gateApi.createDefaultActionRiskManifest(),
      trustedKeys: [receiptHarness.publicKey],
      approverKeys: receiptHarness.approverKeys,
      quorumPolicy: receiptHarness.quorumPolicy,
      rpId: receiptHarness.rpId,
      allowedOrigins: receiptHarness.allowedOrigins,
      capabilityStore,
      capabilityTrustedIssuerKeys: [capabilityIssuerKey],
      capabilityCaidResolver: resolveCaid,
      runtimeMonitor: gateApi.createRuntimeMonitor({ now: () => nowMs }),
      allowEphemeralStore: true,
      now: () => nowMs,
    });
    const kernel = gateApi.createReceiptProgramKernel({
      gate,
      resolveCaid,
      operationIdField: 'payment_instruction_id',
      certificatePrivateKey: certificateOperator.privateKey,
      certificateContext: {
        issuer: 'emilia-dtc-private-test',
        tenant: 'private-test',
        environment: 'hardhat',
        audience: 'private-test-verifier',
        key_id: 'local-dev',
      },
      projectResult: (result) => ({
        provider: result.provider,
        provider_operation_id: result.provider_operation_id,
        status: result.status,
        dtc_base: result.dtc_base,
      }),
      allowEphemeralState: true,
      now: () => nowMs,
    });

    const [admin, bridgeSigner, providerSigner, payerSigner, executorSigner, merchant] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory('DTCBaseSettlement');
    const settlement = await Factory.deploy(admin.address, bridgeSigner.address);
    await settlement.waitForDeployment();
    await settlement.connect(admin).setProviderSigner(merchant.address, providerSigner.address);
    const latestTimestamp = async () => BigInt((await ethers.provider.getBlock('latest')).timestamp);
    const bridge = await createReceiptProgramBaseBridge({
      contract: settlement,
      bridgeSigner,
      payerSigner,
      executorSigner,
      providerSigner,
      merchant: merchant.address,
      operationIdField: 'payment_instruction_id',
      assertGateAuthorization: ({ authorization, operation, program }) => (
        authorization?.allow === true
          && operation?.operationId === program.operation_id
          && `sha256:${operation.actionDigest.replace(/^sha256:/, '')}` === program.action_digest
      ),
      nextNonce: () => 1n,
      expiresAt: async () => (await latestTimestamp()) + 3600n,
      maxAmount: () => ethers.parseEther('0.2'),
      settledAmount: () => ethers.parseEther('0.15'),
      now: latestTimestamp,
    });
    const request = {
      programId: 'dtc-base-payment',
      instructionId: `release-${label}`,
      caid,
      selector: { protocol: 'mcp', tool: 'release_payment' },
      observedAction: action,
      capability: {
        capabilityReceipt: capability.capabilityReceipt,
        secret: capability.secret,
        action: { amount: 1, currency: 'USD' },
        operationId,
      },
    };
    return { bridge, gate, kernel, request, settlement, capabilityStore, capabilityId: `cap_dtc_${label}` };
  }

  it('joins one real Gate authorization, CAID, capability spend, provider effect, and Base certificate', async function () {
    const f = await fixture('executed');
    const run = await f.kernel.run(
      f.request,
      f.bridge.wrap(f.request, async (_authorization, operation) => ({
        provider: 'simulated-custodian',
        provider_operation_id: operation.providerIdempotencyKey,
        status: 'settled',
      })),
    );

    expect(run.ok).to.equal(true);
    expect(run.outcome).to.equal('executed');
    const operation = await f.settlement.getOperation(run.result.dtc_base.operation_id);
    expect(operation.status).to.equal(4n);
    expect(operation.programHash).to.equal(`0x${run.certificate.program_digest.slice(7)}`);
    expect(operation.actionHash).to.equal(`0x${run.certificate.program.action_digest.slice(7)}`);
    expect(operation.certificateHash).to.equal(run.result.dtc_base.certificate_hash);
    expect(f.capabilityStore.getState(f.capabilityId).consumed_amount).to.equal(1);
  });

  it('records both ledgers indeterminate and freezes Base value when the provider response is lost', async function () {
    const f = await fixture('indeterminate');
    const run = await f.kernel.run(
      f.request,
      f.bridge.wrap(f.request, async () => {
        throw new Error('simulated provider response loss');
      }),
    );

    expect(run.ok).to.equal(false);
    expect(run.outcome).to.equal('indeterminate');
    const events = await f.settlement.queryFilter(f.settlement.filters.OperationReserved());
    expect(events).to.have.length(1);
    const operation = await f.settlement.getOperation(events[0].args.operationId);
    expect(operation.status).to.equal(3n);
    expect(operation.programHash).to.equal(`0x${run.certificate.program_digest.slice(7)}`);
    expect(await f.settlement.totalLocked()).to.equal(ethers.parseEther('0.2'));
    expect(await f.settlement.totalClaimable()).to.equal(0);
    expect(f.capabilityStore.getOperation(f.request.capability.operationId).outcome).to.equal('indeterminate');
  });

  it('compensates the Base reservation when provider entry fails before the external effect', async function () {
    const f = await fixture('pre-effect-compensation');
    await f.settlement.pauseSettlements();
    let effects = 0;
    const run = await f.kernel.run(
      f.request,
      f.bridge.wrap(f.request, async () => {
        effects += 1;
        return { provider: 'must-not-run', provider_operation_id: 'none', status: 'none' };
      }),
    );

    expect(run.outcome).to.equal('indeterminate');
    expect(effects).to.equal(0);
    const events = await f.settlement.queryFilter(f.settlement.filters.OperationReserved());
    const operation = await f.settlement.getOperation(events[0].args.operationId);
    expect(operation.status).to.equal(6n);
    expect(await f.settlement.totalLocked()).to.equal(0);
    expect(await f.settlement.claimable(operation.payer)).to.equal(ethers.parseEther('0.2'));
    expect(f.capabilityStore.getOperation(f.request.capability.operationId).outcome).to.equal('indeterminate');
  });
});
