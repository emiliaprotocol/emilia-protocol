const { expect } = require('chai');
const { ethers } = require('hardhat');
const { time } = require('@nomicfoundation/hardhat-network-helpers');

const AUTHORIZATION_TYPES = {
  Authorization: [
    { name: 'receiptHash', type: 'bytes32' },
    { name: 'caid', type: 'bytes32' },
    { name: 'actionHash', type: 'bytes32' },
    { name: 'programHash', type: 'bytes32' },
    { name: 'inputHash', type: 'bytes32' },
    { name: 'payer', type: 'address' },
    { name: 'executor', type: 'address' },
    { name: 'merchant', type: 'address' },
    { name: 'authorizationSigner', type: 'address' },
    { name: 'providerSigner', type: 'address' },
    { name: 'maxAmount', type: 'uint256' },
    { name: 'expiresAt', type: 'uint64' },
    { name: 'providerConfigVersion', type: 'uint64' },
    { name: 'nonce', type: 'uint256' },
  ],
};

const INVOCATION_TYPES = {
  Invocation: [
    { name: 'operationId', type: 'bytes32' },
    { name: 'invocationHash', type: 'bytes32' },
    { name: 'providerRequestId', type: 'bytes32' },
    { name: 'observedAt', type: 'uint64' },
  ],
};

const OUTCOME_TYPES = {
  Outcome: [
    { name: 'operationId', type: 'bytes32' },
    { name: 'invocationHash', type: 'bytes32' },
    { name: 'providerRequestId', type: 'bytes32' },
    { name: 'evidenceHash', type: 'bytes32' },
    { name: 'priorOutcomeDigest', type: 'bytes32' },
    { name: 'amount', type: 'uint256' },
    { name: 'observedAt', type: 'uint64' },
    { name: 'kind', type: 'uint8' },
  ],
};

const STATUS = Object.freeze({
  RESERVED: 1n,
  INVOKED: 2n,
  INDETERMINATE: 3n,
  SUCCEEDED: 4n,
  FAILED: 5n,
  CANCELLED: 6n,
});

const RESOLUTION = Object.freeze({
  PROVIDER_EVIDENCE: 1n,
  RECONCILED_PROVIDER_EVIDENCE: 2n,
  PARTY_AGREEMENT: 3n,
  EXPIRY_CANCELLATION: 4n,
});

const OUTCOME = Object.freeze({ SUCCEEDED: 1, FAILED: 2, INDETERMINATE: 3 });

describe('DTCBaseSettlement', function () {
  let settlement;
  let admin;
  let authorizationSigner;
  let providerSigner;
  let payer;
  let executor;
  let merchant;
  let reconciler;
  let stranger;
  let domain;

  beforeEach(async function () {
    [admin, authorizationSigner, providerSigner, payer, executor, merchant, reconciler, stranger] =
      await ethers.getSigners();
    const Factory = await ethers.getContractFactory('DTCBaseSettlement');
    settlement = await Factory.deploy(admin.address, authorizationSigner.address);
    await settlement.waitForDeployment();
    await settlement.connect(admin).setProviderSigner(merchant.address, providerSigner.address);
    domain = {
      name: 'EMILIA DTC Base Settlement',
      version: '2',
      chainId: (await ethers.provider.getNetwork()).chainId,
      verifyingContract: await settlement.getAddress(),
    };
  });

  async function authorization(overrides = {}) {
    return {
      receiptHash: ethers.id('receipt-1'),
      caid: ethers.sha256(ethers.toUtf8Bytes('EP-CAID-v1:buy-blue-bike')),
      actionHash: ethers.sha256(ethers.toUtf8Bytes('buy-blue-bike')),
      programHash: ethers.sha256(ethers.toUtf8Bytes('purchase-program-v1')),
      inputHash: ethers.sha256(ethers.toUtf8Bytes('{"item":"blue-bike"}')),
      payer: payer.address,
      executor: executor.address,
      merchant: merchant.address,
      authorizationSigner: authorizationSigner.address,
      providerSigner: providerSigner.address,
      maxAmount: ethers.parseEther('1'),
      expiresAt: BigInt(await time.latest()) + 3600n,
      providerConfigVersion: 1n,
      nonce: 1n,
      ...overrides,
    };
  }

  async function signAuthorization(value, signer = authorizationSigner, signingDomain = domain) {
    return signer.signTypedData(signingDomain, AUTHORIZATION_TYPES, value);
  }

  async function reserve(overrides = {}) {
    const value = await authorization(overrides);
    const signature = await signAuthorization(value);
    const operationId = await settlement.hashAuthorization(value);
    await settlement.connect(value.payer === payer.address ? payer : stranger)
      .reserve(value, signature, { value: value.maxAmount });
    return { value, signature, operationId };
  }

  async function invocationFor(operationId, sequence = 1n, overrides = {}) {
    return {
      operationId,
      invocationHash: ethers.id(`provider-invocation-${sequence}`),
      providerRequestId: ethers.id(`provider-request-${sequence}`),
      observedAt: BigInt(await time.latest()),
      ...overrides,
    };
  }

  async function invoke(overrides = {}, sequence = 1n) {
    const prepared = await reserve(overrides);
    const invocation = await invocationFor(prepared.operationId, sequence);
    const signature = await providerSigner.signTypedData(domain, INVOCATION_TYPES, invocation);
    await settlement.connect(executor).markInvoked(invocation, signature);
    return { ...prepared, invocation, invocationSignature: signature };
  }

  async function outcome(prepared, kind, amount = 0n, overrides = {}) {
    return {
      operationId: prepared.operationId,
      invocationHash: prepared.invocation.invocationHash,
      providerRequestId: prepared.invocation.providerRequestId,
      evidenceHash: ethers.id(`provider-evidence-${prepared.operationId}-${kind}`),
      priorOutcomeDigest: ethers.ZeroHash,
      amount,
      observedAt: BigInt(await time.latest()),
      kind,
      ...overrides,
    };
  }

  async function signOutcome(value, signer = providerSigner) {
    return signer.signTypedData(domain, OUTCOME_TYPES, value);
  }

  it('reserves exact value and freezes every signed material field including provider configuration', async function () {
    const { value, operationId } = await reserve();
    const operation = await settlement.getOperation(operationId);

    expect(operation.status).to.equal(STATUS.RESERVED);
    expect(operation.receiptHash).to.equal(value.receiptHash);
    expect(operation.caid).to.equal(value.caid);
    expect(operation.actionHash).to.equal(value.actionHash);
    expect(operation.programHash).to.equal(value.programHash);
    expect(operation.inputHash).to.equal(value.inputHash);
    expect(operation.providerSigner).to.equal(value.providerSigner);
    expect(operation.providerConfigVersion).to.equal(value.providerConfigVersion);
    expect(await settlement.totalLocked()).to.equal(value.maxAmount);
    expect(await settlement.accountedBalance()).to.equal(value.maxAmount);
  });

  it('rejects value, payer, and signed-field substitution', async function () {
    const value = await authorization();
    const signature = await signAuthorization(value);
    await expect(
      settlement.connect(payer).reserve(value, signature, { value: value.maxAmount - 1n }),
    ).to.be.revertedWithCustomError(settlement, 'ValueMismatch');
    await expect(
      settlement.connect(stranger).reserve(value, signature, { value: value.maxAmount }),
    ).to.be.revertedWithCustomError(settlement, 'WrongPayer');
    await expect(
      settlement.connect(payer).reserve(
        { ...value, inputHash: ethers.id('substituted-input') },
        signature,
        { value: value.maxAmount },
      ),
    ).to.be.revertedWithCustomError(settlement, 'InvalidAuthorization');
  });

  it('consumes both the namespaced receipt and signer-payer nonce exactly once', async function () {
    const prepared = await reserve();
    await expect(
      settlement.connect(payer).reserve(prepared.value, prepared.signature, { value: prepared.value.maxAmount }),
    ).to.be.revertedWithCustomError(settlement, 'ReceiptAlreadyConsumed');

    const sameNonce = await authorization({ receiptHash: ethers.id('different-receipt') });
    await expect(
      settlement.connect(payer).reserve(sameNonce, await signAuthorization(sameNonce), { value: sameNonce.maxAmount }),
    ).to.be.revertedWithCustomError(settlement, 'AuthorizationNonceAlreadyConsumed');
  });

  it('requires the frozen provider to authenticate boundary entry and the frozen executor to submit it', async function () {
    const prepared = await reserve();
    const invocation = await invocationFor(prepared.operationId);
    const signature = await providerSigner.signTypedData(domain, INVOCATION_TYPES, invocation);
    await expect(settlement.connect(stranger).markInvoked(invocation, signature))
      .to.be.revertedWithCustomError(settlement, 'WrongExecutor');
    await expect(settlement.connect(executor).markInvoked(invocation, await signOutcome({
      operationId: invocation.operationId,
      invocationHash: invocation.invocationHash,
      providerRequestId: invocation.providerRequestId,
      evidenceHash: ethers.id('wrong-type'),
      priorOutcomeDigest: ethers.ZeroHash,
      amount: 0n,
      observedAt: invocation.observedAt,
      kind: OUTCOME.FAILED,
    }))).to.be.revertedWithCustomError(settlement, 'InvalidProviderEvidence');

    await expect(settlement.connect(executor).markInvoked(invocation, signature))
      .to.emit(settlement, 'ProviderBoundaryEntered');
    expect((await settlement.getOperation(prepared.operationId)).status).to.equal(STATUS.INVOKED);
  });

  it('settles authenticated success with an exact merchant amount and payer remainder', async function () {
    const prepared = await invoke();
    const amount = ethers.parseEther('0.6');
    const evidence = await outcome(prepared, OUTCOME.SUCCEEDED, amount);
    await settlement.submitOutcome(evidence, await signOutcome(evidence));

    const operation = await settlement.getOperation(prepared.operationId);
    expect(operation.status).to.equal(STATUS.SUCCEEDED);
    expect(operation.resolution).to.equal(RESOLUTION.PROVIDER_EVIDENCE);
    expect(operation.settledAmount).to.equal(amount);
    expect(operation.certificateHash).not.to.equal(ethers.ZeroHash);
    expect(await settlement.claimable(merchant.address)).to.equal(amount);
    expect(await settlement.claimable(payer.address)).to.equal(prepared.value.maxAmount - amount);
    expect(await settlement.totalLocked()).to.equal(0);
  });

  it('settles authenticated failure only as a complete payer refund', async function () {
    const prepared = await invoke();
    const evidence = await outcome(prepared, OUTCOME.FAILED);
    await settlement.submitOutcome(evidence, await signOutcome(evidence));
    expect((await settlement.getOperation(prepared.operationId)).status).to.equal(STATUS.FAILED);
    expect(await settlement.claimable(payer.address)).to.equal(prepared.value.maxAmount);
    expect(await settlement.claimable(merchant.address)).to.equal(0);
  });

  it('freezes indeterminate value and requires a fresh, causally chained reconciliation', async function () {
    const prepared = await invoke();
    const uncertain = await outcome(prepared, OUTCOME.INDETERMINATE);
    await settlement.submitOutcome(uncertain, await signOutcome(uncertain));
    const uncertainDigest = await settlement.hashOutcome(uncertain);
    expect((await settlement.getOperation(prepared.operationId)).status).to.equal(STATUS.INDETERMINATE);
    expect(await settlement.totalLocked()).to.equal(prepared.value.maxAmount);

    const terminal = await outcome(prepared, OUTCOME.SUCCEEDED, ethers.parseEther('0.8'), {
      evidenceHash: ethers.id('provider-final-evidence'),
      priorOutcomeDigest: uncertainDigest,
      observedAt: BigInt(await time.latest()) + 1n,
    });
    const role = await settlement.RECONCILER_ROLE();
    await settlement.connect(admin).grantRole(role, reconciler.address);
    await settlement.connect(reconciler).reconcile(terminal, await signOutcome(terminal));
    const operation = await settlement.getOperation(prepared.operationId);
    expect(operation.status).to.equal(STATUS.SUCCEEDED);
    expect(operation.resolution).to.equal(RESOLUTION.RECONCILED_PROVIDER_EVIDENCE);
  });

  it('rejects forged, cross-operation, over-budget, and stale provider outcomes', async function () {
    const prepared = await invoke();
    const success = await outcome(prepared, OUTCOME.SUCCEEDED, ethers.parseEther('0.5'));
    await expect(settlement.submitOutcome(success, await signOutcome(success, stranger)))
      .to.be.revertedWithCustomError(settlement, 'InvalidProviderEvidence');

    const wrongInvocation = { ...success, invocationHash: ethers.id('different-invocation') };
    await expect(settlement.submitOutcome(wrongInvocation, await signOutcome(wrongInvocation)))
      .to.be.revertedWithCustomError(settlement, 'OutcomeNotBoundToInvocation');

    const tooMuch = { ...success, amount: prepared.value.maxAmount + 1n };
    await expect(settlement.submitOutcome(tooMuch, await signOutcome(tooMuch)))
      .to.be.revertedWithCustomError(settlement, 'AmountExceedsAuthorization');

    const stale = { ...success, observedAt: 1n };
    await expect(settlement.submitOutcome(stale, await signOutcome(stale)))
      .to.be.revertedWithCustomError(settlement, 'InvalidObservationTime');
  });

  it('permits expiry cancellation only before provider-confirmed entry', async function () {
    const soon = BigInt(await time.latest()) + 10n;
    const prepared = await reserve({ expiresAt: soon });
    await time.increaseTo(soon + 1n);
    await settlement.connect(stranger).cancelExpired(prepared.operationId);
    const cancelled = await settlement.getOperation(prepared.operationId);
    expect(cancelled.status).to.equal(STATUS.CANCELLED);
    expect(cancelled.resolution).to.equal(RESOLUTION.EXPIRY_CANCELLATION);

    const invoked = await invoke({ nonce: 2n, receiptHash: ethers.id('receipt-2') }, 2n);
    await time.increaseTo(invoked.value.expiresAt + 1n);
    await expect(settlement.cancelExpired(invoked.operationId))
      .to.be.revertedWithCustomError(settlement, 'InvalidState');
  });

  it('lets only the payer compensate a reservation before provider entry', async function () {
    const prepared = await reserve();
    await expect(settlement.connect(stranger).cancelBeforeInvocation(prepared.operationId))
      .to.be.revertedWithCustomError(settlement, 'WrongPayer');
    await settlement.connect(payer).cancelBeforeInvocation(prepared.operationId);
    expect((await settlement.getOperation(prepared.operationId)).status).to.equal(STATUS.CANCELLED);
    expect(await settlement.totalLocked()).to.equal(0);
    expect(await settlement.claimable(payer.address)).to.equal(prepared.value.maxAmount);
  });

  it('uses pull payments and permits a claimant to redirect withdrawal safely', async function () {
    const prepared = await invoke();
    const amount = ethers.parseEther('0.7');
    const success = await outcome(prepared, OUTCOME.SUCCEEDED, amount);
    await settlement.submitOutcome(success, await signOutcome(success));

    await expect(settlement.connect(merchant).withdrawTo(stranger.address))
      .to.emit(settlement, 'Withdrawal')
      .withArgs(merchant.address, stranger.address, amount);
    expect(await settlement.claimable(merchant.address)).to.equal(0);
    expect(await settlement.totalClaimable()).to.equal(prepared.value.maxAmount - amount);
  });

  it('separates reservation pause from settlement pause and never exposes admin withdrawal', async function () {
    const prepared = await invoke();
    await settlement.connect(admin).pauseReservations();
    const second = await authorization({ nonce: 2n, receiptHash: ethers.id('receipt-2') });
    await expect(
      settlement.connect(payer).reserve(second, await signAuthorization(second), { value: second.maxAmount }),
    ).to.be.revertedWithCustomError(settlement, 'EnforcedPause');

    await settlement.connect(admin).pauseSettlements();
    const failed = await outcome(prepared, OUTCOME.FAILED);
    await expect(settlement.submitOutcome(failed, await signOutcome(failed)))
      .to.be.revertedWithCustomError(settlement, 'SettlementsPaused');
    await settlement.connect(admin).unpauseSettlements();
    await settlement.submitOutcome(failed, await signOutcome(failed));

    const functionNames = settlement.interface.fragments
      .filter((fragment) => fragment.type === 'function')
      .map((fragment) => fragment.name);
    expect(functionNames).not.to.include('emergencyWithdraw');
    expect(functionNames).not.to.include('sweep');
  });
});
