const { expect } = require('chai');

describe('receipt-program Base bridge characterization', function () {
  async function api() {
    return import('../dist/lib/receipt-program-bridge.js');
  }

  function request() {
    const receipt = {
      '@type': 'EP-RECEIPT-v1',
      receipt_id: 'rcpt_experimental_001',
      decision: 'allow_with_signoff',
    };
    return {
      programId: 'purchase-program-v1',
      instructionId: 'buy-blue-bicycle',
      caid: 'caid:jcs-sha256:test-value',
      selector: { protocol: 'mcp', tool: 'purchase' },
      observedAction: {
        payment_instruction_id: 'op_001',
        item: 'blue bicycle',
        amount: '200.00',
        currency: 'USD',
      },
      capability: {
        operationId: 'op_001',
        capabilityReceipt: { capability_id: 'cap_001', receipt },
        action: { amount: 200, currency: 'USD' },
      },
    };
  }

  it('preserves deterministic receipt-program and material-field hashes', async function () {
    const { compileReceiptProgram } = await api();
    const compiled = compileReceiptProgram(request(), 'payment_instruction_id');

    expect(compiled.programDigest).to.equal(
      'sha256:806dab30217683d029382af2a3a7e631c6c4ab2e0ee42b078b6c866e0eda278c',
    );
    expect(compiled.receiptHash).to.equal(
      '0x4457e67bc04a009f909aef9d91a7c898793970fb2dbe565fcb151a5eaa840d3b',
    );
    expect(compiled.caidHash).to.equal(
      '0x9ac94becc4433ebc9416f502dcd514a983eaa47f57bd6f9c3f960403c7d325a3',
    );
    expect(compiled.actionHash).to.equal(
      '0x9fb1b5b7dc9d9e93472a75550011de06bd2d74663fb7c14850cddf1454e201a4',
    );
    expect(compiled.inputHash).to.equal(
      '0x4f76fc4ad585a75c105c04d0ad40de6a39df1d3dbcd38a6826ec19033763ff7b',
    );
    expect(Object.isFrozen(compiled)).to.equal(true);
    expect(Object.isFrozen(compiled.program)).to.equal(true);
  });

  it('fails closed when the observed action does not bind the operation ID', async function () {
    const { compileReceiptProgram } = await api();
    const mismatched = request();
    mismatched.observedAction.payment_instruction_id = 'op_other';

    expect(() => compileReceiptProgram(mismatched, 'payment_instruction_id'))
      .to.throw('receipt-program operation binding failed');
  });

  it('requires every trust callback to be pinned when the adapter is constructed', async function () {
    const { createReceiptProgramBaseBridge } = await api();

    await expect(createReceiptProgramBaseBridge({
      contract: { hashAuthorization() {} },
    })).to.be.rejectedWith('assertGateAuthorization must be constructor-pinned');
  });
});
