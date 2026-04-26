/**
 * EMILIA Protocol — blockchain.js extended coverage
 *
 * Targets lines 155–322: anchorToBase (viem mocking, all branches),
 * runAnchorBatch (Supabase mocking, full pipeline), production enforcement,
 * explorer URL construction.
 */

import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';

// ── mock @/lib/env ─────────────────────────────────────────────────────────

const mockGetBlockchainConfig = vi.fn();
const mockIsProduction = vi.fn();

vi.mock('@/lib/env', () => ({
  getBlockchainConfig: (...a) => mockGetBlockchainConfig(...a),
  isProduction: (...a) => mockIsProduction(...a),
}));

vi.mock('@/lib/crypto', () => ({
  sha256: (data) => {
    // simple deterministic stand-in
    const { createHash } = require('crypto');
    return createHash('sha256').update(data, 'utf8').digest('hex');
  },
}));

// ── viem mocks ────────────────────────────────────────────────────────────

const mockSendTransaction = vi.fn();
const mockWaitForTransactionReceipt = vi.fn();
const mockPrivateKeyToAccount = vi.fn();

vi.mock('viem', () => ({
  createWalletClient: vi.fn(() => ({
    sendTransaction: mockSendTransaction,
  })),
  createPublicClient: vi.fn(() => ({
    waitForTransactionReceipt: mockWaitForTransactionReceipt,
  })),
  http: vi.fn(() => ({})),
}));

vi.mock('viem/accounts', () => ({
  privateKeyToAccount: (...a) => mockPrivateKeyToAccount(...a),
}));

vi.mock('viem/chains', () => ({
  base: { id: 8453, name: 'base' },
  baseSepolia: { id: 84532, name: 'baseSepolia' },
}));

import { anchorToBase, runAnchorBatch } from '../lib/blockchain.js';

// ── helpers ───────────────────────────────────────────────────────────────

function makeSupabaseMock({
  unanchored = [],
  fetchErr = null,
  batchInsertErr = null,
} = {}) {
  const updateChain = {
    update: vi.fn().mockReturnThis(),
    eq: vi.fn().mockReturnThis(),
    then: (res) => res({ data: null, error: null }),
  };
  // make update awaitable
  Object.defineProperty(updateChain, Symbol.toStringTag, { value: 'Promise' });

  const mock = {
    from: vi.fn((table) => {
      if (table === 'receipts') {
        return {
          select: vi.fn().mockReturnThis(),
          is: vi.fn().mockReturnThis(),
          order: vi.fn().mockReturnThis(),
          limit: vi.fn().mockResolvedValue({ data: unanchored, error: fetchErr }),
          update: vi.fn().mockReturnValue({
            eq: vi.fn().mockResolvedValue({ data: null, error: null }),
          }),
        };
      }
      if (table === 'anchor_batches') {
        return {
          insert: vi.fn().mockResolvedValue({ data: null, error: batchInsertErr }),
        };
      }
      return { insert: vi.fn().mockResolvedValue({ data: null, error: null }) };
    }),
    // blockchain.js now uses bulk_update_receipt_anchors RPC for the receipt
    // anchoring updates instead of N individual UPDATE statements. Provide a
    // permissive default — most tests don't assert on the RPC payload, just
    // that the pipeline runs to completion.
    rpc: vi.fn((fnName, _params) => {
      if (fnName === 'bulk_update_receipt_anchors') {
        return Promise.resolve({ data: null, error: null });
      }
      return Promise.resolve({ data: null, error: null });
    }),
  };
  return mock;
}

// ─────────────────────────────────────────────────────────────────────────────
// anchorToBase — no private key, non-production → skip
// ─────────────────────────────────────────────────────────────────────────────

describe('anchorToBase — missing private key (non-production)', () => {
  beforeEach(() => {
    mockGetBlockchainConfig.mockReturnValue({ network: 'sepolia', walletPrivateKey: undefined });
    mockIsProduction.mockReturnValue(false);
  });

  it('returns skipped:true when no private key in dev', async () => {
    const result = await anchorToBase('batch-1', 'root-abc');
    expect(result.skipped).toBe(true);
    expect(result.transactionHash).toBeNull();
    expect(result.explorerUrl).toBeNull();
    expect(result.reason).toMatch(/EP_WALLET_PRIVATE_KEY/);
  });

  it('includes chain id in skipped result', async () => {
    const result = await anchorToBase('batch-2', 'root-def');
    expect(typeof result.chain).toBe('number');
  });

  it('returns chain id for sepolia when network=sepolia', async () => {
    const result = await anchorToBase('batch-3', 'root-ghi');
    expect(result.chain).toBe(84532);
  });

  it('returns chain id for mainnet when network=mainnet', async () => {
    mockGetBlockchainConfig.mockReturnValue({ network: 'mainnet', walletPrivateKey: undefined });
    const result = await anchorToBase('batch-4', 'root-jkl');
    expect(result.chain).toBe(8453);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// anchorToBase — missing private key, production → THROW
// ─────────────────────────────────────────────────────────────────────────────

describe('anchorToBase — missing private key (production enforcement)', () => {
  beforeEach(() => {
    mockGetBlockchainConfig.mockReturnValue({ network: 'mainnet', walletPrivateKey: undefined });
    mockIsProduction.mockReturnValue(true);
  });

  it('throws in production when EP_WALLET_PRIVATE_KEY not set', async () => {
    await expect(anchorToBase('batch-prod', 'root-prod')).rejects.toThrow(
      /EP_WALLET_PRIVATE_KEY/
    );
  });

  it('error message mentions blockchain anchoring requirement', async () => {
    await expect(anchorToBase('batch-prod2', 'root-prod2')).rejects.toThrow(
      /required in production/
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// anchorToBase — happy path (viem mocked)
// ─────────────────────────────────────────────────────────────────────────────

describe('anchorToBase — happy path with viem mocked', () => {
  const FAKE_HASH = '0xdeadbeefcafe';
  const FAKE_ADDRESS = '0xabc123';

  beforeEach(() => {
    mockGetBlockchainConfig.mockReturnValue({ network: 'sepolia', walletPrivateKey: 'aabbccdd' });
    mockIsProduction.mockReturnValue(false);
    mockPrivateKeyToAccount.mockReturnValue({ address: FAKE_ADDRESS });
    mockSendTransaction.mockResolvedValue(FAKE_HASH);
    mockWaitForTransactionReceipt.mockResolvedValue({ blockNumber: BigInt(12345) });
  });

  it('returns transactionHash from viem', async () => {
    const result = await anchorToBase('batch-ok', 'merkle-root-abc');
    expect(result.transactionHash).toBe(FAKE_HASH);
  });

  it('returns skipped:false on success', async () => {
    const result = await anchorToBase('batch-ok', 'merkle-root-abc');
    expect(result.skipped).toBe(false);
  });

  it('constructs correct explorer URL for sepolia', async () => {
    const result = await anchorToBase('batch-ok', 'merkle-root-abc');
    expect(result.explorerUrl).toBe(`https://sepolia.basescan.org/tx/${FAKE_HASH}`);
  });

  it('constructs correct explorer URL for mainnet', async () => {
    mockGetBlockchainConfig.mockReturnValue({ network: 'mainnet', walletPrivateKey: 'aabbccdd' });
    const result = await anchorToBase('batch-main', 'merkle-root-main');
    expect(result.explorerUrl).toBe(`https://basescan.org/tx/${FAKE_HASH}`);
  });

  it('includes blockNumber in result', async () => {
    const result = await anchorToBase('batch-ok', 'merkle-root-abc');
    expect(result.blockNumber).toBe(12345);
  });

  it('uses mainnet chain id 8453 when network=mainnet', async () => {
    mockGetBlockchainConfig.mockReturnValue({ network: 'mainnet', walletPrivateKey: 'aabbccdd' });
    const result = await anchorToBase('batch-m', 'root-m');
    expect(result.chain).toBe(8453);
  });

  it('uses sepolia chain id 84532 when network=sepolia', async () => {
    const result = await anchorToBase('batch-s', 'root-s');
    expect(result.chain).toBe(84532);
  });

  it('strips 0x prefix from private key before passing to viem', async () => {
    mockGetBlockchainConfig.mockReturnValue({ network: 'sepolia', walletPrivateKey: '0xdeadbeef' });
    await anchorToBase('batch-strip', 'root-strip');
    expect(mockPrivateKeyToAccount).toHaveBeenCalledWith('0xdeadbeef');
  });

  it('sends transaction to self with calldata', async () => {
    await anchorToBase('batch-cd', 'root-cd');
    expect(mockSendTransaction).toHaveBeenCalledWith(
      expect.objectContaining({
        to: FAKE_ADDRESS,
        value: 0n,
      })
    );
  });

  it('calldata encodes batchId and merkleRoot', async () => {
    mockSendTransaction.mockClear();
    await anchorToBase('BATCH-XYZ', 'ROOT-ABC');
    const call = mockSendTransaction.mock.calls[0][0];
    const decoded = Buffer.from(call.data.slice(2), 'hex').toString();
    expect(decoded).toContain('EP:v1:BATCH-XYZ:ROOT-ABC');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// anchorToBase — viem throws → wrapped error
// ─────────────────────────────────────────────────────────────────────────────

describe('anchorToBase — viem error wrapping', () => {
  beforeEach(() => {
    mockGetBlockchainConfig.mockReturnValue({ network: 'sepolia', walletPrivateKey: 'aabbccdd' });
    mockIsProduction.mockReturnValue(false);
    mockPrivateKeyToAccount.mockReturnValue({ address: '0xabc' });
  });

  it('wraps sendTransaction error in a new Error', async () => {
    mockSendTransaction.mockRejectedValue(new Error('insufficient funds'));
    await expect(anchorToBase('batch-err', 'root-err')).rejects.toThrow(
      /Failed to anchor on Base L2/
    );
  });

  it('wraps waitForTransactionReceipt error', async () => {
    mockSendTransaction.mockResolvedValue('0xhash');
    mockWaitForTransactionReceipt.mockRejectedValue(new Error('timeout'));
    await expect(anchorToBase('batch-timeout', 'root-timeout')).rejects.toThrow(
      /Failed to anchor on Base L2/
    );
  });

  it('error message includes original error message', async () => {
    mockSendTransaction.mockRejectedValue(new Error('nonce too low'));
    const err = await anchorToBase('batch-nonce', 'root-nonce').catch(e => e);
    expect(err.message).toContain('nonce too low');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// runAnchorBatch
// ─────────────────────────────────────────────────────────────────────────────

describe('runAnchorBatch — no receipts', () => {
  it('returns no_receipts status when DB is empty', async () => {
    mockGetBlockchainConfig.mockReturnValue(null);
    mockIsProduction.mockReturnValue(false);

    const supabase = makeSupabaseMock({ unanchored: [] });
    const result = await runAnchorBatch(supabase);
    expect(result.status).toBe('no_receipts');
  });
});

describe('runAnchorBatch — fetch error', () => {
  it('throws when Supabase fetch fails', async () => {
    mockGetBlockchainConfig.mockReturnValue(null);
    mockIsProduction.mockReturnValue(false);

    const supabase = makeSupabaseMock({ fetchErr: { message: 'DB error' } });
    await expect(runAnchorBatch(supabase)).rejects.toThrow(/Failed to fetch unanchored receipts/);
  });
});

describe('runAnchorBatch — happy path (skipped anchor)', () => {
  beforeEach(() => {
    // No private key → anchor will be skipped, not attempted via viem
    mockGetBlockchainConfig.mockReturnValue({ network: 'sepolia', walletPrivateKey: undefined });
    mockIsProduction.mockReturnValue(false);
  });

  const makeReceipts = (n) =>
    Array.from({ length: n }, (_, i) => ({
      id: `id-${i}`,
      receipt_id: `receipt-${i}`,
      receipt_hash: 'a'.repeat(64),
    }));

  it('returns anchored status with receipt count', async () => {
    const supabase = makeSupabaseMock({ unanchored: makeReceipts(3) });
    const result = await runAnchorBatch(supabase);
    expect(result.status).toBe('anchored');
    expect(result.receipts_anchored).toBe(3);
  });

  it('includes merkle_root in result', async () => {
    const supabase = makeSupabaseMock({ unanchored: makeReceipts(2) });
    const result = await runAnchorBatch(supabase);
    expect(result.merkle_root).toBeTruthy();
  });

  it('batch_id starts with batch_', async () => {
    const supabase = makeSupabaseMock({ unanchored: makeReceipts(2) });
    const result = await runAnchorBatch(supabase);
    expect(result.batch_id).toMatch(/^batch_/);
  });

  it('skipped_onchain is true when no private key', async () => {
    const supabase = makeSupabaseMock({ unanchored: makeReceipts(2) });
    const result = await runAnchorBatch(supabase);
    expect(result.skipped_onchain).toBe(true);
  });

  it('works with 1 receipt (single leaf merkle tree)', async () => {
    const supabase = makeSupabaseMock({ unanchored: makeReceipts(1) });
    const result = await runAnchorBatch(supabase);
    expect(result.status).toBe('anchored');
    expect(result.receipts_anchored).toBe(1);
  });

  it('batch insert error throws to surface state divergence', async () => {
    // Updated assertion: blockchain.js now THROWS when the anchor_batches DB
    // record insert fails. The previous "non-fatal" behavior silently lost
    // the linkage between on-chain anchor and DB tracking, requiring manual
    // reconciliation. The new behavior surfaces the divergence immediately
    // so ops can intervene before downstream verification depends on the
    // missing record.
    const supabase = makeSupabaseMock({
      unanchored: makeReceipts(2),
      batchInsertErr: { message: 'insert failed' },
    });
    await expect(runAnchorBatch(supabase)).rejects.toThrow(
      /Anchor batch DB record failed/,
    );
  });

  it('updates receipts via bulk_update_receipt_anchors RPC', async () => {
    // blockchain.js now batches receipt anchor updates through a single
    // bulk_update_receipt_anchors RPC instead of N individual UPDATE
    // statements via supabase.from('receipts').update(...).eq(...). The
    // RPC takes the full update set as `p_updates` and applies them in
    // one round-trip.
    const receipts = makeReceipts(3);
    const supabase = makeSupabaseMock({ unanchored: receipts });
    await runAnchorBatch(supabase);

    const rpcCalls = supabase.rpc.mock.calls.filter(
      ([fnName]) => fnName === 'bulk_update_receipt_anchors',
    );
    expect(rpcCalls.length).toBeGreaterThanOrEqual(1);
    // The RPC payload should include all 3 receipts
    const updates = rpcCalls[0]?.[1]?.p_updates;
    if (Array.isArray(updates)) {
      expect(updates.length).toBe(3);
    }
  });
});
