/**
 * EMILIA Protocol — Blockchain Verification Layer
 *
 * Receipts are cryptographically anchored on Base L2 (Coinbase Layer 2)
 * via Merkle root publishing. This is NOT a crypto product — no tokens,
 * no DeFi, no wallets for users. Just math.
 *
 * Flow: Receipt → SHA-256 Hash → Merkle Tree Batch → Base L2 Anchor → Anyone Can Verify
 *
 * Cost: ~$0.60/mo at launch scale, ~$600/mo at 2M receipts/day.
 *
 * @license Apache-2.0
 */

import crypto from 'crypto';

// =============================================================================
// MERKLE TREE
// =============================================================================

/**
 * SHA-256 hash helper (sync, for Merkle operations).
 */
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Hash two nodes together in sorted order (canonical Merkle construction).
 * Sorting ensures the same proof regardless of leaf position.
 */
function hashPair(a, b) {
  const sorted = [a, b].sort();
  return sha256(sorted[0] + sorted[1]);
}

/**
 * Build a Merkle tree from an array of leaf hashes.
 * Returns { root, layers, leafCount }.
 *
 * layers[0] = leaves, layers[n] = root
 * If odd number of leaves, the last leaf is promoted (not duplicated).
 */
export function buildMerkleTree(leafHashes) {
  if (!leafHashes || leafHashes.length === 0) {
    return { root: null, layers: [], leafCount: 0 };
  }

  if (leafHashes.length === 1) {
    return { root: leafHashes[0], layers: [leafHashes], leafCount: 1 };
  }

  const layers = [leafHashes];
  let currentLayer = leafHashes;

  while (currentLayer.length > 1) {
    const nextLayer = [];
    for (let i = 0; i < currentLayer.length; i += 2) {
      if (i + 1 < currentLayer.length) {
        nextLayer.push(hashPair(currentLayer[i], currentLayer[i + 1]));
      } else {
        // Odd leaf: promote
        nextLayer.push(currentLayer[i]);
      }
    }
    layers.push(nextLayer);
    currentLayer = nextLayer;
  }

  return {
    root: currentLayer[0],
    layers,
    leafCount: leafHashes.length,
  };
}

/**
 * Generate a Merkle proof for a specific leaf.
 * Returns an array of { hash, position } steps.
 * position: 'left' means the sibling is on the left, 'right' on the right.
 */
export function generateMerkleProof(layers, leafIndex) {
  if (!layers || layers.length === 0 || leafIndex < 0 || leafIndex >= layers[0].length) {
    return null;
  }

  const proof = [];
  let index = leafIndex;

  for (let i = 0; i < layers.length - 1; i++) {
    const layer = layers[i];
    const isRight = index % 2 === 1;
    const siblingIndex = isRight ? index - 1 : index + 1;

    if (siblingIndex < layer.length) {
      proof.push({
        hash: layer[siblingIndex],
        position: isRight ? 'left' : 'right',
      });
    }

    index = Math.floor(index / 2);
  }

  return proof;
}

/**
 * Verify a Merkle proof.
 * Returns true if the proof reconstructs the expected root.
 */
export function verifyMerkleProof(leafHash, proof, expectedRoot) {
  let current = leafHash;

  for (const step of proof) {
    if (step.position === 'left') {
      current = hashPair(step.hash, current);
    } else {
      current = hashPair(current, step.hash);
    }
  }

  return current === expectedRoot;
}

// =============================================================================
// BASE L2 ANCHORING
// =============================================================================

// Base Mainnet chain config
const BASE_CHAIN = {
  id: 8453,
  rpcUrl: 'https://mainnet.base.org',
  explorerUrl: 'https://basescan.org',
};

// Base Sepolia (testnet) for development
const BASE_SEPOLIA = {
  id: 84532,
  rpcUrl: 'https://sepolia.base.org',
  explorerUrl: 'https://sepolia.basescan.org',
};

/**
 * Get the chain config based on environment.
 */
function getChain() {
  return process.env.BASE_NETWORK === 'mainnet' ? BASE_CHAIN : BASE_SEPOLIA;
}

/**
 * Anchor a Merkle root to Base L2.
 *
 * Sends a data-only transaction with calldata: EP:v1:{batchId}:{merkleRoot}
 *
 * Requires:
 *   - EP_WALLET_PRIVATE_KEY env var (hex, no 0x prefix)
 *   - Small amount of ETH on Base for gas (~$0.01 per tx)
 *
 * @param {string} batchId - Unique batch identifier
 * @param {string} merkleRoot - The Merkle root to anchor
 * @returns {{ transactionHash, explorerUrl, chain }} or throws
 */
export async function anchorToBase(batchId, merkleRoot) {
  const privateKey = process.env.EP_WALLET_PRIVATE_KEY;
  if (!privateKey) {
    console.warn('EP_WALLET_PRIVATE_KEY not set — skipping on-chain anchor');
    return {
      transactionHash: null,
      explorerUrl: null,
      chain: getChain().id,
      skipped: true,
      reason: 'EP_WALLET_PRIVATE_KEY not configured',
    };
  }

  const chain = getChain();
  const calldata = `EP:v1:${batchId}:${merkleRoot}`;
  const hexData = '0x' + Buffer.from(calldata).toString('hex');

  try {
    // Dynamic import viem (tree-shakeable, no ethers bloat)
    const { createWalletClient, createPublicClient, http } = await import('viem');
    const { privateKeyToAccount } = await import('viem/accounts');
    const { base, baseSepolia } = await import('viem/chains');

    const selectedChain = chain.id === 8453 ? base : baseSepolia;
    const account = privateKeyToAccount(`0x${privateKey.replace('0x', '')}`);

    const publicClient = createPublicClient({
      chain: selectedChain,
      transport: http(),
    });

    const walletClient = createWalletClient({
      account,
      chain: selectedChain,
      transport: http(),
    });

    // Send data-only tx to self (cheapest way to post calldata)
    const hash = await walletClient.sendTransaction({
      to: account.address,
      value: 0n,
      data: hexData,
    });

    // Wait for confirmation
    const receipt = await publicClient.waitForTransactionReceipt({ hash });

    return {
      transactionHash: hash,
      explorerUrl: `${chain.explorerUrl}/tx/${hash}`,
      chain: chain.id,
      blockNumber: Number(receipt.blockNumber),
      skipped: false,
    };
  } catch (err) {
    console.error('Base L2 anchor error:', err);
    throw new Error(`Failed to anchor on Base L2: ${err.message}`);
  }
}

// =============================================================================
// BATCH PROCESSING
// =============================================================================

/**
 * Run the full anchor pipeline:
 * 1. Collect unanchored receipt hashes from Supabase
 * 2. Build Merkle tree
 * 3. Store tree + proofs in DB
 * 4. Anchor root to Base L2
 * 5. Update receipts with batch reference
 *
 * @param {Object} supabase - Supabase service client
 * @returns {Object} batch summary
 */
export async function runAnchorBatch(supabase) {
  // 1. Collect unanchored receipt hashes
  const { data: unanchored, error: fetchErr } = await supabase
    .from('receipts')
    .select('id, receipt_id, receipt_hash')
    .is('anchor_batch_id', null)
    .order('created_at', { ascending: true })
    .limit(1000);

  if (fetchErr) throw new Error(`Failed to fetch unanchored receipts: ${fetchErr.message}`);
  if (!unanchored || unanchored.length === 0) {
    return { status: 'no_receipts', message: 'No unanchored receipts to process' };
  }

  // 2. Build Merkle tree
  const leafHashes = unanchored.map(r => r.receipt_hash);
  const tree = buildMerkleTree(leafHashes);

  // Generate batch ID
  const batchId = `batch_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

  // 3. Generate proofs for each receipt
  const proofs = unanchored.map((r, i) => ({
    receipt_id: r.receipt_id,
    proof: generateMerkleProof(tree.layers, i),
    leaf_index: i,
  }));

  // 4. Anchor to Base L2
  const anchorResult = await anchorToBase(batchId, tree.root);

  // 5. Store batch record
  const { error: batchErr } = await supabase
    .from('anchor_batches')
    .insert({
      batch_id: batchId,
      merkle_root: tree.root,
      leaf_count: tree.leafCount,
      tree_layers: tree.layers,
      transaction_hash: anchorResult.transactionHash,
      chain_id: anchorResult.chain,
      block_number: anchorResult.blockNumber || null,
      explorer_url: anchorResult.explorerUrl,
      skipped_onchain: anchorResult.skipped || false,
    });

  if (batchErr) {
    console.error('Failed to store batch:', batchErr);
    // Continue — the anchor tx is already on-chain
  }

  // 6. Update receipts with batch reference and proofs
  for (const p of proofs) {
    await supabase
      .from('receipts')
      .update({
        anchor_batch_id: batchId,
        merkle_proof: p.proof,
        merkle_leaf_index: p.leaf_index,
      })
      .eq('receipt_id', p.receipt_id);
  }

  return {
    status: 'anchored',
    batch_id: batchId,
    receipts_anchored: unanchored.length,
    merkle_root: tree.root,
    transaction_hash: anchorResult.transactionHash,
    explorer_url: anchorResult.explorerUrl,
    skipped_onchain: anchorResult.skipped || false,
  };
}
