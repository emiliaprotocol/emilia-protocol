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
import { sha256 } from '@/lib/crypto';
import { getBlockchainConfig, isProduction } from '@/lib/env';
import { resolveBlockchainSigner } from './blockchain-signing.js';
import { logger } from './logger.js';

// =============================================================================
// MERKLE TREE
// =============================================================================

// sha256 imported from @/lib/crypto

/**
 * Hash two nodes together in sorted order (canonical Merkle construction).
 * Sorting ensures the same proof regardless of leaf position.
 */
function hashPair(a, b) {
  const sorted = [a, b].sort();
  return sha256(sorted[0] + sorted[1]);
}

// EP-MERKLE-v2: RFC-6962-style domain separation, consistent with the
// document-anchor v2 in @emilia-protocol/verify. A tree-leaf can never collide
// with an internal node (distinct 0x00 / 0x01 prefixes), closing the leaf/branch
// second-preimage class on the on-chain anchor. Positional (not sorted), so the
// proof's `position` is load-bearing. sha256() updates utf8, so a '\x00'/'\x01'
// string prefix is exactly one 0x00/0x01 byte.
export const MERKLE_V2_ALG = 'EP-MERKLE-v2';
export const MERKLE_V1_ALG = 'EP-MERKLE-v1';
/** Tree-leaf for v2 = SHA-256(0x00 || receiptHashHex). */
function hashLeafV2(leafHex) {
  return sha256('\x00' + leafHex);
}
/** Internal node for v2 = SHA-256(0x01 || leftHex || rightHex), positional. */
function hashPairV2(left, right) {
  return sha256('\x01' + left + right);
}

/**
 * Build a Merkle tree from an array of leaf hashes.
 * Returns { root, layers, leafCount }.
 *
 * layers[0] = leaves, layers[n] = root
 * If odd number of leaves, the last leaf is promoted (not duplicated).
 */
export function buildMerkleTree(leafHashes, { v2 = false } = {}) {
  if (!leafHashes || leafHashes.length === 0) {
    return { root: null, layers: [], leafCount: 0, alg: v2 ? MERKLE_V2_ALG : MERKLE_V1_ALG };
  }

  const pair = v2 ? hashPairV2 : hashPair;
  // v2 hashes each input leaf with the 0x00 leaf-domain tag so a leaf can never
  // be presented as an internal node. layer[0] holds these tree-leaves.
  const treeLeaves = v2 ? leafHashes.map(hashLeafV2) : leafHashes;

  if (treeLeaves.length === 1) {
    return { root: treeLeaves[0], layers: [treeLeaves], leafCount: 1, alg: v2 ? MERKLE_V2_ALG : MERKLE_V1_ALG };
  }

  const layers = [treeLeaves];
  let currentLayer = treeLeaves;

  while (currentLayer.length > 1) {
    const nextLayer = [];
    for (let i = 0; i < currentLayer.length; i += 2) {
      if (i + 1 < currentLayer.length) {
        nextLayer.push(pair(currentLayer[i], currentLayer[i + 1]));
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
    leafCount: treeLeaves.length,
    alg: v2 ? MERKLE_V2_ALG : MERKLE_V1_ALG,
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
export function verifyMerkleProof(leafHash, proof, expectedRoot, { v2 = false } = {}) {
  if (typeof leafHash !== 'string' || !leafHash) return false;
  if (typeof expectedRoot !== 'string' || !expectedRoot) return false;
  if (!Array.isArray(proof)) return false;
  // Sanity check: proof depth should never exceed log2(1000 max batch size) ≈ 10
  if (proof.length > 20) return false;

  const pair = v2 ? hashPairV2 : hashPair;
  // v2: fold from the domain-separated tree-leaf; position is load-bearing.
  let current = v2 ? hashLeafV2(leafHash) : leafHash;

  for (const step of proof) {
    if (!step || typeof step.hash !== 'string' || !step.hash) return false;
    // v1 hashPair sorts (position informational); v2 hashPairV2 is positional.
    if (step.position !== 'left' && step.position !== 'right') return false;
    if (step.position === 'left') {
      current = pair(step.hash, current);
    } else {
      current = pair(current, step.hash);
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
  const config = getBlockchainConfig();
  return config?.network === 'mainnet' ? BASE_CHAIN : BASE_SEPOLIA;
}

/**
 * Anchor a Merkle root to Base L2.
 *
 * Sends a data-only transaction with calldata: EP:v1:{batchId}:{merkleRoot}
 *
 * Requires one configured signing provider:
 *   - env mode: EP_WALLET_PRIVATE_KEY (hex, no 0x prefix)
 *   - kms/hsm mode: a registered external blockchain signer
 *   - Small amount of ETH on Base for gas (~$0.01 per tx)
 *
 * @param {string} batchId - Unique batch identifier
 * @param {string} merkleRoot - The Merkle root to anchor
 * @param {{ v2?: boolean }} [options]
 * @returns {Promise<{ transactionHash: string|null, explorerUrl: string|null, chain: number, skipped?: boolean, reason?: string, blockNumber?: number, signing_provider?: * }>} anchor result, or throws
 */
export async function anchorToBase(batchId, merkleRoot, { v2 = false } = {}) {
  const config = getBlockchainConfig();
  // resolveBlockchainSigner's param type only allows signingKeyId?: string
  // (no null); getBlockchainConfig() reports absence as null, so normalize
  // here rather than loosening the signer's declared type.
  const signer = resolveBlockchainSigner(
    config
      ? {
          signingMode: config.signingMode,
          signingKeyId: config.signingKeyId ?? undefined,
          walletPrivateKey: config.walletPrivateKey,
        }
      : {},
  );
  if (!signer) {
    if (isProduction()) {
      // In production, silently skipping blockchain anchoring while the operator claims
      // "Merkle root published on Base L2" is a misleading claim. Throw to make the
      // misconfiguration visible immediately rather than silently compromising integrity.
      throw new Error(
        'No blockchain signing provider is configured. ' +
        'Set EP_WALLET_PRIVATE_KEY for env mode or register the configured KMS/HSM provider. ' +
        'Blockchain anchoring is required in production. ' +
        'Remove blockchain anchoring claims from your deployment if anchoring is not configured.'
      );
    }
    logger.warn('No blockchain signing provider configured — skipping on-chain anchor (non-production only)');
    return {
      transactionHash: null,
      explorerUrl: null,
      chain: getChain().id,
      skipped: true,
      reason: 'EP_WALLET_PRIVATE_KEY or external blockchain signing provider not configured',
    };
  }

  const chain = getChain();
  const calldata = `EP:${v2 ? 'v2' : 'v1'}:${batchId}:${merkleRoot}`;
  const hexData = '0x' + Buffer.from(calldata).toString('hex');

  try {
    // Dynamic import viem (tree-shakeable, no ethers bloat)
    const { createWalletClient, createPublicClient, http } = await import('viem');
    const { privateKeyToAccount, toAccount } = await import('viem/accounts');
    const { base, baseSepolia } = await import('viem/chains');

    const selectedChain = chain.id === 8453 ? base : baseSepolia;
    // signer.createAccount()'s factories.toAccount is intentionally typed
    // with a minimal source shape (BlockchainAccountFactories in
    // blockchain-signing.ts), narrower than viem's real generic toAccount()
    // signature (which also demands signMessage/signTypedData on
    // CustomSource). This signer only ever constructs a signTransaction-only
    // source for anchoring data-only txs, so the extra fields required by
    // viem's CustomSource are never needed at runtime; cast at this call
    // boundary rather than widening the signer's declared factory type.
    const account = /** @type {import('viem').Account} */ (
      signer.createAccount({
        privateKeyToAccount,
        toAccount: (source) => toAccount(/** @type {import('viem/accounts').AccountSource} */ (source)),
      })
    );

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
    // viem's SendTransactionParameters is a large discriminated union (legacy,
    // EIP-1559, EIP-4844 blob, etc.); a plain data-only tx object structurally
    // matches multiple overload legs and checkJs can't pick one without a cast.
    const hash = await walletClient.sendTransaction(/** @type {any} */ ({
      to: account.address,
      value: 0n,
      data: /** @type {`0x${string}`} */ (hexData),
    }));

    // Wait for confirmation
    const receipt = await publicClient.waitForTransactionReceipt({ hash });

    return {
      transactionHash: hash,
      explorerUrl: `${chain.explorerUrl}/tx/${hash}`,
      chain: chain.id,
      blockNumber: Number(receipt.blockNumber),
      skipped: false,
      signing_provider: signer.getMetadata(),
    };
  } catch (err) {
    // Log only the message — never log the full error object which may contain key material
    logger.error('Base L2 anchor error:', err.message);
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
 * @returns {Promise<Object>} batch summary
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

  // 2. Build Merkle tree. New anchors default to EP-MERKLE-v2 (domain-separated);
  // pre-existing v1 batches keep verifying as v1 (anchor_batches.merkle_alg).
  const leafHashes = unanchored.map(r => r.receipt_hash);
  const tree = buildMerkleTree(leafHashes, { v2: true });

  // Generate batch ID
  const batchId = `batch_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

  // 3. Generate proofs for each receipt
  const proofs = unanchored.map((r, i) => ({
    receipt_id: r.receipt_id,
    proof: generateMerkleProof(tree.layers, i),
    leaf_index: i,
  }));

  // 4. Persist the batch row FIRST (pending), BEFORE any on-chain transaction.
  // This eliminates the DB/chain split-brain: if the DB write fails we abort
  // with nothing on chain; and once the tx is sent the row already exists, so a
  // receipt can never reference a batch_id that joins to nothing. Only batch_id
  // and merkle_root are NOT NULL — the on-chain fields are filled in step 6.
  const { error: insertErr } = await supabase
    .from('anchor_batches')
    .insert({
      batch_id: batchId,
      merkle_root: tree.root,
      leaf_count: tree.leafCount,
      tree_layers: tree.layers,
      merkle_alg: tree.alg,
    });

  if (insertErr) {
    // Nothing has been anchored on chain yet — abort cleanly, no inconsistency.
    logger.error('Anchor batch DB pre-insert failed; no on-chain tx attempted.', insertErr);
    throw new Error(`Anchor batch DB pre-insert failed: ${insertErr.message}`);
  }

  // 5. Anchor to Base L2 (the irreversible step). Tag calldata EP:v2:.
  const anchorResult = await anchorToBase(batchId, tree.root, { v2: tree.alg === MERKLE_V2_ALG });

  // 6. Confirm the batch row with the on-chain details.
  const { error: confirmErr } = await supabase
    .from('anchor_batches')
    .update({
      transaction_hash: anchorResult.transactionHash,
      chain_id: anchorResult.chain,
      block_number: anchorResult.blockNumber || null,
      explorer_url: anchorResult.explorerUrl,
      skipped_onchain: anchorResult.skipped || false,
    })
    .eq('batch_id', batchId);

  if (confirmErr) {
    // The tx is on chain AND the batch row exists (with the merkle_root). This is
    // reconcilable, NOT split-brain: ops can backfill the tx hash by matching the
    // root on chain. Receipts are NOT marked until the row is confirmed.
    logger.error(
      `Anchor batch on-chain (txHash: ${anchorResult.transactionHash}) but DB confirm failed — batch row exists as pending (merkle_root: ${tree.root}); reconcilable. Receipts NOT marked.`,
      confirmErr,
    );
    throw new Error(
      `Anchor batch DB confirm failed: ${confirmErr.message}. On-chain tx: ${anchorResult.transactionHash}`,
    );
  }

  // 7. Bulk-update all receipts in a single RPC call (migration 075).
  // Replaces the previous N+1 serial UPDATE loop.
  const updates = proofs.map(p => ({
    receipt_id:        p.receipt_id,
    anchor_batch_id:   batchId,
    merkle_proof:      p.proof,
    merkle_leaf_index: p.leaf_index,
  }));

  const { error: receiptErr } = await supabase
    .rpc('bulk_update_receipt_anchors', { p_updates: updates });

  if (receiptErr) {
    logger.error('Failed to update receipt anchor references:', receiptErr);
    throw new Error(`Receipt anchor update failed: ${receiptErr.message}`);
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
