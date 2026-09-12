// SPDX-License-Identifier: Apache-2.0

// Build-time imports intentionally name the exact restored files. This keeps
// the sealed adapter below Crossing Lab's size limit and avoids pulling the
// broad viem and verify-insight-receipt entry points into the offline bundle.
import canonicalizeJcs from './node_modules/canonicalize/lib/canonicalize.js';
import { secp256k1 } from './node_modules/@noble/curves/esm/secp256k1.js';
import { concat } from './node_modules/viem/_esm/utils/data/concat.js';
import { decodeFunctionData } from './node_modules/viem/_esm/utils/abi/decodeFunctionData.js';
import { encodeAbiParameters } from './node_modules/viem/_esm/utils/abi/encodeAbiParameters.js';
import { hashTypedData } from './node_modules/viem/_esm/utils/signature/hashTypedData.js';
import { isAddress } from './node_modules/viem/_esm/utils/address/isAddress.js';
import { keccak256 } from './node_modules/viem/_esm/utils/hash/keccak256.js';
import { sha256 } from './node_modules/viem/_esm/utils/hash/sha256.js';
import { toBytes } from './node_modules/viem/_esm/utils/encoding/toBytes.js';
import { toHex } from './node_modules/viem/_esm/utils/encoding/toHex.js';
import receiptSchemas from './node_modules/verify-insight-receipt/dist/schemas.js';

const { V3_DOMAIN, V3_PRIMARY_TYPE, V3_TYPES, toV3Message } = receiptSchemas;

export {
  V3_DOMAIN,
  V3_PRIMARY_TYPE,
  V3_TYPES,
  canonicalizeJcs,
  concat,
  decodeFunctionData,
  encodeAbiParameters,
  hashTypedData,
  isAddress,
  keccak256,
  secp256k1,
  sha256,
  toBytes,
  toHex,
  toV3Message,
};
