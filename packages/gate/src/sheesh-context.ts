// SPDX-License-Identifier: Apache-2.0

/**
 * EMILIA-owned interop profile for Justin Kintzele's documented SHEESH/SOMA
 * repository boundary. This is not a SHEESH standard or conformance claim.
 */
import crypto from 'node:crypto';

import type { MemoryProjectionAdapterKey } from '@emilia-protocol/verify/memory-projection';

import { createMemoryProjectionContextProvider } from './memory-projection-context.js';
import {
  absoluteUri,
  boundedString,
  canonicalBytes,
  createNativeMemoryProjection,
  sha256,
  type NativeMemoryProjectionOutput,
  type NativeSourceVerifier,
} from './native-memory-source.js';

export const SHEESH_PROVIDER_ID = 'sheesh-soma';
export const SHEESH_SOURCE_PROFILE = 'urn:emilia:source-profile:sheesh-soma:v0.1';
export const SHEESH_CONTEXT_FRAME_PROFILE = 'urn:emilia:context-frame:sheesh-soma:v0.1';
export const SHEESH_SOURCE_ENVELOPE_VERSION = 'EMILIA-SHEESH-SOURCE-v0.1';
export const SHEESH_PROFILE_STATUS = 'EMILIA_INTEROP_PROFILE_NOT_SHEESH_STANDARD';

const SHEESH_SOURCE_KEYS = new Set([
  '@version',
  'profile_status',
  'repository_uri',
  'revision',
  'path',
  'content_digest',
  'content_b64u',
]);

export interface SheeshContextProviderOptions {
  adapterKeys: Record<string, MemoryProjectionAdapterKey>;
  statusCheckedAt: string | (() => string);
}

export interface SheeshMemorySourceInput {
  repositoryUri: string;
  revision: string;
  path: string;
  sourceBytes: Uint8Array;
  contextFragmentBytes: Uint8Array;
}

export interface SheeshMemoryProjectionInput {
  projectionId: string;
  createdAt: string;
  adapter: {
    id: string;
    keyId: string;
    privateKey: crypto.KeyLike;
  };
  selectionContext: {
    recallRequestBytes: Uint8Array;
    selectionPolicyBytes: Uint8Array;
    trustSnapshotBytes: Uint8Array;
    trustEvaluatedAt: string;
  };
  sources: SheeshMemorySourceInput[];
  verifyNativeSource?: NativeSourceVerifier;
  exclusions?: {
    authenticationFailed?: number;
    schemaInvalid?: number;
    policyFiltered?: number;
    contextLimit?: number;
  };
}

function safeSheeshPath(value: unknown): value is string {
  if (!boundedString(value, 1024)
      || value.startsWith('/')
      || value.includes('\\')
      || value.split('/').some((part) => part === '' || part === '.' || part === '..')) return false;
  const leaf = value.split('/').at(-1)!;
  return leaf === 'somatic_index.json' || leaf.endsWith('.cogobj') || leaf.endsWith('.cogobj.enc');
}

function validateSheeshSourceEnvelope(value: Readonly<Record<string, any>>): void {
  const keys = Object.keys(value);
  if (keys.length !== SHEESH_SOURCE_KEYS.size
      || keys.some((key) => !SHEESH_SOURCE_KEYS.has(key))
      || value['@version'] !== SHEESH_SOURCE_ENVELOPE_VERSION
      || value.profile_status !== SHEESH_PROFILE_STATUS
      || !absoluteUri(value.repository_uri)
      || !boundedString(value.revision, 256)
      || !safeSheeshPath(value.path)) {
    throw new TypeError('SHEESH source envelope invalid');
  }
}

export function createSheeshContextProvider(options: SheeshContextProviderOptions) {
  return createMemoryProjectionContextProvider({
    ...options,
    providerId: SHEESH_PROVIDER_ID,
    profileId: SHEESH_SOURCE_PROFILE,
    contextFrameProfile: SHEESH_CONTEXT_FRAME_PROFILE,
  });
}

/** Produce one signed Memory Projection Record from exact SHEESH/SOMA files. */
export function createSheeshMemoryProjection(
  input: SheeshMemoryProjectionInput,
): NativeMemoryProjectionOutput {
  if (!Array.isArray(input?.sources) || input.sources.length === 0) {
    throw new TypeError('SHEESH sources required');
  }
  const sources = input.sources.map((source) => {
    if (!absoluteUri(source.repositoryUri)
        || !boundedString(source.revision, 256)
        || !safeSheeshPath(source.path)
        || !(source.sourceBytes instanceof Uint8Array)
        || !(source.contextFragmentBytes instanceof Uint8Array)) {
      throw new TypeError('SHEESH source path invalid');
    }
    const bytes = Buffer.from(source.sourceBytes);
    return {
      sourceEnvelope: {
        '@version': SHEESH_SOURCE_ENVELOPE_VERSION,
        profile_status: SHEESH_PROFILE_STATUS,
        repository_uri: source.repositoryUri,
        revision: source.revision,
        path: source.path,
        content_digest: sha256(bytes),
        content_b64u: bytes.toString('base64url'),
      },
      contextFragmentBytes: Buffer.from(source.contextFragmentBytes),
    };
  });
  return createNativeMemoryProjection({
    ...input,
    providerId: SHEESH_PROVIDER_ID,
    sourceProfile: SHEESH_SOURCE_PROFILE,
    contextFrameProfile: SHEESH_CONTEXT_FRAME_PROFILE,
    sources,
    validateSourceEnvelope: validateSheeshSourceEnvelope,
  });
}

/** Stable bytes for independent adapter tests and offline packet inspection. */
export function sheeshSourceEnvelopeBytes(source: SheeshMemorySourceInput): Buffer {
  if (!absoluteUri(source.repositoryUri)
      || !boundedString(source.revision, 256)
      || !safeSheeshPath(source.path)) {
    throw new TypeError('SHEESH source path invalid');
  }
  const bytes = Buffer.from(source.sourceBytes);
  return canonicalBytes({
    '@version': SHEESH_SOURCE_ENVELOPE_VERSION,
    profile_status: SHEESH_PROFILE_STATUS,
    repository_uri: source.repositoryUri,
    revision: source.revision,
    path: source.path,
    content_digest: sha256(bytes),
    content_b64u: bytes.toString('base64url'),
  });
}

export default Object.freeze({
  createSheeshContextProvider,
  createSheeshMemoryProjection,
});
