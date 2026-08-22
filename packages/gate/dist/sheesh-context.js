// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
import { createMemoryProjectionContextProvider } from './memory-projection-context.js';
import { absoluteUri, boundedString, canonicalBytes, createNativeMemoryProjection, sha256, } from './native-memory-source.js';
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
function safeSheeshPath(value) {
    if (!boundedString(value, 1024)
        || value.startsWith('/')
        || value.includes('\\')
        || value.split('/').some((part) => part === '' || part === '.' || part === '..'))
        return false;
    const leaf = value.split('/').at(-1);
    return leaf === 'somatic_index.json' || leaf.endsWith('.cogobj') || leaf.endsWith('.cogobj.enc');
}
function validateSheeshSourceEnvelope(value) {
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
export function createSheeshContextProvider(options) {
    return createMemoryProjectionContextProvider({
        ...options,
        providerId: SHEESH_PROVIDER_ID,
        profileId: SHEESH_SOURCE_PROFILE,
        contextFrameProfile: SHEESH_CONTEXT_FRAME_PROFILE,
    });
}
/** Produce one signed Memory Projection Record from exact SHEESH/SOMA files. */
export function createSheeshMemoryProjection(input) {
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
export function sheeshSourceEnvelopeBytes(source) {
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
//# sourceMappingURL=sheesh-context.js.map