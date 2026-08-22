// @ts-nocheck
// SPDX-License-Identifier: Apache-2.0
import { createMemoryProjectionContextProvider } from './memory-projection-context.js';
import { boundedString, createNativeMemoryProjection, sha256, } from './native-memory-source.js';
export const ZEP_PROVIDER_ID = 'zep';
export const ZEP_SOURCE_PROFILE = 'urn:emilia:source-profile:zep-context:v0.1';
export const ZEP_CONTEXT_FRAME_PROFILE = 'urn:emilia:context-frame:zep-context:v0.1';
export const ZEP_SOURCE_ENVELOPE_VERSION = 'EMILIA-ZEP-SOURCE-v0.1';
export const ZEP_PROFILE_STATUS = 'EMILIA_INTEROP_PROFILE_NOT_ZEP_STANDARD';
const ZEP_SOURCE_KEYS = new Set([
    '@version',
    'profile_status',
    'project_id',
    'graph_id',
    'episode_uuid',
    'content_digest',
    'content_b64u',
]);
export function createZepContextProvider(options) {
    return createMemoryProjectionContextProvider({
        ...options,
        providerId: ZEP_PROVIDER_ID,
        profileId: ZEP_SOURCE_PROFILE,
        contextFrameProfile: ZEP_CONTEXT_FRAME_PROFILE,
    });
}
function validateZepSourceEnvelope(value) {
    const keys = Object.keys(value);
    if (keys.length !== ZEP_SOURCE_KEYS.size
        || keys.some((key) => !ZEP_SOURCE_KEYS.has(key))
        || value['@version'] !== ZEP_SOURCE_ENVELOPE_VERSION
        || value.profile_status !== ZEP_PROFILE_STATUS
        || !boundedString(value.project_id, 256)
        || !boundedString(value.graph_id, 512)
        || !boundedString(value.episode_uuid, 256)) {
        throw new TypeError('Zep source envelope invalid');
    }
}
/** Produce one signed Memory Projection Record from exact Zep response bytes. */
export function createZepMemoryProjection(input) {
    if (!Array.isArray(input?.sources) || input.sources.length === 0) {
        throw new TypeError('Zep sources required');
    }
    const sources = input.sources.map((source) => {
        if (!boundedString(source.projectId, 256)
            || !boundedString(source.graphId, 512)
            || !boundedString(source.episodeUuid, 256)
            || !(source.sourceBytes instanceof Uint8Array)
            || !(source.contextFragmentBytes instanceof Uint8Array)) {
            throw new TypeError('Zep source invalid');
        }
        const bytes = Buffer.from(source.sourceBytes);
        return {
            sourceEnvelope: {
                '@version': ZEP_SOURCE_ENVELOPE_VERSION,
                profile_status: ZEP_PROFILE_STATUS,
                project_id: source.projectId,
                graph_id: source.graphId,
                episode_uuid: source.episodeUuid,
                content_digest: sha256(bytes),
                content_b64u: bytes.toString('base64url'),
            },
            contextFragmentBytes: Buffer.from(source.contextFragmentBytes),
        };
    });
    return createNativeMemoryProjection({
        ...input,
        providerId: ZEP_PROVIDER_ID,
        sourceProfile: ZEP_SOURCE_PROFILE,
        contextFrameProfile: ZEP_CONTEXT_FRAME_PROFILE,
        sources,
        validateSourceEnvelope: validateZepSourceEnvelope,
    });
}
export default Object.freeze({
    createZepContextProvider,
    createZepMemoryProjection,
});
//# sourceMappingURL=zep-context.js.map