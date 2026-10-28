// Generated from orcarouter.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * OrcaRouter Cyber Inference — named provider wiring.
 *
 * @license Apache-2.0
 *
 * OrcaRouter is an OpenAI-compatible AI gateway. Authentication and inference
 * live on different public origins:
 *
 *   auth + code exchange  https://www.orcarouter.ai
 *   inference + catalog   https://api.orcarouter.ai/v1
 *
 * Both origins are configurable, and one public origin is never derived from
 * the other by swapping hostnames. Explicit overrides win over the shared
 * self-hosted base; remote origins must be HTTPS, HTTP is accepted only for
 * loopback development.
 *
 * The model catalog is the only source of truth: GET <api>/models. The small
 * seed below exists so a fresh install survives a catalog outage, and it is
 * never merged into a successful live response.
 *
 * Nothing in this module logs or returns a credential.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { getOrcaRouterEnv } from '../env.js';
import { logger } from '../logger.js';
export const ORCAROUTER_PROVIDER_ID = 'orcarouter';
export const ORCAROUTER_DISPLAY_NAME = 'OrcaRouter Cyber Inference';
export const ORCAROUTER_DEFAULT_AUTH_ORIGIN = 'https://www.orcarouter.ai';
export const ORCAROUTER_DEFAULT_API_ORIGIN = 'https://api.orcarouter.ai/v1';
/** Default model. Any OrcaRouter key can route it. */
export const ORCAROUTER_DEFAULT_MODEL = 'orcarouter/auto';
/** Default embedding model when the operator has not selected one. */
export const ORCAROUTER_DEFAULT_EMBEDDING_MODEL = 'openai/text-embedding-3-small';
/** General fallback when a task is not cyber-specific. */
export const ORCAROUTER_FALLBACK_MODEL = 'orcarouter/fusion';
/** Dedicated cyber models for verified security teams (business verification). */
export const ORCAROUTER_CYBER_MODELS = Object.freeze([
    'orcacyber-ultra-1.0',
    'orcacyber-zero-1.5',
]);
const TEXT_ENDPOINTS = Object.freeze(['openai', 'anthropic', 'gemini', 'openai-response']);
const KNOWN_ENDPOINTS = Object.freeze([
    ...TEXT_ENDPOINTS,
    'embeddings',
    'image-generation',
    'openai-video',
    'jina-rerank',
    'systemone',
]);
const CAPABILITY_ENDPOINTS = {
    embedding: 'embeddings',
    image: 'image-generation',
    video: 'openai-video',
    rerank: 'jina-rerank',
};
export const ORCAROUTER_MAX_CATALOG_BYTES = 1_000_000;
export const ORCAROUTER_MAX_CATALOG_ITEMS = 500;
const CATALOG_CACHE_TTL_MS = 5 * 60 * 1000;
class ConfigError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.name = 'OrcaRouterConfigError';
        this.code = code;
    }
}
/**
 * Verified cold-start seed. Kept deliberately small and each entry carries the
 * metadata the UI and filters rely on. It is used only when live discovery
 * fails; a successful live response is authoritative and never merged with it.
 */
const SEED = {
    chat: [
        seedModel('orcarouter/auto', 'OrcaRouter Auto', 200_000, ['text', 'image'], true, ['low', 'medium', 'high', 'xhigh']),
        seedModel('orcarouter/fusion', 'OrcaRouter Fusion', 1_000_000, ['text', 'image'], true, ['low', 'medium', 'high']),
        seedModel('orcacyber-ultra-1.0', 'OrcaCyber Ultra', 200_000, ['text'], true, ['low', 'medium', 'high', 'xhigh']),
        seedModel('orcacyber-zero-1.5', 'OrcaCyber Zero', 200_000, ['text'], true, ['low', 'medium', 'high']),
        seedModel('openai/gpt-5.5', 'OpenAI: GPT-5.5', 400_000, ['text', 'image'], true, ['low', 'medium', 'high', 'xhigh']),
        seedModel('anthropic/claude-opus-4.8', 'Anthropic: Claude Opus 4.8', 200_000, ['text', 'image'], true, ['low', 'medium', 'high']),
        seedModel('google/gemini-3.5-flash', 'Google: Gemini 3.5 Flash', 1_000_000, ['text', 'image', 'audio'], true, ['low', 'medium', 'high']),
        seedModel('deepseek/deepseek-v4-pro', 'DeepSeek: V4 Pro', 256_000, ['text'], true, ['low', 'medium', 'high']),
    ],
    embedding: [
        seedModel('openai/text-embedding-3-small', 'OpenAI: Text Embedding 3 Small', 8_191, ['text'], false, []),
        seedModel('google/gemini-embedding-001', 'Google: Gemini Embedding 001', 2_048, ['text'], false, []),
    ],
    image: [
        seedModel('openai/gpt-image-1', 'OpenAI: GPT Image 1', null, ['text', 'image'], false, []),
    ],
    video: [
        seedModel('kling/kling-v3', 'Kling: V3', null, ['text', 'image'], false, []),
    ],
    rerank: [],
};
function seedModel(id, name, contextLength, inputModalities, reasoning, effort) {
    return {
        id,
        name,
        context_length: contextLength,
        input_modalities: inputModalities,
        output_modalities: ['text'],
        endpoint_types: ['openai'],
        reasoning,
        reasoning_efforts: effort,
        capability: 'chat',
        verified_seed: true,
    };
}
/**
 * A seed entry must survive the same capability filter as a live entry.
 * Endpoint and output metadata therefore come from the capability, not from
 * the chat-shaped defaults seedModel() uses. Without this, embedding, image,
 * and video seeds were removed by their own filter and the fallback was empty.
 */
const SEED_ENDPOINTS = {
    chat: ['openai'],
    embedding: ['embeddings'],
    image: ['image-generation'],
    video: ['openai-video'],
    rerank: ['jina-rerank'],
};
const SEED_OUTPUT_MODALITIES = {
    chat: ['text'],
    embedding: ['embedding'],
    image: ['image'],
    video: ['video'],
    rerank: ['text'],
};
for (const capability of Object.keys(SEED)) {
    for (const model of SEED[capability]) {
        model.capability = capability;
        model.endpoint_types = [...SEED_ENDPOINTS[capability]];
        model.output_modalities = [...SEED_OUTPUT_MODALITIES[capability]];
    }
}
export function seedModels(capability) {
    return SEED[capability].map((model) => ({ ...model, input_modalities: [...model.input_modalities] }));
}
function isLoopback(hostname) {
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}
/**
 * Validate and normalize one origin. Rejects embedded credentials, query
 * strings, fragments, and non-HTTPS remote origins.
 */
export function normalizeOrcaOrigin(raw, label) {
    let url;
    try {
        url = new URL(String(raw).trim());
    }
    catch {
        throw new ConfigError('invalid_origin', `${label} is not a valid URL`);
    }
    if (url.username || url.password) {
        throw new ConfigError('invalid_origin', `${label} must not embed credentials`);
    }
    if (url.search || url.hash) {
        throw new ConfigError('invalid_origin', `${label} must not carry a query or fragment`);
    }
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback(url.hostname))) {
        throw new ConfigError('insecure_origin', `${label} must use HTTPS (HTTP is allowed only for loopback)`);
    }
    url.pathname = url.pathname.replace(/\/+$/, '');
    return url.toString().replace(/\/$/, '');
}
/**
 * Resolve the two public origins.
 *
 * Explicit auth/API overrides win. ORCA_BASE_URL is a shared self-hosted base:
 * it serves authentication at its root and inference under /v1.
 */
export function resolveOrcaRouterOrigins(env = getOrcaRouterEnv()) {
    const shared = env.sharedBaseOverride
        ? normalizeOrcaOrigin(env.sharedBaseOverride, 'ORCA_BASE_URL')
        : null;
    const auth = env.authBaseOverride
        ? normalizeOrcaOrigin(env.authBaseOverride, 'ORCAROUTER_AUTH_BASE_URL')
        : shared || ORCAROUTER_DEFAULT_AUTH_ORIGIN;
    const api = env.apiBaseOverride
        ? normalizeOrcaOrigin(env.apiBaseOverride, 'ORCAROUTER_API_BASE_URL')
        : shared
            ? `${shared}/v1`
            : ORCAROUTER_DEFAULT_API_ORIGIN;
    return { auth, api };
}
const memoryCache = new Map();
const MAX_MEMORY_CATALOGS = 64;
function rememberCatalog(identity, models) {
    const now = Date.now();
    for (const [key, entry] of memoryCache) {
        if (now - entry.at >= CATALOG_CACHE_TTL_MS)
            memoryCache.delete(key);
    }
    memoryCache.delete(identity);
    while (memoryCache.size >= MAX_MEMORY_CATALOGS) {
        const oldest = memoryCache.keys().next().value;
        if (oldest === undefined)
            break;
        memoryCache.delete(oldest);
    }
    memoryCache.set(identity, { at: now, models });
}
function stateDirectory(explicit) {
    const env = getOrcaRouterEnv();
    return explicit || env.stateDir || path.join(process.cwd(), '.emilia', 'orcarouter');
}
function cachePath(stateDir, capability) {
    return path.join(stateDir, `catalog-${capability}.json`);
}
function readLastKnownGood(stateDir, capability, identity) {
    try {
        const parsed = JSON.parse(fs.readFileSync(cachePath(stateDir, capability), 'utf8'));
        if (parsed?.identity !== identity || !Array.isArray(parsed?.models))
            return null;
        return parsed.models.map((item) => normalizeModel(item, capability)).filter(Boolean);
    }
    catch {
        return null;
    }
}
function writeLastKnownGood(stateDir, capability, identity, models) {
    try {
        fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
        const target = cachePath(stateDir, capability);
        const temporary = `${target}.${process.pid}.tmp`;
        fs.writeFileSync(temporary, JSON.stringify({ capability, identity, models, at: new Date().toISOString() }), {
            encoding: 'utf8',
            mode: 0o600,
        });
        fs.renameSync(temporary, target);
    }
    catch (error) {
        logger.warn('orcarouter: could not persist last-known-good catalog', { error: error?.message });
    }
}
function boundedErrorMessage(status) {
    if (status === 401)
        return 'authentication_failed';
    if (status === 403)
        return 'forbidden';
    if (status === 429)
        return 'rate_limited';
    if (status >= 500)
        return 'provider_unavailable';
    return `catalog_http_${status}`;
}
async function readBoundedText(res, maxBytes) {
    const declared = Number(res.headers?.get?.('content-length') || 0);
    if (Number.isFinite(declared) && declared > maxBytes) {
        throw new Error('catalog_response_too_large');
    }
    const body = res.body;
    if (body && typeof body.getReader === 'function') {
        const reader = body.getReader();
        const chunks = [];
        let total = 0;
        for (;;) {
            const { done, value } = await reader.read();
            if (done)
                break;
            total += value.byteLength;
            if (total > maxBytes) {
                try {
                    await reader.cancel();
                }
                catch { /* already closed */ }
                throw new Error('catalog_response_too_large');
            }
            chunks.push(value);
        }
        return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString('utf8');
    }
    const text = await res.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes)
        throw new Error('catalog_response_too_large');
    return text;
}
function normalizeModalities(value) {
    if (!Array.isArray(value))
        return [];
    return [...new Set(value.filter((item) => typeof item === 'string' && item.length <= 32))];
}
function normalizeModel(raw, capability = 'chat') {
    if (!raw || typeof raw !== 'object')
        return null;
    const id = typeof raw.id === 'string' ? raw.id.trim() : '';
    if (!id || id.length > 200 || !/^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/.test(id))
        return null;
    const rawEndpoints = raw.supported_endpoint_types ?? raw.endpoint_types;
    const endpoints = [];
    if (Array.isArray(rawEndpoints)) {
        for (const item of rawEndpoints) {
            if (typeof item === 'string' && KNOWN_ENDPOINTS.includes(item) && !endpoints.includes(item)) {
                endpoints.push(item);
            }
        }
    }
    const architecture = raw.architecture && typeof raw.architecture === 'object' ? raw.architecture : {};
    // Idempotent: a last-known-good entry is already normalized, so modality
    // lists may arrive on the entry itself rather than under `architecture`.
    const rawInputModalities = architecture.input_modalities ?? raw.input_modalities;
    const rawOutputModalities = architecture.output_modalities ?? raw.output_modalities;
    const parameters = Array.isArray(raw.supported_parameters) ? raw.supported_parameters : [];
    const reasoning = parameters.includes('reasoning')
        || (Array.isArray(raw.reasoning_efforts) && raw.reasoning_efforts.length > 0);
    const efforts = [];
    if (Array.isArray(raw.reasoning_efforts)) {
        for (const item of raw.reasoning_efforts) {
            if (typeof item === 'string' && item.length <= 16 && !efforts.includes(item)) {
                efforts.push(item);
            }
        }
    }
    const contextLength = Number.isFinite(raw.context_length) && raw.context_length > 0
        ? Math.min(Math.trunc(raw.context_length), 100_000_000)
        : null;
    return {
        id,
        name: typeof raw.name === 'string' && raw.name.trim() ? raw.name.trim().slice(0, 200) : id,
        context_length: contextLength,
        input_modalities: normalizeModalities(rawInputModalities),
        output_modalities: normalizeModalities(rawOutputModalities),
        endpoint_types: endpoints,
        reasoning,
        reasoning_efforts: efforts,
        capability,
        verified_seed: false,
    };
}
/**
 * Apply one entry's capability filter. Rules come from catalog metadata only —
 * a model name never implies a capability.
 */
export function modelMatches(model, capability, modality) {
    const endpoints = model.endpoint_types;
    if (capability === 'chat') {
        if (!endpoints.some((endpoint) => TEXT_ENDPOINTS.includes(endpoint)))
            return false;
        // A model that explicitly declares non-text output is not a chat model.
        // Aggregator entries that omit output modalities are still accepted.
        if (model.output_modalities.length && !model.output_modalities.includes('text'))
            return false;
        if (modality && modality !== 'text') {
            if (!model.input_modalities.length)
                return false;
            if (!model.input_modalities.includes(modality))
                return false;
        }
        return true;
    }
    const required = CAPABILITY_ENDPOINTS[capability];
    return endpoints.includes(required);
}
function dedupe(models) {
    const seen = new Set();
    const result = [];
    for (const model of models) {
        if (seen.has(model.id))
            continue;
        seen.add(model.id);
        result.push(model);
    }
    return result;
}
/**
 * Discover the catalog for one capability.
 *
 * Live success is authoritative. On failure the verified seed (or a persisted
 * last-known-good catalog from this deployment) keeps the selector usable and
 * is marked degraded. Neither fallback is ever mixed into a live result.
 */
export async function discoverOrcaRouterModels(options = {}) {
    const env = options.env || getOrcaRouterEnv();
    const capability = options.capability || 'chat';
    const origins = options.origins || resolveOrcaRouterOrigins(env);
    const catalogSource = `${origins.api}/models?capability=${capability}`;
    const credential = options.credential || (env.apiKey
        ? { key: env.apiKey, generation: 'env', source: 'env' }
        : null);
    const allowSeed = options.allowSeed !== false;
    const stateDir = stateDirectory(options.stateDir);
    // A generation alone is insufficient: environment credentials use `env`.
    // Persist only this digest, never the key. Legacy unbound caches are ignored.
    const identity = crypto.createHash('sha256').update(JSON.stringify([
        path.resolve(stateDir), origins.api, capability,
        credential?.source, credential?.generation, credential?.key,
    ])).digest('hex');
    const degraded = (error) => {
        const lastKnown = options.useCache === false ? null : readLastKnownGood(stateDir, capability, identity);
        if (lastKnown && lastKnown.length) {
            const filtered = lastKnown.filter((model) => modelMatches(model, capability, options.modality));
            if (filtered.length) {
                return { models: filtered, capability, source: 'last-known-good', degraded: true, error, catalog_source: catalogSource };
            }
        }
        if (allowSeed) {
            const seed = seedModels(capability).filter((model) => modelMatches(model, capability, options.modality));
            return { models: seed, capability, source: 'seed', degraded: true, error, catalog_source: catalogSource };
        }
        return { models: [], capability, source: 'seed', degraded: true, error, catalog_source: catalogSource };
    };
    if (!credential?.key)
        return degraded('not_configured');
    if (options.useCache !== false) {
        const cached = memoryCache.get(identity);
        if (cached && Date.now() - cached.at < CATALOG_CACHE_TTL_MS) {
            return {
                models: cached.models.filter((model) => modelMatches(model, capability, options.modality)),
                capability,
                source: 'live',
                degraded: false,
                error: null,
                catalog_source: catalogSource,
            };
        }
    }
    const fetchImpl = options.fetchImpl || fetch;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 8_000);
    try {
        const res = await fetchImpl(catalogSource, {
            method: 'GET',
            headers: { authorization: `Bearer ${credential.key}`, accept: 'application/json' },
            signal: controller.signal,
            redirect: 'error',
        });
        if (!res.ok)
            return degraded(boundedErrorMessage(res.status));
        const text = await readBoundedText(res, ORCAROUTER_MAX_CATALOG_BYTES);
        let payload;
        try {
            payload = JSON.parse(text);
        }
        catch {
            return degraded('catalog_malformed');
        }
        const data = Array.isArray(payload?.data) ? payload.data : null;
        if (!data)
            return degraded('catalog_malformed');
        // The cache and the last-known-good file hold the COMPLETE catalog for the
        // capability, never a per-request modality slice: an image-filtered request
        // must not hide text-only models from the next unfiltered request. Filtering
        // happens on the way out, every time.
        const complete = dedupe(data
            .slice(0, ORCAROUTER_MAX_CATALOG_ITEMS)
            .map((item) => normalizeModel(item, capability))
            .filter((model) => model !== null && modelMatches(model, capability)));
        if (!complete.length)
            return degraded('catalog_empty');
        rememberCatalog(identity, complete);
        if (options.useCache !== false)
            writeLastKnownGood(stateDir, capability, identity, complete);
        return {
            models: complete.filter((model) => modelMatches(model, capability, options.modality)),
            capability,
            source: 'live',
            degraded: false,
            error: null,
            catalog_source: catalogSource,
        };
    }
    catch (error) {
        const reason = error?.name === 'AbortError'
            ? 'catalog_timeout'
            : error?.message === 'catalog_response_too_large'
                ? 'catalog_too_large'
                : 'catalog_network_error';
        return degraded(reason);
    }
    finally {
        clearTimeout(timeout);
    }
}
/** Clear the process-local catalog cache (used by tests and manual refresh). */
export function resetOrcaRouterCatalogCache() {
    memoryCache.clear();
}
/** One OpenAI-compatible chat completion. Never logs headers or bodies. */
export async function orcaRouterChatCompletion({ apiKey, origins, model, system, user, maxTokens, temperature, signal, fetchImpl = fetch, }) {
    const response = await fetchImpl(`${origins.api}/chat/completions`, {
        method: 'POST',
        headers: {
            authorization: `Bearer ${apiKey}`,
            'content-type': 'application/json',
            accept: 'application/json',
        },
        body: JSON.stringify({
            model,
            max_tokens: maxTokens,
            temperature,
            messages: [
                ...(system ? [{ role: 'system', content: system }] : []),
                { role: 'user', content: user },
            ],
        }),
        signal,
        redirect: 'error',
    });
    if (!response.ok) {
        const status = response.status;
        const error = new Error(`orcarouter ${status}`);
        error.status = status;
        throw error;
    }
    const json = await response.json();
    const choice = json?.choices?.[0];
    const raw = choice?.message?.content;
    return {
        raw: typeof raw === 'string' ? raw : '',
        usage: json?.usage,
        finishReason: typeof choice?.finish_reason === 'string' ? choice.finish_reason : null,
    };
}
