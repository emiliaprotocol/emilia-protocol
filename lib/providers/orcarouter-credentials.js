// Generated from orcarouter-credentials.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * OrcaRouter credential store — the single seam both authentication paths use.
 *
 * @license Apache-2.0
 *
 * Two adapters produce the same thing: a normal OrcaRouter API key.
 *
 *   api_key  the operator pastes an existing sk-orca-… key
 *   pkce     OAuth 2.0 + PKCE returns a durable key after approval
 *
 * Both are persisted here, sealed at rest with the repository's existing
 * secret box (lib/crypto/secret-box), in the deployment's local state
 * directory. ORCAROUTER_API_KEY remains a supported, non-persisted source for
 * unattended deployments; a credential saved through this store takes
 * precedence over it.
 *
 * A PKCE-issued key is NOT a refresh token. There is no refresh grant. A relay
 * 401 marks exactly the stored generation that made the rejected request as
 * needing reauthentication; an old generation can never overwrite a newer one.
 *
 * No function here returns the key to a caller that is not the inference path,
 * and no function logs it.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { getOrcaRouterEnv } from '../env.js';
import { logger } from '../logger.js';
import { open as openSecret, seal } from '../crypto/secret-box.js';
import { ORCAROUTER_DEFAULT_EMBEDDING_MODEL, ORCAROUTER_DEFAULT_MODEL, ORCAROUTER_PROVIDER_ID, } from './orcarouter.js';
export const ORCAROUTER_MASKED_KEY = 'sk-orca-…';
const CREDENTIAL_FILE = 'credential.json';
const SETTINGS_FILE = 'settings.json';
const KEY_FORMAT = /^sk-orca-[A-Za-z0-9_-]{8,}$/;
export const ORCAROUTER_CAPABILITIES = ['chat', 'embedding', 'image', 'video', 'rerank'];
/** Directory for OrcaRouter runtime state; `.emilia/` is already git-ignored. */
export function orcaRouterStateDir(explicit) {
    const env = getOrcaRouterEnv();
    return explicit || env.stateDir || path.join(process.cwd(), '.emilia', 'orcarouter');
}
function credentialPath(stateDir) {
    return path.join(orcaRouterStateDir(stateDir), CREDENTIAL_FILE);
}
function settingsPath(stateDir) {
    return path.join(orcaRouterStateDir(stateDir), SETTINGS_FILE);
}
function writePrivateJson(target, value) {
    fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    const temporary = `${target}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(value, null, 2), { encoding: 'utf8', mode: 0o600 });
    fs.renameSync(temporary, target);
}
function readStored(stateDir) {
    let raw;
    try {
        raw = fs.readFileSync(credentialPath(stateDir), 'utf8');
    }
    catch (error) {
        if (error?.code === 'ENOENT')
            return null;
        throw new Error('credential_unreadable');
    }
    let parsed;
    try {
        parsed = JSON.parse(raw);
    }
    catch {
        throw new Error('credential_unreadable');
    }
    if (!parsed || typeof parsed !== 'object')
        throw new Error('credential_unreadable');
    return parsed;
}
/** True when any credential is available. Synchronous on purpose: llmAvailable() is sync. */
export function hasOrcaRouterCredential(stateDir) {
    if (getOrcaRouterEnv().apiKey)
        return true;
    return hasStoredOrcaRouterCredential(stateDir);
}
/** True when the settings surface or PKCE flow saved a credential. */
export function hasStoredOrcaRouterCredential(stateDir) {
    try {
        return fs.existsSync(credentialPath(stateDir));
    }
    catch {
        return false;
    }
}
/** Lightweight format check only. An sk-orca-… prefix is not proof of validity. */
export function looksLikeOrcaRouterKey(value) {
    return typeof value === 'string' && KEY_FORMAT.test(value);
}
export async function resolveOrcaRouterCredential(stateDir) {
    let stored;
    try {
        stored = readStored(stateDir);
    }
    catch {
        // A corrupt or unreadable credential file fails closed. Falling through to
        // the environment here would silently swap which identity is in use.
        logger.warn('orcarouter: stored credential file is unreadable');
        return { ok: false, reason: 'unreadable', source: null, generation: null };
    }
    if (stored) {
        const generation = typeof stored.generation === 'string' ? stored.generation : null;
        if (stored.needs_reauth) {
            return {
                ok: false,
                reason: 'needs_reauth',
                source: stored.source || 'api_key',
                generation,
            };
        }
        let key;
        try {
            key = openSecret(stored.sealed_key);
        }
        catch {
            logger.warn('orcarouter: stored credential could not be opened');
            return { ok: false, reason: 'unreadable', source: stored.source || 'api_key', generation };
        }
        if (!looksLikeOrcaRouterKey(key)) {
            logger.warn('orcarouter: stored credential is malformed');
            return { ok: false, reason: 'unreadable', source: stored.source || 'api_key', generation };
        }
        return { ok: true, key, source: stored.source, generation: generation || 'stored', scope: stored.scope || null };
    }
    const envKey = getOrcaRouterEnv().apiKey;
    if (envKey) {
        return { ok: true, key: envKey, source: 'env', generation: 'env', scope: 'api' };
    }
    return { ok: false, reason: 'not_configured', source: null, generation: null };
}
export async function orcaRouterCredentialStatus(stateDir) {
    let stored;
    try {
        stored = readStored(stateDir);
    }
    catch {
        return {
            configured: false,
            source: null,
            masked: null,
            needs_reauth: false,
            scope: null,
            updated_at: null,
            generation: null,
            error: 'unreadable',
        };
    }
    if (stored) {
        const status = {
            configured: !stored.needs_reauth,
            source: stored.source || 'api_key',
            masked: ORCAROUTER_MASKED_KEY,
            needs_reauth: Boolean(stored.needs_reauth),
            scope: stored.scope || null,
            updated_at: stored.updated_at || null,
            generation: stored.generation || null,
            error: stored.needs_reauth ? 'needs_reauth' : null,
        };
        return status;
    }
    if (getOrcaRouterEnv().apiKey) {
        return {
            configured: true,
            source: 'env',
            masked: ORCAROUTER_MASKED_KEY,
            needs_reauth: false,
            scope: 'api',
            updated_at: null,
            generation: 'env',
            error: null,
        };
    }
    return {
        configured: false,
        source: null,
        masked: null,
        needs_reauth: false,
        scope: null,
        updated_at: null,
        generation: null,
        error: 'not_configured',
    };
}
function persistCredential(key, source, scope, stateDir) {
    const record = {
        version: 1,
        provider: ORCAROUTER_PROVIDER_ID,
        source,
        sealed_key: String(seal(key)),
        generation: crypto.randomBytes(16).toString('hex'),
        scope,
        needs_reauth: false,
        updated_at: new Date().toISOString(),
    };
    writePrivateJson(credentialPath(stateDir), record);
    return {
        configured: true,
        source,
        masked: ORCAROUTER_MASKED_KEY,
        needs_reauth: false,
        scope,
        updated_at: record.updated_at,
        generation: record.generation,
        error: null,
    };
}
/** API-key adapter: persist a pasted key. */
export async function saveOrcaRouterApiKey(key, stateDir) {
    if (!looksLikeOrcaRouterKey(key)) {
        throw new Error('invalid_key_format');
    }
    return persistCredential(key, 'api_key', 'api', stateDir);
}
/** PKCE adapter: persist the durable key returned by the exchange. */
export async function saveOrcaRouterPkceKey(key, scope, stateDir) {
    if (!looksLikeOrcaRouterKey(key)) {
        throw new Error('invalid_key_format');
    }
    return persistCredential(key, 'pkce', scope, stateDir);
}
/**
 * Remove the stored credential. The environment variable, if any, is never
 * touched: clearing the UI must not pretend to remove a deployment secret.
 */
export async function clearOrcaRouterCredential(stateDir) {
    try {
        fs.unlinkSync(credentialPath(stateDir));
    }
    catch (error) {
        if (error?.code !== 'ENOENT')
            throw error;
    }
    return orcaRouterCredentialStatus(stateDir);
}
/**
 * Mark exactly the generation that made a rejected request as needing
 * reauthentication. A late failure from an old generation is a no-op.
 */
export async function markOrcaRouterNeedsReauth(generation, stateDir) {
    if (!generation || generation === 'env')
        return;
    let stored;
    try {
        stored = readStored(stateDir);
    }
    catch {
        return;
    }
    if (!stored || stored.generation !== generation || stored.needs_reauth)
        return;
    writePrivateJson(credentialPath(stateDir), { ...stored, needs_reauth: true });
}
function readSettings(stateDir) {
    try {
        const parsed = JSON.parse(fs.readFileSync(settingsPath(stateDir), 'utf8'));
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
            return {};
        return parsed;
    }
    catch {
        return {};
    }
}
/**
 * The operator's explicit selection for one capability, or null. Selections are
 * stored per capability: choosing a chat model must never change the embedding
 * model, and vice versa.
 */
export async function getOrcaRouterModelSelection(capability, stateDir) {
    const stored = readSettings(stateDir);
    const selected = stored.models?.[capability];
    if (typeof selected === 'string' && selected)
        return selected;
    if (capability === 'chat' && typeof stored.model === 'string' && stored.model)
        return stored.model;
    return null;
}
/**
 * Selected model for one capability: explicit UI choice, then a capability-
 * specific environment override, then the built-in default. Capabilities with
 * no generic default return null and require an explicit selection.
 */
export async function getOrcaRouterModelFor(capability, stateDir) {
    const selected = await getOrcaRouterModelSelection(capability, stateDir);
    if (selected)
        return selected;
    const env = getOrcaRouterEnv();
    if (capability === 'chat')
        return env.modelOverride || ORCAROUTER_DEFAULT_MODEL;
    if (capability === 'embedding')
        return env.embeddingModelOverride || ORCAROUTER_DEFAULT_EMBEDDING_MODEL;
    return null;
}
/** Chat-model shorthand used by the Trust Desk inference pipeline. */
export async function getOrcaRouterModel(stateDir) {
    return (await getOrcaRouterModelFor('chat', stateDir)) || ORCAROUTER_DEFAULT_MODEL;
}
function assertModelId(model) {
    if (typeof model !== 'string' || !model || model.length > 200 || !/^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$/.test(model)) {
        throw new Error('invalid_model_id');
    }
}
/** Persist a selection for exactly one capability, leaving the others intact. */
export async function setOrcaRouterModelFor(capability, model, stateDir) {
    if (!ORCAROUTER_CAPABILITIES.includes(capability))
        throw new Error('invalid_capability');
    assertModelId(model);
    const stored = readSettings(stateDir);
    const models = { ...(stored.models || {}) };
    if (capability === 'chat' && typeof stored.model === 'string' && stored.model && !models.chat) {
        models.chat = stored.model;
    }
    models[capability] = model;
    writePrivateJson(settingsPath(stateDir), {
        version: 2,
        models,
        updated_at: new Date().toISOString(),
    });
    return { model, capability, models };
}
/** Chat-model shorthand retained for existing callers. */
export async function setOrcaRouterModel(model, stateDir) {
    return setOrcaRouterModelFor('chat', model, stateDir);
}
/**
 * The fence a PKCE attempt is bound to: the stored credential generation, or
 * `env` / `none` when only the environment supplies one. Captured when the
 * authorization starts and compared again immediately before the write, so a
 * key approved for an old attempt can never replace a newer credential.
 */
export function orcaRouterCredentialFence(stateDir) {
    let stored;
    try {
        stored = readStored(stateDir);
    }
    catch {
        return 'unreadable';
    }
    if (stored && typeof stored.generation === 'string' && stored.generation)
        return stored.generation;
    return getOrcaRouterEnv().apiKey ? 'env' : 'none';
}
/**
 * Fenced PKCE write. The check and the write are synchronous and contiguous,
 * so no other request can interleave between them. A mismatch means the
 * credential changed while the approval was in flight (cancelled, replaced by
 * an API key, or another PKCE approval won the race); the old approval is
 * discarded instead of overwriting the newer credential.
 */
export function saveOrcaRouterPkceKeyIfCurrent(key, scope, expectedGeneration, stateDir) {
    if (!looksLikeOrcaRouterKey(key)) {
        throw new Error('invalid_key_format');
    }
    if (orcaRouterCredentialFence(stateDir) !== (expectedGeneration || 'none')) {
        throw new Error('credential_superseded');
    }
    return persistCredential(key, 'pkce', scope, stateDir);
}
