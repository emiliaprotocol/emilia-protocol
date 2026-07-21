// Generated from logger.ts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * EMILIA Protocol — Structured Logger
 * @license Apache-2.0
 *
 * Thin structured JSON logger for production observability.
 * Outputs newline-delimited JSON in production/staging, human-readable
 * lines in development. Implements the same interface as pino/winston
 * so it can be swapped for a full-featured logger without callsite changes.
 *
 * ## Upgrading to pino (zero callsite changes required)
 *
 * When throughput or sampling requirements outgrow this implementation:
 *
 *   1. `npm install pino`
 *   2. Replace the body of this file with:
 *
 *      import pino from 'pino';
 *      export const logger = pino({
 *        level: getLoggerConfig().level,
 *        base: { service: 'emilia-protocol' },
 *        redact: ['req.headers.authorization', 'req.headers.cookie'],
 *      });
 *
 *   3. Done. All 103 callsites use `.error/.warn/.info/.debug/.child` —
 *      the same interface pino exposes — so no other files need changing.
 *
 * Usage:
 *   import { logger } from '../lib/logger.js';
 *   logger.error('Handshake verification failed', { handshake_id, error: err.message });
 *   logger.warn('Rate limit approaching', { entity_id, count });
 *   logger.info('Protocol write completed', { command_type, actor });
 *   logger.debug('Policy resolved', { policy_id, hash });
 *
 * Context binding (for correlation IDs across a request):
 *   const reqLogger = logger.child({ request_id: 'abc', actor: 'entity-1' });
 *   reqLogger.error('Write failed');
 *   // → { level: 'error', request_id: 'abc', actor: 'entity-1', msg: 'Write failed', ... }
 */
import * as env from './env.js';
const SERVICE = 'emilia-protocol';
// Some isolated tests mock env.js with only the accessor they need. The
// fallback keeps the logger test-compatible while production always uses the
// centralized accessor above.
let getLoggerConfig;
try {
    // Vitest's strict module mock proxy throws for an omitted named export.
    getLoggerConfig = env.getLoggerConfig;
}
catch {
    getLoggerConfig = null;
}
const loggerConfig = typeof getLoggerConfig === 'function'
    ? getLoggerConfig()
    : { version: 'unknown', isDevelopment: true, isTest: true, level: 'info' };
const VERSION = loggerConfig.version;
const IS_DEV = loggerConfig.isDevelopment;
const IS_TEST = loggerConfig.isTest;
// In test mode, delegate directly to console.error/console.warn/console.log so
// test suites that spy on console.* methods (vi.spyOn(console, 'error')) continue
// to work without modification.
const PASSTHROUGH_TEST = IS_TEST;
/** ANSI color codes for development output. */
const COLORS = { error: '\x1b[31m', warn: '\x1b[33m', info: '\x1b[36m', debug: '\x1b[90m', reset: '\x1b[0m' };
const LEVELS = { error: 50, warn: 40, info: 30, debug: 20 };
// Keys whose VALUE must never reach a log sink, matched case-insensitively at
// any nesting depth. Defends against accidentally logging a headers object, an
// error carrying a token, or a credential-bearing field. Free-text in `msg` is
// not scrubbed — callers must not interpolate secrets into the message string.
const SENSITIVE_KEY = /(authorization|cookie|secret|passw(or)?d|token|bearer|api[-_]?key|x-api-key|private[-_]?key)/i;
function redactSensitive(value, depth = 0) {
    if (depth > 6 || value === null || typeof value !== 'object')
        return value;
    if (Array.isArray(value))
        return value.map((v) => redactSensitive(v, depth + 1));
    const out = {};
    for (const [k, v] of Object.entries(value)) {
        out[k] = SENSITIVE_KEY.test(k) ? '[REDACTED]' : redactSensitive(v, depth + 1);
    }
    return out;
}
function normalizeFields(fields) {
    if (fields === undefined)
        return undefined;
    if (fields !== null && typeof fields === 'object')
        return redactSensitive(fields);
    return fields;
}
/**
 * Emit a single structured log line.
 *
 * @param {'error'|'warn'|'info'|'debug'} level
 * @param {object} context  - Bound context fields from logger.child()
 * @param {string} msg      - Human-readable message
 * @param {object} [fields] - Additional structured fields
 */
function emit(level, context, msg, fields) {
    const safeFields = normalizeFields(fields);
    const fieldsObject = safeFields === undefined
        ? {}
        : (safeFields !== null && typeof safeFields === 'object' && !Array.isArray(safeFields)
            ? safeFields
            : { detail: safeFields });
    // In test mode, delegate directly to console.* so vi.spyOn(console, 'error') works.
    if (PASSTHROUGH_TEST) {
        const sink = level === 'error' ? console.error
            : level === 'warn' ? console.warn
                : console.log;
        const extra = safeFields === undefined ? [] : [safeFields];
        sink(msg, ...extra);
        return;
    }
    const entry = {
        level,
        levelNum: LEVELS[level],
        time: new Date().toISOString(),
        service: SERVICE,
        version: VERSION,
        ...context,
        msg,
        ...fieldsObject,
    };
    if (IS_DEV) {
        // Human-readable format for local development.
        const color = COLORS[level] ?? '';
        const reset = COLORS.reset;
        const prefix = `${color}[${level.toUpperCase()}]${reset}`;
        const extra = Object.keys({ ...context, ...fieldsObject }).length > 0
            ? `\n${JSON.stringify(redactSensitive({ ...context, ...fieldsObject }), null, 2)}`
            : '';
        const sink = level === 'error' || level === 'warn' ? console.error : console.log;
        sink(`${entry.time} ${prefix} ${msg}${extra}`);
        return;
    }
    // Production: newline-delimited JSON for log aggregators (Datadog, CloudWatch, Loki).
    // console.* is available in both Node and the Edge runtime. It also keeps
    // the structured line format without importing Node-only stdout/stderr APIs
    // into handlers that Next may bundle for Edge.
    const sink = level === 'error' || level === 'warn' ? console.error : console.log;
    sink(JSON.stringify(redactSensitive(entry)));
}
/**
 * Create a logger instance (optionally with bound context).
 *
 * @param {object} [context] - Fields merged into every log entry from this logger.
 * @returns Logger instance with .error/.warn/.info/.debug/.child
 */
function createLogger(context = {}) {
    return {
        error(msg, fields) { emit('error', context, msg, fields); },
        warn(msg, fields) { emit('warn', context, msg, fields); },
        info(msg, fields) { emit('info', context, msg, fields); },
        debug(msg, fields) { emit('debug', context, msg, fields); },
        /**
         * Create a child logger with additional bound context.
         * Child context is merged with parent context; child fields take precedence.
         *
         * @param {object} childContext
         * @returns Child logger instance
         */
        child(childContext) {
            return createLogger({ ...context, ...childContext });
        },
    };
}
export const logger = createLogger();
