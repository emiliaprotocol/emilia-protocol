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
 *        level: process.env.LOG_LEVEL ?? 'info',
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

const SERVICE  = 'emilia-protocol';
const VERSION  = process.env.npm_package_version ?? 'unknown';
const IS_DEV   = process.env.NODE_ENV === 'development' || process.env.NODE_ENV === undefined;
const IS_TEST  = process.env.NODE_ENV === 'test';

// In test mode, delegate directly to console.error/console.warn/console.log so
// test suites that spy on console.* methods (vi.spyOn(console, 'error')) continue
// to work without modification.
const PASSTHROUGH_TEST = IS_TEST;

/** ANSI color codes for development output. */
const COLORS = { error: '\x1b[31m', warn: '\x1b[33m', info: '\x1b[36m', debug: '\x1b[90m', reset: '\x1b[0m' };

const LEVELS = { error: 50, warn: 40, info: 30, debug: 20 };

/**
 * Emit a single structured log line.
 *
 * @param {'error'|'warn'|'info'|'debug'} level
 * @param {object} context  - Bound context fields from logger.child()
 * @param {string} msg      - Human-readable message
 * @param {object} [fields] - Additional structured fields
 */
function emit(level, context, msg, fields) {
  // In test mode, delegate directly to console.* so vi.spyOn(console, 'error') works.
  if (PASSTHROUGH_TEST) {
    const sink = level === 'error' ? console.error
               : level === 'warn'  ? console.warn
               : console.log;
    const extra = fields ? [fields] : [];
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
    ...fields,
  };

  if (IS_DEV) {
    // Human-readable format for local development.
    const color  = COLORS[level] ?? '';
    const reset  = COLORS.reset;
    const prefix = `${color}[${level.toUpperCase()}]${reset}`;
    const extra  = Object.keys({ ...context, ...fields }).length > 0
      ? `\n${JSON.stringify({ ...context, ...fields }, null, 2)}`
      : '';
    const sink = level === 'error' || level === 'warn' ? console.error : console.log;
    sink(`${entry.time} ${prefix} ${msg}${extra}`);
    return;
  }

  // Production: newline-delimited JSON for log aggregators (Datadog, CloudWatch, Loki).
  const sink = level === 'error' || level === 'warn' ? process.stderr : process.stdout;
  sink.write(JSON.stringify(entry) + '\n');
}

/**
 * Create a logger instance (optionally with bound context).
 *
 * @param {object} [context] - Fields merged into every log entry from this logger.
 * @returns Logger instance with .error/.warn/.info/.debug/.child
 */
function createLogger(context = {}) {
  return {
    error(msg, fields)  { emit('error', context, msg, fields); },
    warn(msg, fields)   { emit('warn',  context, msg, fields); },
    info(msg, fields)   { emit('info',  context, msg, fields); },
    debug(msg, fields)  { emit('debug', context, msg, fields); },

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
