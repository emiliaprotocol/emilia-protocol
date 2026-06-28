/**
 * EMILIA Protocol — Sentry Client Configuration
 * @license Apache-2.0
 *
 * Initializes Sentry error reporting in the browser. Runs once when the
 * Next.js client bundle is loaded.
 *
 * DSN and environment are pulled from NEXT_PUBLIC_SENTRY_DSN and
 * NEXT_PUBLIC_SENTRY_ENVIRONMENT environment variables. No DSN = disabled
 * (safe default for local dev).
 *
 * See: https://docs.sentry.io/platforms/javascript/guides/nextjs/
 */

import * as Sentry from '@sentry/nextjs';

Sentry.init({
  dsn: process.env.NEXT_PUBLIC_SENTRY_DSN,
  environment: process.env.NEXT_PUBLIC_SENTRY_ENVIRONMENT ?? 'development',

  // Capture 10% of transactions for performance monitoring in production.
  // Increase to 1.0 for local debugging.
  tracesSampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 0,

  // Only send errors in production and staging. Suppress in local dev.
  enabled: !!process.env.NEXT_PUBLIC_SENTRY_DSN,

  // Attach user context from the EP API key prefix for correlation.
  beforeSend(event) {
    // Strip any PII from request data before sending.
    if (event.request?.headers) {
      delete event.request.headers['authorization'];
      delete event.request.headers['cookie'];
    }
    // Scrub sensitive fields from bodies/extra/locals. (NASTY-7)
    const SENSITIVE = /(signature|private[_-]?key|signing[_-]?key|secret|token|api[_-]?key|password|x-emilia-receipt)/i;
    const redact = (o, depth = 0) => {
      if (!o || typeof o !== 'object' || depth > 6) return;
      for (const k of Object.keys(o)) {
        if (SENSITIVE.test(k)) { o[k] = '[redacted]'; continue; }
        if (o[k] && typeof o[k] === 'object') redact(o[k], depth + 1);
      }
    };
    redact(event.request?.data);
    redact(event.extra);
    redact(event.contexts);
    return event;
  },
});
