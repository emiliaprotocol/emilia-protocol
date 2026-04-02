/**
 * EMILIA Protocol — Sentry Server Configuration
 * @license Apache-2.0
 *
 * Initializes Sentry error reporting on the Node.js server runtime.
 * Also covers the instrumentation hook (instrumentation.js) which runs
 * before the Next.js server starts.
 *
 * SENTRY_DSN is a server-only env var (not exposed to the browser).
 * SENTRY_ENVIRONMENT defaults to NODE_ENV.
 *
 * See: https://docs.sentry.io/platforms/javascript/guides/nextjs/
 */

import * as Sentry from '@sentry/nextjs';

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.SENTRY_ENVIRONMENT ?? process.env.NODE_ENV ?? 'development',

  // Sample 10% of requests for performance traces in production.
  tracesSampleRate: process.env.NODE_ENV === 'production' ? 0.1 : 0,

  enabled: !!process.env.SENTRY_DSN,

  // Tag all events with protocol version for release correlation.
  initialScope: {
    tags: {
      protocol_version: 'EP/1.1-v2',
      service: 'emilia-protocol-api',
    },
  },

  beforeSend(event) {
    // Strip authorization headers — never leak API keys to Sentry.
    if (event.request?.headers) {
      delete event.request.headers['authorization'];
      delete event.request.headers['x-api-key'];
      delete event.request.headers['cookie'];
    }
    return event;
  },
});
