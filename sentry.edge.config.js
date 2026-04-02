/**
 * EMILIA Protocol — Sentry Edge Runtime Configuration
 * @license Apache-2.0
 *
 * Initializes Sentry for Next.js Edge Runtime routes (middleware and
 * any API routes that opt into `export const runtime = 'edge'`).
 *
 * The Edge Runtime is a constrained environment: no Node.js APIs,
 * no file system access. This config mirrors server-config semantics
 * but avoids Node-only imports (e.g., crypto, fs).
 *
 * SENTRY_DSN is provided via the build-time env injection from
 * withSentryConfig() in next.config.js. No NEXT_PUBLIC_ prefix needed
 * here because edge config is evaluated at build time, not in the browser.
 *
 * See: https://docs.sentry.io/platforms/javascript/guides/nextjs/
 */

import * as Sentry from '@sentry/nextjs';

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.SENTRY_ENVIRONMENT ?? process.env.NODE_ENV ?? 'development',

  // Keep traces low to avoid latency impact on Edge routes.
  tracesSampleRate: process.env.NODE_ENV === 'production' ? 0.05 : 0,

  // Only activate when DSN is configured — safe no-op otherwise.
  enabled: !!process.env.SENTRY_DSN,

  // Tag all Edge events consistently with server events for cross-runtime correlation.
  initialScope: {
    tags: {
      protocol_version: 'EP/1.1-v2',
      service: 'emilia-protocol-api',
      runtime: 'edge',
    },
  },

  beforeSend(event) {
    // Strip authorization headers before shipping to Sentry.
    // Edge Runtime may surface these in request context.
    if (event.request?.headers) {
      delete event.request.headers['authorization'];
      delete event.request.headers['x-api-key'];
      delete event.request.headers['cookie'];
    }
    return event;
  },
});
