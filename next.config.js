const { withSentryConfig } = require('@sentry/nextjs');

/** @type {import('next').NextConfig} */
// CSP is set dynamically per-request in middleware.js using a nonce,
// removing 'unsafe-inline' from script-src (resolves HIGH-09 pentest finding).
// These static headers cover everything CSP does not.
const securityHeaders = [
  { key: 'X-DNS-Prefetch-Control', value: 'on' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
];

const nextConfig = {
  output: 'standalone',
  // Pin file-tracing root to this repo. Without it, Next.js walks up the
  // filesystem looking for a lockfile and may pick a parent monorepo root
  // (e.g., ~/Documents/package-lock.json), which produces a "multiple
  // lockfiles detected" warning at build time.
  outputFileTracingRoot: __dirname,
  // instrumentation.js is loaded automatically since Next.js 15 — the
  // experimental.instrumentationHook flag is no longer needed (and emits a
  // build warning if set).
  async rewrites() {
    return [
      // Serve /.well-known/ep-keys.json from the dynamic API route.
      // ep-trust.json is static (public/.well-known/ep-trust.json).
      {
        source: '/.well-known/ep-keys.json',
        destination: '/api/discovery/keys',
      },
    ];
  },
  async headers() {
    return [
      {
        source: '/:path*',
        headers: securityHeaders,
      },
      {
        source: '/api/:path*',
        headers: [
          { key: 'Cache-Control', value: 'no-store, no-cache, must-revalidate' },
        ],
      },
    ];
  },
};

// Wrap with Sentry to enable automatic error reporting and source maps.
// Only enable Sentry build plugin when SENTRY_AUTH_TOKEN is set — prevents
// build failures on federation operators and CI environments without Sentry.
if (process.env.SENTRY_AUTH_TOKEN) {
  module.exports = withSentryConfig(nextConfig, {
    org: process.env.SENTRY_ORG,
    project: process.env.SENTRY_PROJECT,
    silent: !process.env.CI,
    widenClientFileUpload: true,
    disableLogger: true,
    automaticVercelMonitors: false,
  });
} else {
  module.exports = nextConfig;
}
