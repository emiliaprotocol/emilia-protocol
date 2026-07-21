/**
 * Next.js Instrumentation Hook
 *
 * Runs once when the server starts (Node.js runtime only).
 * Registers graceful shutdown handlers for SIGTERM/SIGINT so Docker
 * and Kubernetes can drain in-flight protocol writes before killing
 * the process.
 *
 * See: https://nextjs.org/docs/app/building-your-application/optimizing/instrumentation
 * See: lib/shutdown.js for the drain implementation
 */

export async function register() {
  // Only register in the Node.js runtime, not in Edge runtime or during build.
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    const { registerShutdownHandlers } = await import('./lib/shutdown.js');
    registerShutdownHandlers();
  }
}
