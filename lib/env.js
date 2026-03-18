export function assertServerEnv({ required = [] } = {}) {
  const missing = required.filter(k => !process.env[k]);
  if (missing.length === 0) return { ok: true };

  const msg = `Missing required server env: ${missing.join(', ')}`;
  if (process.env.NODE_ENV === 'production') {
    throw new Error(msg);
  }

  // In non-production, warn but allow startup for developer convenience
  // Servers should still gate sensitive operations by checking secrets
  // at call-time (see lib/blockchain.js which already checks wallet key).
  // Keep warning concise to avoid log noise.
  // eslint-disable-next-line no-console
  console.warn('ENV WARNING:', msg);
  return { ok: false, missing };
}
