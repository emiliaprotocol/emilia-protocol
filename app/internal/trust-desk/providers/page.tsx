// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import { cookies } from 'next/headers';
import { getOrcaRouterEnv } from '@/lib/env';
import {
  authenticateTrustDeskReviewer,
  TRUST_DESK_SESSION_COOKIE,
} from '@/lib/trust-desk/auth';
import OrcaRouterProvidersPanel from './OrcaRouterProvidersPanel';

export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Model providers — OrcaRouter Cyber Inference',
  robots: { index: false, follow: false },
};

const wrap = { maxWidth: 1040, margin: '0 auto', padding: '40px 24px', fontFamily: "'IBM Plex Sans', -apple-system, sans-serif" };

export default async function ProvidersPage() {
  const enabled = getOrcaRouterEnv().settingsSurfaceEnabled;
  if (!enabled) {
    return (
      <main style={wrap}>
        <div style={{ fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#78716c', marginBottom: 8 }}>
          AI Trust Desk · Internal
        </div>
        <h1 style={{ fontSize: 28, fontWeight: 700, color: '#1c1917', marginBottom: 8 }}>Provider settings disabled</h1>
        <p style={{ color: '#57534e', fontSize: 14, maxWidth: 640, lineHeight: 1.6 }}>
          This surface can replace the deployment&apos;s model credential. Set
          {' '}<code>ORCAROUTER_PROVIDER_ADMIN=1</code>{' '}to enable it, or configure
          {' '}<code>ORCAROUTER_API_KEY</code>{' '}directly for unattended deployments.
        </p>
      </main>
    );
  }

  // The surface can replace the credential used for inference, so it renders
  // only for an authenticated internal administrator. The session cookie is
  // the same signed Trust Desk session the review routes use; the API routes
  // verify it independently on every request.
  const session = authenticateTrustDeskReviewer(
    (await cookies()).get(TRUST_DESK_SESSION_COOKIE)?.value,
  );
  if (!session) {
    return (
      <main style={wrap}>
        <div style={{ fontSize: 11, letterSpacing: 3, textTransform: 'uppercase', color: '#78716c', marginBottom: 8 }}>
          AI Trust Desk · Internal
        </div>
        <h1 style={{ fontSize: 28, fontWeight: 700, color: '#1c1917', marginBottom: 8 }}>Administrator session required</h1>
        <p style={{ color: '#57534e', fontSize: 14, maxWidth: 640, lineHeight: 1.6 }}>
          Sign in through the internal Trust Desk to manage model provider credentials.
        </p>
      </main>
    );
  }

  return <OrcaRouterProvidersPanel />;
}
