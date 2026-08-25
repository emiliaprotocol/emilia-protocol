import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Eye — Action-Scoped Risk Advisories for EMILIA Gate',
  description:
    'Eye emits short-lived, action-scoped risk advisories that can tighten a ' +
    'relying party\'s Gate policy. Eye never authorizes or blocks; Gate owns enforcement.',
  alternates: { canonical: '/eye' },
  openGraph: {
    title: 'Eye — Observe, Explain, Escalate',
    description:
      'Action-scoped risk advisories for a separately configured EMILIA Gate.',
    url: 'https://www.emiliaprotocol.ai/eye',
    type: 'article',
  },
};

export default function EyeLayout({ children }: { children: React.ReactNode }) {
  return children;
}
