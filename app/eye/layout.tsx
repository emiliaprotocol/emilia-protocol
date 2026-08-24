import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Eye — Experimental Action-Risk Advisory Profile',
  description:
    'An experimental, advisory-only EMILIA profile for observation and shadow evaluation. ' +
    'Eye can tighten posture but never authorizes or enforces an action by itself.',
  alternates: { canonical: '/eye' },
  openGraph: {
    title: 'Eye — Observe and Evaluate Without Authorizing',
    description:
      'Experimental action-risk advisories with an explicit non-authorizing boundary.',
    url: 'https://www.emiliaprotocol.ai/eye',
    type: 'article',
  },
};

export default function EyeLayout({ children }: { children: React.ReactNode }) {
  return children;
}
