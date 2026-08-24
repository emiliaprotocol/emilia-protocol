import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Experimental Registry Sandbox — Create a Test API Key',
  description:
    'Create a reference credential for the experimental public EMILIA registry sandbox. '
    + 'This rate-limited nonproduction surface carries no service-level or global-network claim.',
  alternates: { canonical: '/signup' },
  openGraph: {
    title: 'Experimental EMILIA Registry Sandbox',
    description: 'Create a nonproduction reference credential and exercise experimental registry, receipt, handshake, and Gate paths.',
    url: 'https://www.emiliaprotocol.ai/signup',
    type: 'website',
  },
  keywords: ['EMILIA Protocol sandbox', 'experimental agent registry', 'authorization receipt sandbox', 'reference API credential'],
};

export default function SignupLayout({ children }: { children: React.ReactNode }) {
  return children;
}
