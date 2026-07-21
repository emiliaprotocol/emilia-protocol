import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Proof a Human Authorized the Transfer — EMILIA for Insurers',
  description:
    'Cyber and crime policies require dual authorization and out-of-band '
    + 'verification of wires and payment changes — but the proof is ad hoc and '
    + 'deepfakes now defeat the callback. EMILIA turns that control into a '
    + 'cryptographic, offline-verifiable authorization receipt: a named human '
    + 'signs the exact action; a two-person rule a cloned voice cannot defeat.',
  alternates: { canonical: '/insurance' },
  openGraph: {
    title: 'EMILIA for insurers — verifiable proof a human authorized the transfer',
    description:
      'The dual-authorization control you already require, finally machine-checkable '
      + 'and deepfake-resistant. An offline-verifiable authorization receipt for '
      + 'funds-transfer-fraud, social engineering, and agentic-AI risk.',
    url: 'https://www.emiliaprotocol.ai/insurance',
    type: 'article',
  },
  keywords: [
    'proof of authorization for wire transfers',
    'funds transfer fraud control evidence',
    'social engineering fraud insurance control',
    'out-of-band verification proof',
    'dual authorization receipt',
    'deepfake wire fraud prevention',
    'business email compromise control',
    'agentic AI liability insurance',
    'AI agent authorization evidence',
    'cyber insurance coverage condition proof',
    'verifiable human authorization',
    'two-person rule cryptographic',
  ],
};

export default function InsuranceLayout({ children }: { children: React.ReactNode }) {
  return children;
}
