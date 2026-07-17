export const metadata = {
  title: 'GovGuard — EMILIA Gate Government Profile',
  description:
    'A government solution profile for EMILIA Gate, covering configured disbursement, benefit-routing, enrollment, and override actions. Start in observe mode.',
  alternates: { canonical: '/govguard' },
  openGraph: {
    title: 'GovGuard — EMILIA Gate Government Profile',
    description:
      'Apply Gate policy and authorization-evidence requirements to configured public-sector workflows.',
    url: 'https://www.emiliaprotocol.ai/govguard',
    type: 'article',
  },
  keywords: [
    'county treasurer payment integrity',
    'vendor bank account change control',
    'government fraud control fire drill',
    'disbursement approval audit',
    'grant disbursement approval',
    'provider enrollment fraud control',
    'eligibility override audit',
    'benefit redirection fraud',
    'SNAP fraud prevention',
    'Medicaid fraud',
    'caseworker override control',
    'government AI controls',
    'NIST AI RMF evidence',
    'IG GAO evidence',
  ],
};

export default function GovGuardLayout({ children }) {
  return children;
}
