export const metadata = {
  title: 'Approver Apps — Exact-Action Human Decisions',
  description:
    'Open iOS, Android, Swift, and Kotlin reference clients for showing exact '
    + 'material fields and returning device-bound human-decision evidence to EMILIA Gate.',
  alternates: { canonical: '/product/accountable-signoff' },
  openGraph: {
    title: 'EMILIA Approver Apps',
    description:
      'Gate creates the exact-action challenge. The Approver app captures the '
      + 'device-bound human decision before protected execution.',
    url: 'https://www.emiliaprotocol.ai/product/accountable-signoff',
    type: 'article',
  },
  keywords: [
    'accountable signoff',
    'named human approval',
    'AI action signoff',
    'cryptographic signoff',
    'segregation of duties AI',
    'AI approval app',
    'mobile human authorization',
  ],
};

export default function AccountableSignoffLayout({ children }) {
  return children;
}
