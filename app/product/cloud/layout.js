export const metadata = {
  title: 'EP Cloud — Hosted authorization receipts + Signoff Workflow',
  description:
    'Managed deployment of the EMILIA Protocol runtime. Hosted handshake ' +
    'service, trust desk for named signoff, receipt explorer, and ' +
    'observability — without operating the runtime yourself.',
  alternates: { canonical: '/product/cloud' },
  openGraph: {
    title: 'EMILIA Cloud',
    description:
      'Hosted EP runtime with managed authorization receipts, named-signoff ' +
      'workflow, and receipt explorer.',
    url: 'https://www.emiliaprotocol.ai/product/cloud',
    type: 'article',
  },
  keywords: [
    'EP Cloud',
    'hosted AI authorization',
    'managed authorization receipts',
    'signoff workflow as a service',
  ],
};

export default function CloudProductLayout({ children }) {
  return children;
}
