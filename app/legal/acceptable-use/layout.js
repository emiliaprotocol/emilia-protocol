export const metadata = {
  title: 'Acceptable Use Policy — EMILIA Protocol',
  description:
    'Prohibited and restricted uses of EMILIA Protocol services and SDKs. ' +
    'Aligned with standard prohibited-use policies for security ' +
    'infrastructure and AI authorization tooling.',
  alternates: { canonical: '/legal/acceptable-use' },
  openGraph: {
    title: 'EMILIA Protocol Acceptable Use Policy',
    description: 'Prohibited and restricted uses of the protocol and services.',
    url: 'https://www.emiliaprotocol.ai/legal/acceptable-use',
    type: 'article',
  },
};

export default function AcceptableUseLayout({ children }) {
  return children;
}
