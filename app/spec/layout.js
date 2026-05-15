export const metadata = {
  title: 'EP Protocol Specification — Formal Verification + Receipt Schema',
  description:
    'The full EMILIA Protocol specification: state machine, formal ' +
    'invariants (26 TLA+ theorems, 35 Alloy facts), EP-RECEIPT-v1 schema, ' +
    'and conformance test fixtures. Reference for any implementer.',
  alternates: { canonical: '/spec' },
  openGraph: {
    title: 'EP Protocol Specification',
    description:
      'State machine, formal invariants, receipt schema, and conformance ' +
      'tests for the EMILIA Protocol open standard.',
    url: 'https://www.emiliaprotocol.ai/spec',
    type: 'article',
  },
  keywords: [
    'EP protocol specification',
    'formal verification AI authorization',
    'TLA+ theorems',
    'Alloy facts',
    'EP-RECEIPT-v1',
    'conformance test fixtures',
  ],
};

export default function SpecLayout({ children }) {
  return children;
}
