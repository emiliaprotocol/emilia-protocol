// SPDX-License-Identifier: Apache-2.0

export const metadata = {
  title: 'Try to Break Receipt Required - EMILIA Protocol',
  description:
    'Run the live EMILIA Receipt Required ritual: try a dangerous action without a receipt, sign the exact action, execute it, replay it, forge it, and export the evidence packet.',
  alternates: { canonical: '/try/receipt-required' },
  openGraph: {
    title: 'Try to Break Receipt Required',
    description:
      'A live public demo: missing receipt fails, exact-action receipt runs, replay fails, forgery fails, evidence exports.',
    url: 'https://www.emiliaprotocol.ai/try/receipt-required',
    type: 'website',
  },
};

export default function ReceiptRequiredTryLayout({ children }) {
  return children;
}
