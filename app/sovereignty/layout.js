// SPDX-License-Identifier: Apache-2.0

export const metadata = {
  title: 'European Digital Sovereignty for Accountable AI — EMILIA',
  description:
    'EMILIA provides offline-verifiable action-authorization evidence relevant to EU AI Act '
    + 'human-oversight and logging assessments, checkable by European institutions against '
    + 'their own pinned trust inputs.',
  alternates: { canonical: '/sovereignty' },
  openGraph: {
    title: 'European Digital Sovereignty for Accountable AI',
    description:
      'An open authorization-receipt layer for verifiable human authority over AI actions. '
      + 'No receipt, no execution. Offline-verifiable, Apache-2.0, self-hostable.',
    url: 'https://www.emiliaprotocol.ai/sovereignty',
    type: 'website',
  },
  keywords: [
    'European digital sovereignty',
    'EU AI Act Article 14',
    'verifiable human oversight',
    'AI Act human oversight',
    'authorization receipts',
    'accountable AI infrastructure',
    'eIDAS AI authorization',
    'offline verifiable AI governance',
  ],
};

export default function SovereigntyLayout({ children }) {
  return children;
}
