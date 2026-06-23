export const metadata = {
  title: 'Break the Ceremony — Red-Team Challenge & Attack Matrix — EMILIA Protocol',
  description:
    'The authorization-receipt layer for irreversible AI-agent actions: no receipt, no execution. What a receipt proves and what it does not, the attack matrix we reject (replay, forged receipt, tampered action, wrong approver, missing receipt, wrong quorum), a real authority-binding bug we caught and fixed, and an open invitation to break the model. Every confirmed break and its fix is published, with credit.',
  alternates: { canonical: '/break-the-ceremony' },
  openGraph: {
    title: 'Break the Ceremony — attack matrix & red-team challenge',
    description:
      'No receipt, no execution. The attacks EP rejects, what it does not prove, the bug we caught and fixed — and an open invitation to break it. Offline-verifiable, formally checked.',
    url: 'https://www.emiliaprotocol.ai/break-the-ceremony',
    type: 'website',
  },
  keywords: [
    'AI agent security red team',
    'authorization receipt attack matrix',
    'no receipt no execution',
    'irreversible agent action enforcement',
    'offline verifiable authorization',
    'replay forgery tamper resistance',
    'agent authorization bug bounty',
  ],
};

export default function BreakLayout({ children }) {
  return children;
}
