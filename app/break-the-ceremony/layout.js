export const metadata = {
  title: 'Break the Ceremony — EMILIA Protocol Red-Team Challenge',
  description:
    'EMILIA’s authorization ceremony is formally verified to be replay-proof, unforgeable, self-approval-proof, and irreversible. Try to break it. Every confirmed break and its fix is published, with credit.',
  alternates: { canonical: '/break-the-ceremony' },
  openGraph: {
    title: 'Break the Ceremony — 0 confirmed breaks',
    description:
      'Don’t take our word that it’s safe. The protocol is open, the receipts are public, the proofs are machine-checked. Try to break it.',
    url: 'https://www.emiliaprotocol.ai/break-the-ceremony',
    type: 'website',
  },
};

export default function BreakLayout({ children }) {
  return children;
}
