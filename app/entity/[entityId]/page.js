import { redirect } from 'next/navigation';

// The per-entity score card has been retired. EMILIA publishes portable,
// verifiable authorization evidence — not a 0-100 reputation score or ranking.
// Trust look-ups now live in the Explorer (confidence tier, established status,
// effective evidence, and receipts anyone can verify offline). This also removes
// the legacy compat-score readout and the dangerouslySetInnerHTML breakdown that
// used to render here.
export const metadata = {
  title: 'Trust Profile Explorer — EMILIA Protocol',
  description:
    'Look up verifiable authorization evidence for an entity — confidence and ' +
    'receipts you can verify offline. Portable evidence, not a score.',
  robots: { index: false },
};

export default async function EntityProfile({ params }) {
  await params; // entityId no longer used; the score-card surface is retired.
  redirect('/explorer');
}
