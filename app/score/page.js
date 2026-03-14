import { redirect } from 'next/navigation';

export const metadata = {
  title: 'Trust Profile Explorer — EMILIA Protocol',
  description: 'Look up any entity\'s trust profile. Behavioral rates, signal breakdowns, anomaly alerts, confidence levels.',
};

/**
 * /score page — redirects to the main site.
 * 
 * The old "Check any EMILIA Score" page has been replaced.
 * EP's canonical read surface is GET /api/trust/profile/:entityId.
 * The landing page at / has the trust profile lookup widget.
 * 
 * This redirect ensures old links and bookmarks still work.
 */
export default function ScorePage() {
  redirect('/#score');
}
