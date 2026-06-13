// SPDX-License-Identifier: Apache-2.0
// EP Essay — "The Model Is the Crumple Zone".
// @license Apache-2.0

import EssayArticle from '@/components/EssayArticle';

const SLUG = 'the-model-is-the-crumple-zone';
const TITLE = 'The Model Is the Crumple Zone';
const DESCRIPTION =
  'A human-in-the-loop protects the human from the agent. The authorization ' +
  'receipt protects the agent — and its maker — from the human.';
const URL = 'https://www.emiliaprotocol.ai/essays/the-model-is-the-crumple-zone';

export const metadata = {
  title: `${TITLE} — EMILIA Protocol`,
  description: DESCRIPTION,
  alternates: { canonical: `/essays/${SLUG}` },
  openGraph: {
    title: TITLE,
    description: DESCRIPTION,
    url: URL,
    type: 'article',
    publishedTime: '2026-06-12T00:00:00.000Z',
    authors: ['Iman Schrock'],
  },
  keywords: [
    'moral crumple zone',
    'AI agent accountability',
    'authorization receipt',
    'human-in-the-loop',
    'AI liability',
    'pre-action authorization',
  ],
};

export default function CrumpleZoneEssayPage() {
  return <EssayArticle slug={SLUG} />;
}
