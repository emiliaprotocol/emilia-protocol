// SPDX-License-Identifier: Apache-2.0
// EP Essay — "Why Authorization Is Not Proof".
// @license Apache-2.0

import type { Metadata } from 'next';
import EssayArticle from '@/components/EssayArticle';

const SLUG = 'why-authorization-is-not-proof';
const TITLE = 'Why Authorization Is Not Proof';
const DESCRIPTION =
  'Decision logs are testimony; receipts are evidence. A log records what the ' +
  'operator says happened. A receipt is something a named human signed, that ' +
  'anyone can verify, that survives the operator.';
const URL = 'https://www.emiliaprotocol.ai/essays/why-authorization-is-not-proof';

export const metadata: Metadata = {
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
    'authorization receipt',
    'decision logs vs receipts',
    'verifiable authorization',
    'AI agent authorization',
    'offline verification',
    'pre-action authorization',
  ],
};

export default function AuthorizationIsNotProofEssayPage(): React.JSX.Element {
  return <EssayArticle slug={SLUG} />;
}
