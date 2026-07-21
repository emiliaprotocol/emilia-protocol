// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import ReleaseLockNew from './ReleaseLockNew';

export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Create a Release Lock',
  description: 'Invite-only creation of an exact-version contractor milestone Release Lock.',
};

type PageProps = { searchParams: Promise<{ [key: string]: string | string[] | undefined }> };

export default async function NewReleaseLockPage({ searchParams }: PageProps) {
  const query = await searchParams;
  const pilotToken = typeof query?.pilot === 'string' ? query.pilot : '';

  return <ReleaseLockNew pilotToken={pilotToken} />;
}
