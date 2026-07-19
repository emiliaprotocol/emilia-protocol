// SPDX-License-Identifier: Apache-2.0

import ReleaseLockNew from './ReleaseLockNew';

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'Create a Release Lock',
  description: 'Invite-only creation of an exact-version contractor milestone Release Lock.',
};

export default async function NewReleaseLockPage({ searchParams }) {
  const query = await searchParams;
  const pilotToken = typeof query?.pilot === 'string' ? query.pilot : '';

  return <ReleaseLockNew pilotToken={pilotToken} />;
}
