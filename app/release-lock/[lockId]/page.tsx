// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import { cookies } from 'next/headers';
import { isReleaseLockDemoMode } from '../api';
import { DEMO_RELEASE_LOCK } from '../demo-fixture';
import ReleaseLockExperience from './ReleaseLockExperience';

export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Review Release Lock',
  description: 'Review and approve one exact contractor milestone or change-order version.',
};

type PageParams = { params: Promise<{ lockId: string }> };

export default async function ReleaseLockPage({ params }: PageParams) {
  const { lockId } = await params;
  const cookieStore = await cookies();
  const storedRole = cookieStore.get('release_lock_demo_role')?.value;
  const initialRole = storedRole === 'customer' ? 'customer' : 'contractor';
  const demo = isReleaseLockDemoMode();

  return (
    <ReleaseLockExperience
      lockId={lockId}
      initialLock={demo ? DEMO_RELEASE_LOCK : null}
      initialRole={initialRole}
      demo={demo}
    />
  );
}
