// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import PairingIntake from './PairingIntake';

export const metadata: Metadata = {
  title: 'Pair Action Mirror',
  description: 'Open one exact Release Lock approval round on a second device.',
};

type PageProps = { searchParams: Promise<{ [key: string]: string | string[] | undefined }> };

export default async function ReleaseLockPairingIntake({ searchParams }: PageProps) {
  const query = await searchParams;
  const lockId = typeof query?.lock_id === 'string' ? query.lock_id : '';
  const role = typeof query?.role === 'string' ? query.role : '';
  const round = typeof query?.round === 'string' ? query.round : '';
  return <PairingIntake lockId={lockId} role={role} round={round} />;
}
