// SPDX-License-Identifier: Apache-2.0

import PairingIntake from './PairingIntake';

export const metadata = {
  title: 'Pair Action Mirror',
  description: 'Open one exact Release Lock approval round on a second device.',
};

export default async function ReleaseLockPairingIntake({ searchParams }) {
  const query = await searchParams;
  const lockId = typeof query?.lock_id === 'string' ? query.lock_id : '';
  const role = typeof query?.role === 'string' ? query.role : '';
  const round = typeof query?.round === 'string' ? query.round : '';
  return <PairingIntake lockId={lockId} role={role} round={round} />;
}
