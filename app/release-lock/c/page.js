// SPDX-License-Identifier: Apache-2.0

import CapabilityIntake from './CapabilityIntake';

export const metadata = {
  title: 'Release Lock invitation',
  description: 'Open a contractor or customer Release Lock invitation.',
};

export default async function ReleaseLockCapabilityIntake({ searchParams }) {
  const query = await searchParams;
  const lockId = typeof query?.lock_id === 'string' ? query.lock_id : '';
  const role = typeof query?.role === 'string' ? query.role : '';
  return <CapabilityIntake lockId={lockId} role={role} />;
}
