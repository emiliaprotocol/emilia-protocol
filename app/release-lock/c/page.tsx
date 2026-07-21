// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import CapabilityIntake from './CapabilityIntake';

export const metadata: Metadata = {
  title: 'Release Lock invitation',
  description: 'Open a contractor or customer Release Lock invitation.',
};

type PageProps = { searchParams: Promise<{ [key: string]: string | string[] | undefined }> };

export default async function ReleaseLockCapabilityIntake({ searchParams }: PageProps) {
  const query = await searchParams;
  const lockId = typeof query?.lock_id === 'string' ? query.lock_id : '';
  const role = typeof query?.role === 'string' ? query.role : '';
  return <CapabilityIntake lockId={lockId} role={role} />;
}
