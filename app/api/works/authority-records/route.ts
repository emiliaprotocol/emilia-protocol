// SPDX-License-Identifier: Apache-2.0

import { listPublicAuthorityRecords } from '@/lib/works/authority-record-service';
import {
  authorityRecordFailure,
  authorityRecordNotFound,
  authorityRecordStore,
  authorityRecordsEnabled,
  json,
} from './_shared';

export async function GET() {
  if (!authorityRecordsEnabled()) return authorityRecordNotFound();
  try {
    const records = await listPublicAuthorityRecords({ store: authorityRecordStore() });
    return json({ records });
  } catch (error) {
    return authorityRecordFailure(error);
  }
}
