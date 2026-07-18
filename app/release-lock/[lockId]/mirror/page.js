// SPDX-License-Identifier: Apache-2.0

import { isReleaseLockDemoMode } from '../../api';
import {
  CEREMONY_CO_ACCEPTANCE,
  CEREMONY_DRAW_RELEASE,
  DEMO_RELEASE_LOCK,
} from '../../demo-fixture';
import ActionMirrorExperience from './ActionMirrorExperience';

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'Action Mirror',
  description: 'Independently retrieve and approve one exact Release Lock action.',
};

export default async function ActionMirrorPage({ params, searchParams }) {
  const { lockId } = await params;
  const query = await searchParams;
  const ceremony = query?.ceremony === CEREMONY_DRAW_RELEASE
    ? CEREMONY_DRAW_RELEASE
    : CEREMONY_CO_ACCEPTANCE;
  const demo = isReleaseLockDemoMode();

  return (
    <ActionMirrorExperience
      lockId={lockId}
      ceremony={ceremony}
      initialLock={demo ? DEMO_RELEASE_LOCK : null}
      demo={demo}
    />
  );
}
