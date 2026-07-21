'use client';

// SPDX-License-Identifier: Apache-2.0

import React, { useEffect, useState } from 'react';
import { CircleAlert, KeyRound, LoaderCircle } from 'lucide-react';
import { exchangeReleaseLockCapability, isReleaseLockDemoMode } from '../api';
import ReleaseLockShell from '../ReleaseLockShell';
import styles from '../release-lock.module.css';

function fragmentToken(): string {
  const fragment = window.location.hash.startsWith('#')
    ? window.location.hash.slice(1)
    : window.location.hash;
  return new URLSearchParams(fragment).get('cap') || '';
}

interface CapabilityIntakeProps {
  lockId?: string;
  role?: string;
}

export default function CapabilityIntake({ lockId, role }: CapabilityIntakeProps): React.ReactElement {
  const demo = isReleaseLockDemoMode();
  const eligible = !demo && Boolean(lockId) && ['contractor', 'customer'].includes(role || '');
  const [status, setStatus] = useState<string>(eligible ? 'opening' : 'unavailable');

  useEffect(() => {
    if (!eligible) return undefined;
    const token = fragmentToken();
    window.history.replaceState(null, '', '/release-lock/c');
    if (!token) {
      const timeout = window.setTimeout(() => setStatus('unavailable'), 0);
      return () => window.clearTimeout(timeout);
    }
    let active = true;
    exchangeReleaseLockCapability({ token, lockId, role })
      .then((exchange) => {
        if (active) window.location.replace(exchange.clean_path);
      })
      .catch(() => {
        if (active) setStatus('unavailable');
      });
    return () => {
      active = false;
    };
  }, [eligible, lockId, role]);

  const opening = status === 'opening';
  return (
    <ReleaseLockShell statusLabel={opening ? 'Opening invitation' : 'Invite required'}>
      <main>
        <section className={styles.workspaceIntro}>
          <div>
            <span className={styles.eyebrow}>Capability intake</span>
            <h1>{opening ? 'Opening your exact Release Lock' : 'This invitation is unavailable'}</h1>
            <p>
              {opening
                ? 'The single-use capability is being exchanged and removed before any terms appear.'
                : 'Ask the contractor for a current invitation. Expired, incomplete, or exchanged capabilities stay closed.'}
            </p>
          </div>
        </section>

        <div className={styles.boundaryNotice} role="status">
          {opening
            ? <LoaderCircle aria-hidden="true" size={20} className={styles.spin} />
            : <CircleAlert aria-hidden="true" size={20} />}
          <p>
            <strong>No approval has been recorded.</strong>
            {' '}
            Opening an invitation creates only a role-scoped review session.
          </p>
        </div>

        <div className={styles.intakeMark} aria-hidden="true">
          <KeyRound size={26} />
        </div>
      </main>
    </ReleaseLockShell>
  );
}
