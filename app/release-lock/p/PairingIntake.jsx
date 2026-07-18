'use client';

// SPDX-License-Identifier: Apache-2.0

import { CircleAlert, LoaderCircle, Smartphone } from 'lucide-react';
import { useEffect, useState } from 'react';
import {
  exchangeReleaseLockPairing,
  isReleaseLockDemoMode,
} from '../api';
import ReleaseLockShell from '../ReleaseLockShell';
import styles from '../release-lock.module.css';

function fragmentToken() {
  const fragment = window.location.hash.startsWith('#')
    ? window.location.hash.slice(1)
    : window.location.hash;
  return new URLSearchParams(fragment).get('cap') || '';
}

export default function PairingIntake({ lockId, role, round }) {
  const demo = isReleaseLockDemoMode();
  const eligible = !demo
    && Boolean(lockId)
    && ['contractor', 'customer'].includes(role)
    && ['co-accepted', 'draw-release'].includes(round);
  const [status, setStatus] = useState(eligible ? 'opening' : 'unavailable');

  useEffect(() => {
    if (!eligible) return undefined;
    const token = fragmentToken();
    window.history.replaceState(null, '', '/release-lock/p');
    if (!token) {
      const timeout = window.setTimeout(() => setStatus('unavailable'), 0);
      return () => window.clearTimeout(timeout);
    }
    let active = true;
    exchangeReleaseLockPairing({
      token,
      lockId,
      role,
      round,
    })
      .then((exchange) => {
        if (active) window.location.replace(exchange.clean_path);
      })
      .catch(() => {
        if (active) setStatus('unavailable');
      });
    return () => {
      active = false;
    };
  }, [eligible, lockId, role, round]);

  const opening = status === 'opening';
  return (
    <ReleaseLockShell statusLabel={opening ? 'Pairing Action Mirror' : 'Pairing required'}>
      <main>
        <section className={styles.workspaceIntro}>
          <div>
            <span className={styles.eyebrow}>Action Mirror pairing</span>
            <h1>{opening ? 'Retrieving this exact approval round' : 'This pairing is unavailable'}</h1>
            <p>
              {opening
                ? 'The one-time capability is being exchanged for a short-lived, round-scoped phone session.'
                : 'Return to the participant workspace and create a fresh Action Mirror pairing.'}
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
            The pairing can open only one lock, role, and approval round.
          </p>
        </div>

        <div className={styles.intakeMark} aria-hidden="true">
          <Smartphone size={26} />
        </div>
      </main>
    </ReleaseLockShell>
  );
}
