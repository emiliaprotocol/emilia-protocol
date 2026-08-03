'use client';

// SPDX-License-Identifier: Apache-2.0
import { useState, useSyncExternalStore } from 'react';

import styles from './record.module.css';

const OWNER_TOKEN = /^ear1_[0-9a-f]{64}$/;

function ownerKey(recordId: string) {
  return `emilia_agent_record_owner:${recordId}`;
}

function subscribeToStorage(onStoreChange: () => void) {
  window.addEventListener('storage', onStoreChange);
  return () => window.removeEventListener('storage', onStoreChange);
}

export default function OwnerControls({ recordId }: { recordId: string }) {
  const ownerToken = useSyncExternalStore(
    subscribeToStorage,
    () => window.localStorage.getItem(ownerKey(recordId)) ?? '',
    () => '',
  );
  const [armed, setArmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  if (!OWNER_TOKEN.test(ownerToken)) return null;

  async function revoke() {
    if (!armed) {
      setArmed(true);
      setError('');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const response = await fetch(
        `/api/agent-records/${encodeURIComponent(recordId)}/revoke`,
        {
          method: 'POST',
          headers: { authorization: `Bearer ${ownerToken}` },
          credentials: 'same-origin',
        },
      );
      if (!response.ok) throw new Error('The record could not be unpublished.');
      window.localStorage.removeItem(ownerKey(recordId));
      window.location.reload();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The record could not be unpublished.');
      setArmed(false);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className={styles.ownerControls} aria-labelledby="owner-controls-heading">
      <p className={styles.kicker}>THIS BROWSER HOLDS THE RECORD CREDENTIAL</p>
      <h2 id="owner-controls-heading">Owner controls</h2>
      <p>
        This credential controls only this public record. It is not identity or ownership proof.
        Unpublishing is permanent.
      </p>
      <button type="button" disabled={busy} onClick={revoke}>
        {busy ? 'Unpublishing…' : armed ? 'Confirm permanent unpublish' : 'Unpublish this record'}
      </button>
      {armed && !busy && <button type="button" className={styles.cancel} onClick={() => setArmed(false)}>Cancel</button>}
      {error && <p className={styles.error} role="alert">{error}</p>}
    </section>
  );
}
