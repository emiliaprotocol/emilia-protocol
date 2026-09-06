'use client';

// SPDX-License-Identifier: Apache-2.0

import { FormEvent, useState, useSyncExternalStore } from 'react';

import { color, cta, styles } from '@/lib/tokens';

const subscribeToHydration = () => () => {};
const clientReady = () => true;
const serverReady = () => false;

export default function RequestAuthorityRecord({
  recordId,
  verifiedRequesters,
  verifiedOrganizations,
}: {
  recordId: string;
  verifiedRequesters: number;
  verifiedOrganizations: number;
}) {
  const ready = useSyncExternalStore(subscribeToHydration, clientReady, serverReady);
  const [state, setState] = useState<'idle' | 'sending' | 'accepted' | 'error'>('idle');

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || state === 'sending') return;
    const form = new FormData(event.currentTarget);
    setState('sending');
    try {
      const response = await fetch(`/api/works/authority-records/${encodeURIComponent(recordId)}/requests`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: form.get('email') }),
        cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
      });
      setState(response.ok ? 'accepted' : 'error');
    } catch {
      setState('error');
    }
  }

  return (
    <section style={{ ...styles.card, marginTop: 32 }}>
      <h2 style={styles.h2}>Request this Authority Record</h2>
      <p style={{ color: color.t3 }}>
        {verifiedRequesters} independently verified request{verifiedRequesters === 1 ? '' : 's'} from{' '}
        {verifiedOrganizations} organization{verifiedOrganizations === 1 ? '' : 's'}. These are interest
        confirmations, not purchases or endorsements.
      </p>
      {state === 'accepted' ? (
        <p>Check your inbox to confirm the request. The count changes only after verification.</p>
      ) : (
        <form method="post" onSubmit={submit}>
          <noscript><p>JavaScript is required to request an email verification link securely.</p></noscript>
          <fieldset disabled={!ready || state === 'sending'} style={{ display: 'flex', gap: 12, flexWrap: 'wrap', border: 0, margin: 0, padding: 0, minWidth: 0 }}>
          <label style={{ display: 'grid', gap: 6, flex: '1 1 260px', minWidth: 0 }}>
            <span>Work email</span>
            <input required type="email" name="email" autoComplete="email" placeholder="you@company.com"
              style={{ ...styles.input, minWidth: 0 }} />
          </label>
          <button disabled={!ready || state === 'sending'} type="submit" style={{ ...cta.primary, alignSelf: 'end' }}>
            {state === 'sending' ? 'Sending…' : 'Email verification link'}
          </button>
          </fieldset>
        </form>
      )}
      {state === 'error' ? <p role="alert">We could not confirm the request. Check your inbox before trying again.</p> : null}
    </section>
  );
}
