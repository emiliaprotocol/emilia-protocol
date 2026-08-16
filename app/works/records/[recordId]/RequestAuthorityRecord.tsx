'use client';

// SPDX-License-Identifier: Apache-2.0

import { FormEvent, useState } from 'react';

import { color, cta, styles } from '@/lib/tokens';

export default function RequestAuthorityRecord({
  recordId,
  verifiedRequesters,
  verifiedOrganizations,
}: {
  recordId: string;
  verifiedRequesters: number;
  verifiedOrganizations: number;
}) {
  const [state, setState] = useState<'idle' | 'sending' | 'accepted' | 'error'>('idle');

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setState('sending');
    const response = await fetch(`/api/works/authority-records/${encodeURIComponent(recordId)}/requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: form.get('email') }),
    });
    setState(response.ok ? 'accepted' : 'error');
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
        <form onSubmit={submit} style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <input required type="email" name="email" autoComplete="email" placeholder="Work email"
            style={{ ...styles.input, minWidth: 260 }} />
          <button disabled={state === 'sending'} type="submit" style={cta.primary}>
            {state === 'sending' ? 'Sending…' : 'Email verification link'}
          </button>
        </form>
      )}
      {state === 'error' ? <p role="alert">The request could not be recorded. Please try again.</p> : null}
    </section>
  );
}
