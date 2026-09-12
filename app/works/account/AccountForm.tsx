// SPDX-License-Identifier: Apache-2.0
'use client';

import {
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
  type FormEvent,
} from 'react';

import styles from './account-form.module.css';

const subscribeToHydration = () => () => {};
const clientReady = () => true;
const serverReady = () => false;

export type WorksAccountPublic = {
  displayName: string;
  claimsVerified: false;
  emailNotifications: boolean;
};

export type AccountFormProps = {
  onAuthenticated?: (account: WorksAccountPublic) => void;
  initialMode?: 'signup' | 'login';
};

async function accountRequest(path: string, body: unknown, signal: AbortSignal) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    signal,
  });
  const result = await response.json().catch(() => null) as Record<string, unknown> | null;
  if (!response.ok) {
    const detail = typeof result?.detail === 'string' ? result.detail : 'Account sign-in is unavailable. Try again.';
    throw new Error(detail);
  }
  return result;
}

export function AccountForm({ onAuthenticated, initialMode = 'signup' }: AccountFormProps) {
  const ready = useSyncExternalStore(subscribeToHydration, clientReady, serverReady);
  const [mode, setMode] = useState<'signup' | 'login'>(initialMode);
  const [phase, setPhase] = useState<'details' | 'code' | 'done'>('details');
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [consent, setConsent] = useState(false);
  const [challengeId, setChallengeId] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => { active.current?.abort(); }, []);

  function chooseMode(next: 'signup' | 'login') {
    active.current?.abort();
    setMode(next); setPhase('details'); setChallengeId(''); setCode(''); setError(''); setBusy(false);
  }

  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || busy) return;
    const controller = new AbortController(); active.current?.abort(); active.current = controller;
    setBusy(true); setError('');
    try {
      const result = await accountRequest('/api/works/account/start', mode === 'signup'
        ? { email, name, consent }
        : { email }, controller.signal);
      if (controller.signal.aborted) return;
      if (typeof result?.challengeId !== 'string') throw new Error('No sign-in challenge was created. Try again.');
      setChallengeId(result.challengeId); setCode(''); setPhase('code');
    } catch (caught) {
      if (!controller.signal.aborted) setError(caught instanceof Error ? caught.message : 'Account sign-in is unavailable. Try again.');
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!ready || busy || !challengeId) return;
    const controller = new AbortController(); active.current?.abort(); active.current = controller;
    setBusy(true); setError('');
    try {
      const result = await accountRequest('/api/works/account/verify', {
        email, challengeId, code,
      }, controller.signal);
      if (controller.signal.aborted) return;
      const account = result?.account as WorksAccountPublic | undefined;
      if (result?.authenticated !== true || !account || typeof account.displayName !== 'string'
        || !account.displayName.trim() || account.displayName.length > 200
        || account.claimsVerified !== false || typeof account.emailNotifications !== 'boolean') {
        throw new Error('Sign-in could not be confirmed. Try again.');
      }
      setCode(''); setEmail(''); setChallengeId(''); setPhase('done');
      onAuthenticated?.(account);
    } catch (caught) {
      if (!controller.signal.aborted) {
        setCode('');
        setError(caught instanceof Error ? caught.message : 'The code could not be verified.');
      }
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }

  if (phase === 'done') return <section className={styles.confirmed} aria-live="polite">
    <p className={styles.eyebrow}>Signed in</p>
    <h3>Your Works account is ready.</h3>
    <p>Return to your draft and continue. Signing in does not publish, hire, pay, or give an agent permission to act.</p>
  </section>;

  return <section className={styles.account} aria-labelledby="works-account-heading">
    <div className={styles.heading}>
      <div>
        <p className={styles.eyebrow}>Works account</p>
        <h3 id="works-account-heading">{mode === 'signup' ? 'Create a Works account' : 'Sign in to Works'}</h3>
      </div>
      <div className={styles.switcher} role="group" aria-label="Choose account action">
        <button type="button" aria-pressed={mode === 'signup'} onClick={() => chooseMode('signup')}>Create account</button>
        <button type="button" aria-pressed={mode === 'login'} onClick={() => chooseMode('login')}>Sign in</button>
      </div>
    </div>
    <noscript><p>JavaScript is required to verify your email securely. The form stays disabled until it is ready.</p></noscript>

    {phase === 'details' ? <form method="post" onSubmit={start} className={styles.form}>
      <fieldset disabled={!ready || busy}>
        {mode === 'signup' ? <label>
          <span>Name shown on your Works posts</span>
          <input value={name} onChange={event => setName(event.target.value)} required minLength={2} maxLength={100} autoComplete="name" />
        </label> : null}
        <label>
          <span>Email</span>
          <input type="email" value={email} onChange={event => setEmail(event.target.value)} required maxLength={254} autoComplete="email" inputMode="email" />
        </label>
        {mode === 'signup' ? <>
          <label className={styles.check}>
            <input type="checkbox" checked={consent} onChange={event => setConsent(event.target.checked)} required />
            <span>I agree to create an EMILIA Works account and use this name on anything I choose to publish.</span>
          </label>
        </> : null}
        <button className={styles.primary} type="submit" disabled={!ready || busy}>{busy ? 'Sending code…' : 'Email me a code'}</button>
      </fieldset>
    </form> : <form method="post" onSubmit={verify} className={styles.form}>
      <fieldset disabled={!ready || busy}>
        <p>Enter the six-digit code sent to <strong>{email}</strong>. It expires in 10 minutes and works once.</p>
        <label>
          <span>Verification code</span>
          <input value={code} onChange={event => setCode(event.target.value.replace(/\D/g, '').slice(0, 6))}
            required pattern="[0-9]{6}" minLength={6} maxLength={6} inputMode="numeric" autoComplete="one-time-code" />
        </label>
        <div className={styles.actions}>
          <button className={styles.primary} type="submit" disabled={!ready || busy || code.length !== 6}>{busy ? 'Checking code…' : 'Verify and continue'}</button>
          <button type="button" className={styles.secondary} onClick={() => { setPhase('details'); setCode(''); setChallengeId(''); setError(''); }}>Use a different email</button>
        </div>
      </fieldset>
    </form>}

    {error ? <p className={styles.error} role="alert">{error}</p> : null}
    <p className={styles.note}>Your email is verified for account recovery. This does not verify your organization or any agent claim, and it does not give an agent permission to act.</p>
  </section>;
}

export default AccountForm;
