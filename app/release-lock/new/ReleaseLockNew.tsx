'use client';

// SPDX-License-Identifier: Apache-2.0
import {
  ArrowRight,
  BadgeCheck,
  CalendarClock,
  CircleAlert,
  FileKey2,
  Landmark,
  LoaderCircle,
  UsersRound,
} from 'lucide-react';
import { useMemo, useState } from 'react';
import {
  createReleaseLock,
  isReleaseLockDemoMode,
  isReleaseLockDemoPilotToken,
} from '../api';
import {
  buildDemoLock,
  CEREMONY_CO_ACCEPTANCE,
  CEREMONY_DRAW_RELEASE,
  releaseLockFormDefaults,
} from '../demo-fixture';
import ReleaseLockShell from '../ReleaseLockShell';
import ReleaseLockTerms from '../ReleaseLockTerms';
import styles from '../release-lock.module.css';

interface FieldProps {
  children: React.ReactNode;
  className?: string;
}

function Field({ children, className = '' }: FieldProps) {
  return <div className={`${styles.field} ${className}`}>{children}</div>;
}

interface ReleaseLockNewProps {
  pilotToken?: string;
}

export default function ReleaseLockNew({ pilotToken }: ReleaseLockNewProps) {
  const demo = isReleaseLockDemoMode();
  const [form, setForm] = useState<Record<string, any>>(() => releaseLockFormDefaults());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const hasPilotInvite = isReleaseLockDemoPilotToken(pilotToken);
  const preview = useMemo(() => buildDemoLock(form), [form]);

  const update = (field: string) => (event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    setForm((current) => ({ ...current, [field]: event.target.value }));
  };

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!hasPilotInvite || busy) return;
    setBusy(true);
    setError('');

    try {
      const result = await createReleaseLock({
        pilotToken,
        lock: form,
      });
      if (result.demo) {
        document.cookie = 'release_lock_demo_role=contractor; Path=/release-lock; SameSite=Lax';
      }
      window.location.assign(result.clean_path);
    } catch (caught) {
      setError(caught.message || 'Release Lock could not be created.');
      setBusy(false);
    }
  }

  if (!hasPilotInvite) {
    return (
      <ReleaseLockShell
        demo={demo}
        statusLabel={demo ? 'Demo link required' : 'Server integration required'}
      >
        <main className={styles.centeredState}>
          <CircleAlert aria-hidden="true" size={28} />
          <span className={styles.eyebrow}>
            {demo ? 'Deterministic demonstration' : 'Production boundary'}
          </span>
          <h1>
            {demo
              ? 'This demo creation link is invalid.'
              : 'Live creation starts from an authenticated integration.'}
          </h1>
          <p>
            {demo
              ? 'Open the published Release Lock demo link to run the fixed scenario.'
              : 'The public browser never receives an organization API key or treats a URL token as verified.'}
          </p>
        </main>
      </ReleaseLockShell>
    );
  }

  return (
    <ReleaseLockShell demo={demo} statusLabel="Demo link accepted">
      <main>
        <section className={styles.workspaceIntro}>
          <div>
            <span className={styles.eyebrow}>Contractor creation</span>
            <h1>Create a Release Lock</h1>
            <p>Define the separate change-order acceptance and later draw-release ceremonies.</p>
          </div>
          <span className={styles.inviteStatus}>
            <BadgeCheck aria-hidden="true" size={17} />
            Demo link verified
          </span>
        </section>

        <section className={styles.boundaryNotice} aria-label="Release Lock boundaries">
          <FileKey2 aria-hidden="true" size={21} />
          <p>
            Each round records two separately enrolled passkey credentials approving the same
            exact immutable action version. Round 1 accepts the change order and is not payment
            authority. Only both Round 2 DRAW_RELEASE approvals can make the custodian instruction
            eligible. Release Lock does not hold funds, judge work, or prove legal enforceability.
          </p>
        </section>

        <div className={styles.creationLayout}>
          <form className={styles.creationForm} onSubmit={submit}>
            <fieldset className={styles.formSection}>
              <legend>
                <span>01</span>
                Milestone
              </legend>
              <div className={styles.fieldGrid}>
                <Field>
                  <label htmlFor="release-lock-project">Project</label>
                  <input
                    id="release-lock-project"
                    value={form.project}
                    onChange={update('project')}
                    autoComplete="organization"
                    required
                  />
                </Field>
                <Field>
                  <label htmlFor="release-lock-title">Milestone / change-order title</label>
                  <input
                    id="release-lock-title"
                    value={form.title}
                    onChange={update('title')}
                    required
                  />
                </Field>
                <Field className={styles.fieldWide}>
                  <label htmlFor="release-lock-scope">Scope summary</label>
                  <textarea
                    id="release-lock-scope"
                    value={form.scope_summary}
                    onChange={update('scope_summary')}
                    rows={4}
                    required
                  />
                  <small>State the work and any included change order precisely.</small>
                </Field>
                <Field className={styles.fieldWide}>
                  <label htmlFor="release-lock-schedule">Schedule effect</label>
                  <input
                    id="release-lock-schedule"
                    value={form.schedule_effect}
                    onChange={update('schedule_effect')}
                    required
                  />
                  <small>State the exact calendar or completion-date effect of this version.</small>
                </Field>
              </div>
            </fieldset>

            <fieldset className={styles.formSection}>
              <legend>
                <span>02</span>
                Round 1 · Change-order price
              </legend>
              <div className={styles.fieldGrid}>
                <Field>
                  <label htmlFor="release-lock-amount">Change-order price effect</label>
                  <div className={styles.amountControl}>
                    <span aria-hidden="true">$</span>
                    <input
                      id="release-lock-amount"
                      inputMode="decimal"
                      min="0.01"
                      step="0.01"
                      type="number"
                      value={form.amount}
                      onChange={update('amount')}
                      required
                    />
                  </div>
                </Field>
                <Field>
                  <label htmlFor="release-lock-currency">Currency</label>
                  <select
                    id="release-lock-currency"
                    value={form.currency}
                    onChange={update('currency')}
                    required
                  >
                    <option value="USD">USD · US dollar</option>
                    <option value="CAD">CAD · Canadian dollar</option>
                    <option value="EUR">EUR · Euro</option>
                    <option value="GBP">GBP · Pound sterling</option>
                  </select>
                </Field>
                <p className={styles.fieldSectionNotice}>
                  <strong>CO_ACCEPTED is not payment authority.</strong>
                  Both parties accept the exact document, scope, price, and schedule effect only.
                </p>
              </div>
            </fieldset>

            <fieldset className={styles.formSection}>
              <legend>
                <span>03</span>
                Round 2 · Draw release instruction
              </legend>
              <div className={styles.fieldGrid}>
                <Field>
                  <label htmlFor="release-lock-draw-id">Draw ID</label>
                  <input
                    id="release-lock-draw-id"
                    value={form.draw_id}
                    onChange={update('draw_id')}
                    required
                  />
                </Field>
                <Field>
                  <label htmlFor="release-lock-draw-amount">Exact draw / release amount</label>
                  <div className={styles.amountControl}>
                    <span aria-hidden="true">$</span>
                    <input
                      id="release-lock-draw-amount"
                      inputMode="decimal"
                      min="0.01"
                      step="0.01"
                      type="number"
                      value={form.draw_amount}
                      onChange={update('draw_amount')}
                      required
                    />
                  </div>
                </Field>
                <Field>
                  <label htmlFor="release-lock-payee-one">Payee 1</label>
                  <input
                    id="release-lock-payee-one"
                    value={form.payee_one}
                    onChange={update('payee_one')}
                    required
                  />
                </Field>
                <Field>
                  <label htmlFor="release-lock-payee-one-amount">Payee 1 amount</label>
                  <input
                    id="release-lock-payee-one-amount"
                    value={form.payee_one_amount}
                    onChange={update('payee_one_amount')}
                    required
                  />
                </Field>
                <Field>
                  <label htmlFor="release-lock-payee-two">Payee 2</label>
                  <input
                    id="release-lock-payee-two"
                    value={form.payee_two}
                    onChange={update('payee_two')}
                    required
                  />
                </Field>
                <Field>
                  <label htmlFor="release-lock-payee-two-amount">Payee 2 amount</label>
                  <input
                    id="release-lock-payee-two-amount"
                    value={form.payee_two_amount}
                    onChange={update('payee_two_amount')}
                    required
                  />
                </Field>
                <Field className={styles.fieldWide}>
                  <label htmlFor="release-lock-custodian">Custodian</label>
                  <input
                    id="release-lock-custodian"
                    value={form.custodian}
                    onChange={update('custodian')}
                    required
                  />
                </Field>
                <Field className={styles.fieldWide}>
                  <label htmlFor="release-lock-instruction">
                    Recipient / custodian instruction
                  </label>
                  <textarea
                    id="release-lock-instruction"
                    value={form.recipient_instruction}
                    onChange={update('recipient_instruction')}
                    rows={3}
                    required
                  />
                  <small>
                    This remains blocked until both DRAW_RELEASE approvals bind to the exact draw
                    and evidence set. Release Lock does not custody or move funds.
                  </small>
                </Field>
              </div>
            </fieldset>

            <fieldset className={styles.formSection}>
              <legend>
                <span>04</span>
                Documents, milestone evidence, and expiry
              </legend>
              <div className={styles.fieldGrid}>
                <Field>
                  <label htmlFor="release-lock-document">Change-order document reference</label>
                  <input
                    id="release-lock-document"
                    value={form.document_reference}
                    onChange={update('document_reference')}
                    required
                  />
                </Field>
                <Field>
                  <label htmlFor="release-lock-expiration">Change-order acceptance expiration</label>
                  <div className={styles.iconInput}>
                    <CalendarClock aria-hidden="true" size={17} />
                    <input
                      id="release-lock-expiration"
                      type="datetime-local"
                      value={form.expiration}
                      onChange={update('expiration')}
                      required
                    />
                  </div>
                </Field>
                <Field className={styles.fieldWide}>
                  <label htmlFor="release-lock-digest">Change-order document digest</label>
                  <input
                    id="release-lock-digest"
                    className={styles.monoInput}
                    value={form.document_digest}
                    onChange={update('document_digest')}
                    pattern="sha256:[0-9a-fA-F]{64}"
                    spellCheck="false"
                    required
                  />
                  <small>SHA-256 of the exact referenced document bytes.</small>
                </Field>
                <Field>
                  <label htmlFor="release-lock-completion-reference">
                    Completion evidence reference
                  </label>
                  <input
                    id="release-lock-completion-reference"
                    value={form.completion_evidence_reference}
                    onChange={update('completion_evidence_reference')}
                    required
                  />
                </Field>
                <Field>
                  <label htmlFor="release-lock-lien-reference">Lien-waiver evidence reference</label>
                  <input
                    id="release-lock-lien-reference"
                    value={form.lien_waiver_reference}
                    onChange={update('lien_waiver_reference')}
                    required
                  />
                </Field>
                <Field>
                  <label htmlFor="release-lock-completion-digest">Completion evidence digest</label>
                  <input
                    id="release-lock-completion-digest"
                    className={styles.monoInput}
                    value={form.completion_evidence_digest}
                    onChange={update('completion_evidence_digest')}
                    pattern="sha256:[0-9a-fA-F]{64}"
                    spellCheck="false"
                    required
                  />
                </Field>
                <Field>
                  <label htmlFor="release-lock-lien-digest">Lien-waiver evidence digest</label>
                  <input
                    id="release-lock-lien-digest"
                    className={styles.monoInput}
                    value={form.lien_waiver_digest}
                    onChange={update('lien_waiver_digest')}
                    pattern="sha256:[0-9a-fA-F]{64}"
                    spellCheck="false"
                    required
                  />
                </Field>
              </div>
            </fieldset>

            <fieldset className={styles.formSection}>
              <legend>
                <span>05</span>
                Separately verified contacts
              </legend>
              <div className={styles.fieldGrid}>
                <Field>
                  <label htmlFor="release-lock-contractor">Contractor verified contact handle</label>
                  <div className={styles.iconInput}>
                    <UsersRound aria-hidden="true" size={17} />
                    <input
                      id="release-lock-contractor"
                      value={form.contractor_handle}
                      onChange={update('contractor_handle')}
                      autoComplete="email"
                      required
                    />
                  </div>
                </Field>
                <Field>
                  <label htmlFor="release-lock-customer">Customer verified contact handle</label>
                  <div className={styles.iconInput}>
                    <UsersRound aria-hidden="true" size={17} />
                    <input
                      id="release-lock-customer"
                      value={form.customer_handle}
                      onChange={update('customer_handle')}
                      autoComplete="email"
                      required
                    />
                  </div>
                </Field>
              </div>
            </fieldset>

            {error && (
              <div className={styles.formError} role="alert">
                <CircleAlert aria-hidden="true" size={17} />
                {error}
              </div>
            )}

            <div className={styles.formActions}>
              <div>
                <Landmark aria-hidden="true" size={18} />
                <span>No account or funds are created in this demo.</span>
              </div>
              <button type="submit" className={styles.primaryButton} disabled={busy}>
                {busy ? (
                  <LoaderCircle aria-hidden="true" size={18} className={styles.spin} />
                ) : (
                  <FileKey2 aria-hidden="true" size={18} />
                )}
                {busy ? 'Creating exact version' : 'Create Release Lock'}
                {!busy && <ArrowRight aria-hidden="true" size={17} />}
              </button>
            </div>
          </form>

          <aside className={styles.creationPreview} aria-label="Exact version preview">
            <ReleaseLockTerms
              lock={preview}
              ceremony={CEREMONY_CO_ACCEPTANCE}
              compact
            />
            <div className={styles.previewRoundDivider}>
              <span>After milestone evidence</span>
            </div>
            <ReleaseLockTerms
              lock={preview}
              ceremony={CEREMONY_DRAW_RELEASE}
              compact
            />
            <div className={styles.previewSeats}>
              <span className={styles.eyebrow}>Required seats</span>
              <div>
                <BadgeCheck aria-hidden="true" size={17} />
                <span>Contractor</span>
                <code>{form.contractor_handle}</code>
              </div>
              <div>
                <BadgeCheck aria-hidden="true" size={17} />
                <span>Customer</span>
                <code>{form.customer_handle}</code>
              </div>
            </div>
          </aside>
        </div>
      </main>
    </ReleaseLockShell>
  );
}
