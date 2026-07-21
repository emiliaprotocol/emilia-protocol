'use client';

// SPDX-License-Identifier: Apache-2.0
import {
  ArrowLeft,
  BadgeCheck,
  Check,
  CheckCircle2,
  CircleAlert,
  Fingerprint,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  ShieldCheck,
  Smartphone,
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { getReleaseLock } from '../../api';
import {
  CEREMONY_CO_ACCEPTANCE,
  CEREMONY_DRAW_RELEASE,
  selectMaterialQuestions,
} from '../../demo-fixture';
import {
  buildActionMirrorBindings,
  sha256Digest,
  shortDigest,
} from '../../digests';
import {
  approveReleaseLockWithPasskey,
  beginReleaseLockActionCheck,
  completeReleaseLockActionCheck,
  ensureReleaseLockCredential,
} from '../../passkey';
import ReleaseLockShell from '../../ReleaseLockShell';
import ReleaseLockTerms from '../../ReleaseLockTerms';
import styles from '../../release-lock.module.css';

interface ActionMirrorExperienceProps {
  lockId: string;
  ceremony: string;
  initialLock: any;
  demo?: boolean;
}

interface BindingsState {
  ceremony: string;
  action_digest: string;
  prompt_set_digest?: string;
  answer_digest?: string;
  submitted_answers?: any[];
}

interface LiveResolutionState {
  action_hash?: string;
  prompt_set_digest?: string;
  prompt_set: {
    version?: number;
    round?: string;
    role?: string;
    questions?: any[];
  };
}

export default function ActionMirrorExperience({
  lockId,
  ceremony,
  initialLock,
  demo,
}: ActionMirrorExperienceProps): React.ReactElement {
  const [lock, setLock] = useState<any>(initialLock);
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [mismatches, setMismatches] = useState<string[]>([]);
  const [bindings, setBindings] = useState<BindingsState | null>(null);
  const [stage, setStage] = useState<string>(demo ? 'questions' : 'prepare');
  const [approval, setApproval] = useState<{ credential_id?: string } | null>(null);
  const [locked, setLocked] = useState<boolean>(false);
  const [error, setError] = useState<string>('');
  const [participantRole, setParticipantRole] = useState<string>('customer');
  const [credentialEnrolled, setCredentialEnrolled] = useState<boolean>(false);
  const [liveResolution, setLiveResolution] = useState<LiveResolutionState | null>(null);
  const questions = useMemo(() => {
    if (!lock) return [];
    if (demo) return selectMaterialQuestions(lock, ceremony, 3);
    return (liveResolution?.prompt_set?.questions || []).map((question) => ({
      id: question.question_id,
      field: question.question_id.replaceAll('_', ' '),
      prompt: question.stem,
      options: question.options,
    }));
  }, [ceremony, demo, liveResolution, lock]);
  const definition = lock?.ceremonies?.[ceremony];
  const isCo = ceremony === CEREMONY_CO_ACCEPTANCE;

  useEffect(() => {
    let active = true;
    getReleaseLock(lockId)
      .then((result) => {
        if (!active) return;
        setLock(result.lock);
        if (result.role === 'contractor' || result.role === 'customer') {
          setParticipantRole(result.role);
        }
        setCredentialEnrolled(result.credential_enrolled === true);
        const ceremonyState = result.state?.ceremonies?.[ceremony];
        if (ceremony === CEREMONY_DRAW_RELEASE
          && ceremonyState?.status === 'locked_until_milestone') {
          setLocked(true);
        }
        const activeRole = result.role === 'contractor' ? 'contractor' : 'customer';
        if (ceremonyState?.approvals?.[activeRole]) {
          setApproval(ceremonyState.approvals[activeRole]);
          setStage('complete');
        }
      })
      .catch((caught) => {
        if (active) setError(caught.message || 'The canonical action could not be retrieved.');
      });
    return () => {
      active = false;
    };
  }, [ceremony, lockId]);

  if (!lock || !definition) {
    return (
      <ReleaseLockShell
        demo={demo}
        role={participantRole === 'contractor' ? 'Contractor' : 'Customer'}
        statusLabel="Independent retrieval"
      >
        <main className={styles.centeredState}>
          <LoaderCircle aria-hidden="true" size={28} className={styles.spin} />
          <span className={styles.eyebrow}>Action Mirror</span>
          <h1>Retrieving the canonical ceremony</h1>
        </main>
      </ReleaseLockShell>
    );
  }

  function choose(questionId, value) {
    setAnswers((current) => ({ ...current, [questionId]: value }));
    setMismatches((current) => current.filter((id) => id !== questionId));
    setError('');
  }

  async function beginLiveReview() {
    setStage('registering');
    setError('');
    try {
      await ensureReleaseLockCredential({
        lockId,
        role: participantRole,
        verifiedHandle: lock.contacts[participantRole].verified_handle,
        credentialAlreadyEnrolled: credentialEnrolled,
      });
      setCredentialEnrolled(true);
      const resolution = await beginReleaseLockActionCheck({
        lockId,
        ceremony,
        role: participantRole,
      });
      if (resolution.action_hash !== definition.digest
          || resolution.prompt_set?.role !== participantRole
          || resolution.prompt_set?.round !== definition.code) {
        throw new Error('The server challenge does not match this exact participant view.');
      }
      setLiveResolution(resolution);
      setAnswers({});
      setStage('questions');
    } catch (caught) {
      setError(caught.message || 'The secure review could not begin.');
      setStage('prepare');
    }
  }

  async function continueToPasskey(event) {
    event.preventDefault();
    const wrong = demo
      ? questions
        .filter((question) => answers[question.id] !== question.correct_value)
        .map((question) => question.id)
      : [];

    if (wrong.length > 0) {
      setMismatches(wrong);
      setError('One or more answers do not match the canonical action. Review the exact terms.');
      return;
    }

    setStage('binding');
    setError('');
    try {
      const submittedAnswers = demo ? null : questions.map((question) => ({
        question_id: question.id,
        option_id: answers[question.id],
      }));
      // Reaching the !demo "questions"/"binding" stages requires beginLiveReview()
      // to have already set liveResolution (it throws and reverts stage otherwise),
      // so it is guaranteed non-null here even though the type is nullable.
      const resolution = liveResolution as NonNullable<typeof liveResolution>;
      const nextBindings = demo
        ? await buildActionMirrorBindings({
          lock,
          ceremony,
          questions,
          answers,
        })
        : {
          ceremony,
          action_digest: resolution.action_hash,
          prompt_set_digest: resolution.prompt_set_digest,
          answer_digest: await sha256Digest({
            '@version': 'EP-RELEASE-LOCK-ACTION-CHECK-v1-ANSWERS',
            lock_id: lockId,
            version: resolution.prompt_set.version,
            round: resolution.prompt_set.round,
            role: resolution.prompt_set.role,
            answers: submittedAnswers,
          }),
          submitted_answers: submittedAnswers,
        };
      setBindings(nextBindings);
      setStage('passkey');
    } catch {
      setError('The Action Mirror binding could not be prepared.');
      setStage('questions');
    }
  }

  async function approve() {
    if (!bindings) return;
    setStage('signing');
    setError('');
    try {
      const result = demo
        ? await approveReleaseLockWithPasskey({
          lockId,
          ceremony,
          role: 'customer',
          verifiedHandle: lock.contacts.customer.verified_handle,
          bindings,
        })
        : await completeReleaseLockActionCheck({
          lockId,
          ceremony,
          resolution: liveResolution,
          answers: bindings.submitted_answers,
        });
      setApproval(result.approval || {
        credential_id: `${participantRole} credential recorded`,
      });
      setStage('complete');
    } catch (caught) {
      setError(caught.message || 'The participant approval was not recorded.');
      setStage('passkey');
    }
  }

  const complete = stage === 'complete';

  return (
    <ReleaseLockShell
      demo={demo}
      role={participantRole === 'contractor' ? 'Contractor' : 'Customer'}
      statusLabel={complete ? `${definition.code} recorded` : 'Action Mirror'}
    >
      <main className={styles.mirrorSurface}>
        <section className={styles.mirrorIntro}>
          <span className={styles.mirrorIcon}>
            <Smartphone aria-hidden="true" size={22} />
          </span>
          <div>
            <span className={styles.eyebrow}>
              Independent phone retrieval · round {definition.round}
            </span>
            <h1>Action Mirror</h1>
            <p>
              {definition.code} · pairing phrase <strong>{definition.pairing_phrase}</strong>
            </p>
          </div>
          <span className={styles.retrievalStatus}>
            <ShieldCheck aria-hidden="true" size={15} />
            Canonical action retrieved
          </span>
        </section>

        <ol className={styles.mirrorProgress} aria-label="Action Mirror progress">
          <li data-active="true">
            <span>1</span>
            Exact action
          </li>
          <li data-active={stage !== 'questions' ? 'true' : undefined}>
            <span>2</span>
            Term check
          </li>
          <li data-active={['passkey', 'signing', 'complete'].includes(stage) ? 'true' : undefined}>
            <span>3</span>
            Passkey
          </li>
        </ol>

        <ReleaseLockTerms lock={lock} ceremony={ceremony} />

        {locked && (
          <section className={styles.mirrorLocked} role="status">
            <LockKeyhole aria-hidden="true" size={26} />
            <span className={styles.eyebrow}>DRAW_RELEASE unavailable</span>
            <h2>Milestone evidence is not ready.</h2>
            <p>Complete CO_ACCEPTED and bind the milestone evidence before opening Round 2.</p>
            <a className={styles.primaryButton} href={`/release-lock/${encodeURIComponent(lockId)}`}>
              <ArrowLeft aria-hidden="true" size={17} />
              Return to Release Lock
            </a>
          </section>
        )}

        {!demo && !locked && !complete && stage === 'prepare' && (
          <section className={styles.bindingPanel}>
            <div className={styles.bindingHeading}>
              <ShieldCheck aria-hidden="true" size={23} />
              <div>
                <span className={styles.eyebrow}>{participantRole} seat</span>
                <h2>Begin the server-generated Action Check</h2>
              </div>
            </div>
            <div className={styles.bindingAction}>
              <p>
                The server will enroll or reuse this seat&apos;s passkey, then generate a fresh,
                randomized question set bound to this exact action and session.
              </p>
              <button type="button" className={styles.primaryButton} onClick={beginLiveReview}>
                <KeyRound aria-hidden="true" size={18} />
                Begin secure review
              </button>
            </div>
          </section>
        )}

        {!demo && !locked && !complete && stage === 'registering' && (
          <section className={styles.bindingPanel} aria-live="polite">
            <div className={styles.bindingLoading}>
              <LoaderCircle aria-hidden="true" size={18} className={styles.spin} />
              Preparing the role-scoped passkey and fresh Action Check
            </div>
          </section>
        )}

        {!locked && !complete && stage === 'questions' && (
          <form className={styles.mirrorQuestionForm} onSubmit={continueToPasskey}>
            <div className={styles.mirrorSectionHeading}>
              <div>
                <span className={styles.eyebrow}>Randomized material-field check</span>
                <h2>Match the exact {isCo ? 'change-order' : 'draw'} terms</h2>
              </div>
              <span className={styles.questionCount}>{questions.length} questions</span>
            </div>

            {questions.map((question, index) => {
              const mismatch = mismatches.includes(question.id);
              return (
                <fieldset
                  key={question.id}
                  className={styles.mirrorQuestion}
                  data-material-field={question.id}
                  aria-invalid={mismatch}
                >
                  <legend>
                    <span>{String(index + 1).padStart(2, '0')} · {question.field}</span>
                    {question.prompt}
                  </legend>
                  <div className={styles.answerOptions}>
                    {question.options.map((option) => {
                      const optionValue = typeof option === 'string' ? option : option.option_id;
                      const optionLabel = typeof option === 'string' ? option : option.label;
                      const inputId = `mirror-${question.id}-${optionValue.replaceAll(/[^a-zA-Z0-9]/g, '-')}`;
                      return (
                        <label key={optionValue} htmlFor={inputId}>
                          <input
                            id={inputId}
                            type="radio"
                            name={question.id}
                            value={optionValue}
                            checked={answers[question.id] === optionValue}
                            onChange={() => choose(question.id, optionValue)}
                          />
                          <span>{optionLabel}</span>
                          {answers[question.id] === optionValue && (
                            <Check aria-hidden="true" size={16} />
                          )}
                        </label>
                      );
                    })}
                  </div>
                  {mismatch && (
                    <p className={styles.answerMismatch}>
                      <CircleAlert aria-hidden="true" size={14} />
                      This answer does not match the retrieved action.
                    </p>
                  )}
                </fieldset>
              );
            })}

            {stage === 'questions' && (
              <div className={styles.mirrorActions}>
                <p>
                  {demo
                    ? 'Matching answers are recorded as evidence. '
                    : 'The server refuses any answer set that differs from its committed exact answers. '}
                  This does not prove comprehension, identity, or absence of coercion.
                </p>
                <button
                  type="submit"
                  className={styles.primaryButton}
                  disabled={Object.keys(answers).length !== questions.length}
                >
                  Bind answers to {definition.code}
                  <KeyRound aria-hidden="true" size={17} />
                </button>
              </div>
            )}
          </form>
        )}

        {!locked && ['binding', 'passkey', 'signing'].includes(stage) && (
          <section className={styles.bindingPanel} aria-live="polite">
            <div className={styles.bindingHeading}>
              <BadgeCheck aria-hidden="true" size={23} />
              <div>
                <span className={styles.eyebrow}>{definition.code} approval request</span>
                <h2>Three digests, one passkey request</h2>
              </div>
            </div>
            {bindings ? (
              <dl className={styles.bindingDigests}>
                <div>
                  <dt>Prompt set</dt>
                  <dd><code>{shortDigest(bindings.prompt_set_digest, 15, 10)}</code></dd>
                </div>
                <div>
                  <dt>Answers</dt>
                  <dd><code>{shortDigest(bindings.answer_digest, 15, 10)}</code></dd>
                </div>
                <div>
                  <dt>{definition.code}</dt>
                  <dd><code>{shortDigest(bindings.action_digest, 15, 10)}</code></dd>
                </div>
              </dl>
            ) : (
              <div className={styles.bindingLoading}>
                <LoaderCircle aria-hidden="true" size={18} className={styles.spin} />
                Computing canonical bindings
              </div>
            )}
            <div className={styles.bindingAction}>
              <p>
                The ceremony identifier and all three digests enter the resolution challenge
                before the passkey action.
              </p>
              <button
                type="button"
                className={styles.primaryButton}
                onClick={approve}
                disabled={stage !== 'passkey'}
              >
                {stage === 'signing'
                  ? <LoaderCircle aria-hidden="true" size={18} className={styles.spin} />
                  : <KeyRound aria-hidden="true" size={18} />}
                {stage === 'signing'
                  ? 'Waiting for passkey'
                  : `${isCo ? 'Accept' : 'Approve'} with ${demo ? 'demo ' : ''}passkey`}
              </button>
            </div>
          </section>
        )}

        {complete && (
          <section className={styles.mirrorComplete} role="status">
            <CheckCircle2 aria-hidden="true" size={34} />
            <span className={styles.eyebrow}>
              {participantRole} seat · round {definition.round}
            </span>
            <h2>{definition.code} approval recorded</h2>
            <p>
              The {participantRole} resolution binds this ceremony identifier, prompt-set digest, answer
              digest, and exact action digest.
              {isCo && ' This is not payment authority.'}
            </p>
            <code>{approval?.credential_id || `${participantRole} credential recorded`}</code>
            <a className={styles.primaryButton} href={`/release-lock/${encodeURIComponent(lockId)}`}>
              <ArrowLeft aria-hidden="true" size={17} />
              Return to Release Lock
            </a>
          </section>
        )}

        {error && (
          <div className={styles.mirrorError} role="alert">
            <CircleAlert aria-hidden="true" size={17} />
            {error}
          </div>
        )}

        <section className={styles.mirrorBoundary}>
          <Fingerprint aria-hidden="true" size={18} />
          <p>
            Action Mirror checks entered answers against this retrieved {definition.code} action
            and binds the resulting digests into that approval request.
            {isCo && ' CO_ACCEPTED is not payment authority.'} It does not prove comprehension,
            biometric identity, freedom from coercion, device-bound hardware, or enforceability.
          </p>
        </section>
      </main>
    </ReleaseLockShell>
  );
}
