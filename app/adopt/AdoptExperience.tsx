'use client';

// SPDX-License-Identifier: Apache-2.0
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/browser';
import { useEffect, useState } from 'react';
import styles from './adopt.module.css';

const STAGES = [
  { id: 'agent', number: '01', label: 'Agent' },
  { id: 'job', number: '02', label: 'Job' },
  { id: 'allowance', number: '03', label: 'Allowance' },
  { id: 'passkey', number: '04', label: 'Passkey' },
  { id: 'try', number: '05', label: 'Try' },
  { id: 'share', number: '06', label: 'Share' },
] as const;

const AGENT_SOURCE_TEMPLATES = [
  {
    id: 'source_local_v1',
    kind: 'local',
    marker: 'LOC',
    name: 'Local or custom',
    detail: 'A local process, custom agent, or private prototype.',
  },
  {
    id: 'source_github_v1',
    kind: 'github',
    marker: 'GIT',
    name: 'GitHub project',
    detail: 'A repository URL used only as inert source metadata.',
  },
  {
    id: 'source_mcp_v1',
    kind: 'mcp',
    marker: 'MCP',
    name: 'MCP agent',
    detail: 'An MCP-based agent without connecting a server or credential.',
  },
  {
    id: 'source_a2a_v1',
    kind: 'a2a',
    marker: 'A2A',
    name: 'A2A agent',
    detail: 'An A2A-shaped agent described without network discovery.',
  },
] as const;

const JOB_TEMPLATES = [
  {
    id: 'job_vendor_intake_v1',
    marker: '01',
    name: 'Vendor intake',
    detail: 'Route a synthetic vendor request through an approved demo destination.',
    target: 'vendor.demo',
  },
  {
    id: 'job_compute_batch_v1',
    marker: '02',
    name: 'Batch compute request',
    detail: 'Ask for a bounded, simulated compute allocation inside the Arena.',
    target: 'compute.batch',
  },
  {
    id: 'job_document_route_v1',
    marker: '03',
    name: 'Document routing',
    detail: 'Test whether a synthetic document action fits a declared route.',
    target: 'documents.demo',
  },
] as const;

const ALLOWANCE_TEMPLATES = [
  {
    id: 'allowance_cautious_v1',
    marker: 'S',
    name: 'Cautious',
    total: 200,
    perAction: 40,
    detail: 'A narrow envelope that makes boundary crossings easy to see.',
  },
  {
    id: 'allowance_balanced_v1',
    marker: 'M',
    name: 'Balanced',
    total: 500,
    perAction: 100,
    detail: 'Enough synthetic room for several ordinary challenge attempts.',
  },
  {
    id: 'allowance_stretch_v1',
    marker: 'L',
    name: 'Stretch',
    total: 1000,
    perAction: 250,
    detail: 'A larger counter with the same hard target and action limits.',
  },
] as const;

const ATTEMPT_TEMPLATES = [
  {
    id: 'attempt_in_bounds_v1',
    tone: 'permit',
    name: 'Routine request',
    detail: 'Inside the approved target and per-action limit.',
    target: 'approved demo target',
    credits: 30,
  },
  {
    id: 'attempt_over_limit_v1',
    tone: 'refuse',
    name: 'Oversized request',
    detail: 'Crosses the selected per-action allowance.',
    target: 'approved demo target',
    credits: 900,
  },
  {
    id: 'attempt_unlisted_target_v1',
    tone: 'refuse',
    name: 'Unlisted destination',
    detail: 'Uses a target outside the declared job boundary.',
    target: 'unlisted.demo',
    credits: 20,
  },
] as const;

type StageId = (typeof STAGES)[number]['id'];
type AgentSourceTemplateId = (typeof AGENT_SOURCE_TEMPLATES)[number]['id'];
type AgentSourceKind = (typeof AGENT_SOURCE_TEMPLATES)[number]['kind'];
type JobTemplateId = (typeof JOB_TEMPLATES)[number]['id'];
type AllowanceTemplateId = (typeof ALLOWANCE_TEMPLATES)[number]['id'];
type AttemptTemplateId = (typeof ATTEMPT_TEMPLATES)[number]['id'];
type TemplateId = AgentSourceTemplateId | JobTemplateId | AllowanceTemplateId | AttemptTemplateId | 'none';

export type AdoptDecision = 'permit' | 'refuse';

export interface AdoptSession {
  session_id: string;
  expires_at: string;
  authority_state: 'draft' | 'asserted' | 'revoked';
  passkey_asserted: boolean;
  bond_id?: string;
  bond_digest?: string;
  trial_token?: string;
  trial_expires_at?: string;
  recovery?: {
    label?: string;
    source_kind?: AgentSourceKind;
    job_template_id?: JobTemplateId;
    allowance_template_id?: AllowanceTemplateId;
  };
}

export interface AdoptAttempt {
  attempt_id: string;
  template_id: AttemptTemplateId;
  decision: AdoptDecision;
  reason_code: 'within_allowance' | 'per_action_limit_exceeded' | 'target_not_allowed' | 'allowance_exhausted';
  synthetic_credits: number;
  target_template_id: string;
  action_digest: string;
  refusal_digest?: string;
  share_url?: string;
}

export interface CreateAdoptSessionRequest {
  label: string;
  source_kind: AgentSourceKind;
  source_url?: string;
  job_template_id: JobTemplateId;
  allowance_template_id: AllowanceTemplateId;
}

interface PasskeyRegistrationOptionsResponse {
  ceremony_token: string;
  options: PublicKeyCredentialCreationOptionsJSON;
}

interface PasskeyRegistrationResponse {
  credential_id: string;
}

interface PasskeyAssertionOptionsResponse {
  ceremony_token: string;
  options: PublicKeyCredentialRequestOptionsJSON;
}

interface PublishedOperatingBond {
  share_url: string;
  published_at: string;
}

interface RevokedSession {
  authority_state: 'revoked';
  revoked_at: string;
}

export interface AdoptApiClient {
  createSession(request: CreateAdoptSessionRequest): Promise<AdoptSession>;
  recoverSession?(sessionId: string): Promise<AdoptSession>;
  assertPasskey(session: AdoptSession): Promise<AdoptSession>;
  provisionTrial?(session: AdoptSession): Promise<AdoptSession>;
  runAttempt(session: AdoptSession, templateId: AttemptTemplateId): Promise<AdoptAttempt>;
  publishOperatingBond(session: AdoptSession): Promise<PublishedOperatingBond>;
  revokeSession(session: AdoptSession): Promise<RevokedSession>;
}

type ApiProblem = { detail?: unknown; title?: unknown };

const ADOPT_API_BASE = '/api/adopt/sessions';

async function requestJson<T>(url: string, init: RequestInit): Promise<T> {
  const response = await fetch(url, { credentials: 'same-origin', ...init });
  const data = await response.json().catch(() => null) as (T & ApiProblem) | null;

  if (!response.ok) {
    const detail = typeof data?.detail === 'string'
      ? data.detail
      : typeof data?.title === 'string'
        ? data.title
        : 'The adoption session could not continue.';
    throw new Error(detail);
  }

  if (!data) throw new Error('The adoption service returned an empty response.');
  return data;
}

function authorized(session: AdoptSession, body?: unknown): RequestInit {
  return {
    method: 'POST',
    headers: {
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  };
}

/**
 * Parent integration seam. All adoption traffic is rooted under
 * /api/adopt/sessions and can be replaced by passing a different client.
 */
export const adoptApiClient: AdoptApiClient = {
  createSession(request) {
    return requestJson<AdoptSession>(ADOPT_API_BASE, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(request),
    });
  },

  recoverSession(sessionId) {
    return requestJson<AdoptSession>(
      ADOPT_API_BASE + '/' + encodeURIComponent(sessionId),
      { method: 'GET' },
    );
  },

  async assertPasskey(session) {
    const registration = await requestJson<PasskeyRegistrationOptionsResponse>(
      ADOPT_API_BASE + '/' + encodeURIComponent(session.session_id) + '/passkey/register/options',
      authorized(session),
    );
    const { startAuthentication, startRegistration } = await import('@simplewebauthn/browser');
    const attestation: RegistrationResponseJSON = await startRegistration({
      optionsJSON: registration.options,
    });
    const registered = await requestJson<PasskeyRegistrationResponse>(
      ADOPT_API_BASE + '/' + encodeURIComponent(session.session_id) + '/passkey/register/verify',
      authorized(session, {
        ceremony_token: registration.ceremony_token,
        attestation,
      }),
    );
    const assertionOptions = await requestJson<PasskeyAssertionOptionsResponse>(
      ADOPT_API_BASE + '/' + encodeURIComponent(session.session_id) + '/passkey/assert/options',
      authorized(session, { credential_id: registered.credential_id }),
    );
    const assertion: AuthenticationResponseJSON = await startAuthentication({
      optionsJSON: assertionOptions.options,
    });
    const assertedSession = await requestJson<AdoptSession>(
      ADOPT_API_BASE + '/' + encodeURIComponent(session.session_id) + '/passkey/assert/verify',
      authorized(session, {
        ceremony_token: assertionOptions.ceremony_token,
        assertion,
      }),
    );
    const trial = await requestJson<AdoptSession>(
      ADOPT_API_BASE + '/' + encodeURIComponent(session.session_id) + '/trial',
      authorized(assertedSession),
    );
    return { ...assertedSession, ...trial };
  },

  runAttempt(session, templateId) {
    return requestJson<AdoptAttempt>(
      ADOPT_API_BASE + '/' + encodeURIComponent(session.session_id) + '/attempts',
      authorized(session, {
        attempt_template_id: templateId,
        trial_token: session.trial_token,
      }),
    );
  },

  async provisionTrial(session) {
    const trial = await requestJson<AdoptSession>(
      ADOPT_API_BASE + '/' + encodeURIComponent(session.session_id) + '/trial',
      authorized(session),
    );
    return { ...session, ...trial };
  },

  publishOperatingBond(session) {
    return requestJson<PublishedOperatingBond>(
      ADOPT_API_BASE + '/' + encodeURIComponent(session.session_id) + '/share',
      authorized(session, { bond_id: session.bond_id }),
    );
  },

  revokeSession(session) {
    return requestJson<RevokedSession>(
      ADOPT_API_BASE + '/' + encodeURIComponent(session.session_id) + '/revoke',
      authorized(session),
    );
  },
};

type AdoptEventName =
  | 'template_selected'
  | 'stage_advanced'
  | 'passkey_started'
  | 'passkey_asserted'
  | 'attempt_started'
  | 'attempt_permitted'
  | 'attempt_refused'
  | 'publication_confirmed'
  | 'publication_created'
  | 'share_link_copied'
  | 'revocation_started'
  | 'revocation_completed'
  | 'pilot_cta_opened';

export interface AdoptUiEvent {
  event: AdoptEventName;
  stage: StageId;
  template_id: TemplateId;
}

/**
 * Non-PII analytics hook. It dispatches enum values and template IDs only;
 * no session, credential, user, organization, or free-text data is included.
 */
function emitAdoptEvent(detail: AdoptUiEvent) {
  window.dispatchEvent(new CustomEvent<AdoptUiEvent>('emilia:adopt-event', { detail }));
}

const REASON_COPY: Record<AdoptAttempt['reason_code'], string> = {
  within_allowance: 'The exact request stayed inside the declared target and allowance.',
  per_action_limit_exceeded: 'The request crossed the selected per-action limit.',
  target_not_allowed: 'The request named a destination outside the declared job boundary.',
  allowance_exhausted: 'The request crossed the remaining synthetic allowance.',
};

interface ChoiceCardProps {
  checked: boolean;
  detail: string;
  marker: string;
  meta?: string;
  name: string;
  group: string;
  onChange: () => void;
}

function ChoiceCard({ checked, detail, marker, meta, name, group, onChange }: ChoiceCardProps) {
  return (
    <label className={checked ? styles.choiceCardSelected : styles.choiceCard}>
      <input type="radio" name={group} checked={checked} onChange={onChange} />
      <span className={styles.choiceMarker} aria-hidden="true">{marker}</span>
      <span className={styles.choiceCopy}>
        <strong>{name}</strong>
        <span>{detail}</span>
        {meta && <small>{meta}</small>}
      </span>
      <span className={styles.choiceCheck} aria-hidden="true">{checked ? '✓' : ''}</span>
    </label>
  );
}

function fingerprint(value?: string) {
  if (!value) return 'pending';
  return value.length > 30 ? value.slice(0, 18) + '…' + value.slice(-8) : value;
}

function getPublicArtifactId(shareUrl?: string): string {
  const id = shareUrl?.split('/').at(-1) ?? '';
  return /^agent_share_[0-9a-f]{40}$/.test(id) ? id : '';
}

interface AdoptExperienceProps {
  api?: AdoptApiClient;
}

export default function AdoptExperience({ api = adoptApiClient }: AdoptExperienceProps) {
  const [stageIndex, setStageIndex] = useState(0);
  const [furthestStage, setFurthestStage] = useState(0);
  const [agentLabel, setAgentLabel] = useState('Atlas');
  const [agentSourceTemplateId, setAgentSourceTemplateId] = useState<AgentSourceTemplateId>('source_local_v1');
  const [sourceUrl, setSourceUrl] = useState('');
  const [jobTemplateId, setJobTemplateId] = useState<JobTemplateId | null>(null);
  const [allowanceTemplateId, setAllowanceTemplateId] = useState<AllowanceTemplateId | null>(null);
  const [session, setSession] = useState<AdoptSession | null>(null);
  const [attempts, setAttempts] = useState<AdoptAttempt[]>([]);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [status, setStatus] = useState('Describe the agent you want to test.');
  const [publicationConfirmed, setPublicationConfirmed] = useState(false);
  const [revokeArmed, setRevokeArmed] = useState(false);

  const currentStage = STAGES[stageIndex];
  const selectedAgentSource = AGENT_SOURCE_TEMPLATES.find((item) => item.id === agentSourceTemplateId)!;
  const selectedJob = JOB_TEMPLATES.find((item) => item.id === jobTemplateId);
  const selectedAllowance = ALLOWANCE_TEMPLATES.find((item) => item.id === allowanceTemplateId);
  const latestAttempt = attempts.at(-1);
  const publishedAttempt = [...attempts].reverse().find((attempt) => Boolean(attempt.share_url));
  const publicArtifactId = getPublicArtifactId(publishedAttempt?.share_url);
  const pilotHref = publicArtifactId
    ? `/pilot?artifact_id=${encodeURIComponent(publicArtifactId)}`
    : '/pilot';
  const revoked = session?.authority_state === 'revoked';
  const sourceUrlValid = !sourceUrl || (() => {
    try {
      const parsed = new URL(sourceUrl);
      return parsed.protocol === 'https:' && !parsed.username && !parsed.password
        && !parsed.search && !parsed.hash && !parsed.port && parsed.href === sourceUrl;
    } catch {
      return false;
    }
  })();
  const agentReady = agentLabel.trim().length > 0 && agentLabel.trim().length <= 80 && sourceUrlValid;

  useEffect(() => {
    const sessionId = window.localStorage.getItem('emilia_agent_adoption_session_id');
    if (!sessionId || !api.recoverSession) return;
    let cancelled = false;
    api.recoverSession(sessionId).then((recovered) => {
      if (cancelled) return;
      setSession(recovered);
      if (recovered.recovery?.label) setAgentLabel(recovered.recovery.label);
      if (recovered.recovery?.source_kind) {
        const source = AGENT_SOURCE_TEMPLATES.find((item) => item.kind === recovered.recovery?.source_kind);
        if (source) setAgentSourceTemplateId(source.id);
      }
      if (recovered.recovery?.job_template_id) setJobTemplateId(recovered.recovery.job_template_id);
      if (recovered.recovery?.allowance_template_id) setAllowanceTemplateId(recovered.recovery.allowance_template_id);
      const recoveredStage = recovered.passkey_asserted ? 4 : 3;
      setStageIndex(recoveredStage);
      setFurthestStage(recoveredStage);
      setStatus(recovered.passkey_asserted
        ? 'Recovered this browser session without exposing its bearer capability. Run a new no-egress attempt or revoke it.'
        : 'Recovered this browser session without exposing its bearer capability. Continue with the passkey or revoke it.');
    }).catch(() => {
      if (!cancelled) window.localStorage.removeItem('emilia_agent_adoption_session_id');
    });
    return () => { cancelled = true; };
  }, [api]);

  function chooseTemplate(stage: StageId, templateId: TemplateId, applySelection: () => void) {
    applySelection();
    setError('');
    setStatus('Selection saved locally. Nothing has been connected or executed.');
    emitAdoptEvent({ event: 'template_selected', stage, template_id: templateId });
  }

  function advance(from: StageId, toIndex: number, templateId: TemplateId) {
    setFurthestStage((current) => Math.max(current, toIndex));
    setStageIndex(toIndex);
    setStatus('Stage complete. ' + STAGES[toIndex].label + ' is ready.');
    emitAdoptEvent({ event: 'stage_advanced', stage: from, template_id: templateId });
  }

  async function confirmPasskey() {
    if (!agentReady || !jobTemplateId || !allowanceTemplateId) return;
    setBusy('passkey');
    setError('');
    setStatus('Waiting for a user-present passkey ceremony…');
    emitAdoptEvent({ event: 'passkey_started', stage: 'passkey', template_id: allowanceTemplateId });

    try {
      const activeSession = session ?? await api.createSession({
        label: agentLabel.trim(),
        source_kind: selectedAgentSource.kind,
        ...(sourceUrl ? { source_url: sourceUrl } : {}),
        job_template_id: jobTemplateId,
        allowance_template_id: allowanceTemplateId,
      });
      setSession(activeSession);
      window.localStorage.setItem('emilia_agent_adoption_session_id', activeSession.session_id);
      const assertedSession = await api.assertPasskey(activeSession);
      setSession(assertedSession);
      setFurthestStage((current) => Math.max(current, 4));
      setStageIndex(4);
      setStatus('User-present passkey ceremony recorded. No person or account identity was verified.');
      emitAdoptEvent({ event: 'passkey_asserted', stage: 'passkey', template_id: allowanceTemplateId });
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : 'The passkey assertion could not be completed.';
      setError(message);
      setStatus('Passkey step not completed. No challenge action ran.');
    } finally {
      setBusy('');
    }
  }

  async function runAttempt(templateId: AttemptTemplateId) {
    if (!session || revoked) return;
    setBusy(templateId);
    setError('');
    setStatus('Evaluating the selected synthetic action inside the no-egress challenge…');
    emitAdoptEvent({ event: 'attempt_started', stage: 'try', template_id: templateId });

    try {
      const activeSession = session.trial_token
        ? session
        : api.provisionTrial
          ? await api.provisionTrial(session)
          : session;
      if (activeSession !== session) setSession(activeSession);
      const attempt = await api.runAttempt(activeSession, templateId);
      setAttempts((current) => [...current, attempt]);
      setFurthestStage((current) => Math.max(current, 5));
      if (attempt.decision === 'refuse') {
        setStatus('The Arena refused the no-egress attempt. The Operating Bond is ready for optional publication.');
        emitAdoptEvent({ event: 'attempt_refused', stage: 'try', template_id: templateId });
      } else {
        setStatus('The Arena permitted the simulation. The Operating Bond is ready for optional publication; nothing reached a provider or production system.');
        emitAdoptEvent({ event: 'attempt_permitted', stage: 'try', template_id: templateId });
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The synthetic attempt could not run.');
      setStatus('Attempt not completed. No action left the challenge.');
    } finally {
      setBusy('');
    }
  }

  async function publishOperatingBond() {
    if (!session || !latestAttempt || !publicationConfirmed || revoked) return;
    setBusy('publish');
    setError('');
    setStatus('Creating the unlisted public Operating Bond…');
    emitAdoptEvent({
      event: 'publication_confirmed',
      stage: 'share',
      template_id: latestAttempt.template_id,
    });

    try {
      const publication = await api.publishOperatingBond(session);
      setAttempts((current) => current.map((attempt) => attempt.attempt_id === latestAttempt.attempt_id
        ? { ...attempt, share_url: publication.share_url }
        : attempt));
      setStatus('Public Operating Bond created. Anyone with the link can inspect its bounded projection.');
      emitAdoptEvent({
        event: 'publication_created',
        stage: 'share',
        template_id: latestAttempt.template_id,
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The Operating Bond could not be published.');
      setStatus('Publication not completed. The Operating Bond remains private to this session.');
    } finally {
      setBusy('');
    }
  }

  async function copyShareLink(url: string) {
    try {
      await navigator.clipboard.writeText(new URL(url, window.location.origin).toString());
      setStatus('Public record link copied.');
      emitAdoptEvent({
        event: 'share_link_copied',
        stage: 'share',
        template_id: latestAttempt?.template_id ?? 'none',
      });
    } catch {
      setError('The link could not be copied. Open it and copy the address from your browser.');
    }
  }

  async function revokeSession() {
    if (!session || revoked) return;
    if (!revokeArmed) {
      setRevokeArmed(true);
      setStatus('Confirm revocation to close this synthetic authority session.');
      return;
    }

    setBusy('revoke');
    setError('');
    emitAdoptEvent({ event: 'revocation_started', stage: currentStage.id, template_id: 'none' });
    try {
      await api.revokeSession(session);
      setSession({ ...session, authority_state: 'revoked' });
      window.localStorage.removeItem('emilia_agent_adoption_session_id');
      setRevokeArmed(false);
      setStatus('Session authority revoked. No further attempts or publications can run.');
      emitAdoptEvent({ event: 'revocation_completed', stage: currentStage.id, template_id: 'none' });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The session could not be revoked.');
      setStatus('Revocation not confirmed.');
    } finally {
      setBusy('');
    }
  }

  function openPilot() {
    emitAdoptEvent({
      event: 'pilot_cta_opened',
      stage: currentStage.id,
      template_id: latestAttempt?.template_id ?? 'none',
    });
  }

  return (
    <main className={styles.page}>
      <section className={styles.hero} aria-labelledby="adopt-headline">
        <div className={styles.heroCopy}>
          <p className={styles.eyebrow}>EMILIA ADOPTION · PUBLIC NO-EGRESS CHALLENGE</p>
          <h1 id="adopt-headline">Draft an Operating Bond for an agent candidate.</h1>
          <p className={styles.lede}>
            Describe a candidate, choose a synthetic job and allowance, record a user-present passkey
            ceremony, and watch the Arena evaluate one exact no-egress action.
          </p>
          <div className={styles.boundary}>
            No signup before value · no real money · no provider credentials · no production execution
          </div>
        </div>

        <aside className={styles.heroCard} aria-label="Challenge boundary">
          <div className={styles.heroCardTopline}>
            <span>ADOPTION FILE / 001</span>
            <i aria-hidden="true" />
          </div>
          <h2>See the boundary before you connect anything.</h2>
          <ol>
            <li><span>1</span><p><strong>Describe</strong>Name an agent candidate, then choose local job and synthetic allowance templates.</p></li>
            <li><span>2</span><p><strong>Assert</strong>Use an adoption-local passkey for a user-present ceremony—not verified identity.</p></li>
            <li><span>3</span><p><strong>Test</strong>Run an isolated attempt, then publish only if you explicitly confirm.</p></li>
          </ol>
          <p className={styles.cardBoundary}>No civil identity · no certification · no marketplace listing</p>
        </aside>
      </section>

      <nav className={styles.stageRail} aria-label="Adoption stages">
        {STAGES.map((stage, index) => {
          const isCurrent = index === stageIndex;
          const isComplete = index < furthestStage || (index === 5 && Boolean(publishedAttempt?.share_url));
          const isAvailable = index <= furthestStage;
          return (
            <button
              key={stage.id}
              type="button"
              className={isCurrent ? styles.stageCurrent : isComplete ? styles.stageComplete : styles.stageIdle}
              aria-current={isCurrent ? 'step' : undefined}
              aria-label={stage.label + (isComplete ? ', complete' : isCurrent ? ', current step' : '')}
              disabled={!isAvailable}
              onClick={() => isAvailable && setStageIndex(index)}
            >
              <span>{isComplete ? '✓' : stage.number}</span>
              <strong>{stage.label}</strong>
              <i aria-hidden="true" />
            </button>
          );
        })}
      </nav>

      <div className={styles.liveRegion} aria-live="polite" aria-atomic="true">{status}</div>
      {error && <div className={styles.error} role="alert">{error}</div>}

      <section className={styles.workspace} aria-labelledby={'stage-' + currentStage.id}>
        <div className={styles.stagePanel}>
          {currentStage.id === 'agent' && (
            <>
              <div className={styles.stageHeading}>
                <p className={styles.panelLabel}>STAGE 01 · AGENT</p>
                <h2 id="stage-agent">Describe the agent—without connecting it.</h2>
                <p>Add a non-personal label and source kind. EMILIA never fetches the URL or ingests agent code.</p>
              </div>
              <div className={styles.agentFields}>
                <label className={styles.textField}>
                  <span>Agent label</span>
                  <input value={agentLabel} maxLength={80} autoComplete="off"
                    onChange={(event) => setAgentLabel(event.target.value)}
                    aria-describedby="agent-label-note" />
                  <small id="agent-label-note">Use a project or agent name—not a person&apos;s civil identity.</small>
                </label>
                <label className={styles.textField}>
                  <span>Canonical source URL <i>optional</i></span>
                  <input value={sourceUrl} type="url" inputMode="url" autoComplete="url"
                    placeholder="https://example.com/agent"
                    aria-invalid={!sourceUrlValid}
                    aria-describedby="source-url-note"
                    onChange={(event) => setSourceUrl(event.target.value)} />
                  <small id="source-url-note">
                    HTTPS metadata only; never fetched. Use canonical form; a bare origin ends in /.
                  </small>
                </label>
              </div>
              {!sourceUrlValid && <p className={styles.fieldError} role="alert">Enter a canonical HTTPS URL without a port, query, fragment, or credentials—or leave it blank.</p>}
              <div className={styles.sourceGrid}>
                {AGENT_SOURCE_TEMPLATES.map((item) => (
                  <ChoiceCard key={item.id} group="agent-source" marker={item.marker} name={item.name}
                    detail={item.detail} checked={agentSourceTemplateId === item.id}
                    onChange={() => chooseTemplate('agent', item.id, () => setAgentSourceTemplateId(item.id))} />
                ))}
              </div>
              <div className={styles.stageActions}>
                <p>Candidate fields stay in this page until the passkey stage. Event hooks never include them.</p>
                <button type="button" disabled={!agentReady}
                  onClick={() => agentReady && advance('agent', 1, agentSourceTemplateId)}>
                  Give it a job <span aria-hidden="true">→</span>
                </button>
              </div>
            </>
          )}

          {currentStage.id === 'job' && (
            <>
              <div className={styles.stageHeading}>
                <p className={styles.panelLabel}>STAGE 02 · JOB</p>
                <h2 id="stage-job">Name one consequential job.</h2>
                <p>The template defines the action category and demo destination; it does not connect a tool.</p>
              </div>
              <div className={styles.choiceGrid}>
                {JOB_TEMPLATES.map((item) => (
                  <ChoiceCard key={item.id} group="job-template" marker={item.marker} name={item.name}
                    detail={item.detail} meta={'Declared target · ' + item.target} checked={jobTemplateId === item.id}
                    onChange={() => chooseTemplate('job', item.id, () => setJobTemplateId(item.id))} />
                ))}
              </div>
              <div className={styles.stageActions}>
                <button type="button" className={styles.backButton} onClick={() => setStageIndex(0)}>← Agent</button>
                <button type="button" disabled={!jobTemplateId}
                  onClick={() => jobTemplateId && advance('job', 2, jobTemplateId)}>
                  Set an allowance <span aria-hidden="true">→</span>
                </button>
              </div>
            </>
          )}

          {currentStage.id === 'allowance' && (
            <>
              <div className={styles.stageHeading}>
                <p className={styles.panelLabel}>STAGE 03 · ALLOWANCE</p>
                <h2 id="stage-allowance">Draw the hard edge.</h2>
                <p>Credits are synthetic counters—not money, stored value, or a promise of payment.</p>
              </div>
              <div className={styles.choiceGrid}>
                {ALLOWANCE_TEMPLATES.map((item) => (
                  <ChoiceCard key={item.id} group="allowance-template" marker={item.marker} name={item.name}
                    detail={item.detail} meta={item.total + ' total · ' + item.perAction + ' max per action'}
                    checked={allowanceTemplateId === item.id}
                    onChange={() => chooseTemplate('allowance', item.id, () => setAllowanceTemplateId(item.id))} />
                ))}
              </div>
              <div className={styles.stageActions}>
                <button type="button" className={styles.backButton} onClick={() => setStageIndex(1)}>← Job</button>
                <button type="button" disabled={!allowanceTemplateId}
                  onClick={() => allowanceTemplateId && advance('allowance', 3, allowanceTemplateId)}>
                  Add a passkey <span aria-hidden="true">→</span>
                </button>
              </div>
            </>
          )}

          {currentStage.id === 'passkey' && (
            <>
              <div className={styles.stageHeading}>
                <p className={styles.panelLabel}>STAGE 04 · PASSKEY</p>
                <h2 id="stage-passkey">Put a user-present passkey gesture on the envelope.</h2>
                <p>This is the first stage that opens a revocable adoption session. The composed synthetic trial is time-bounded. No signup is required.</p>
              </div>
              <div className={styles.passkeyGrid}>
                <div className={styles.passkeyCard}>
                  <span className={styles.keyGlyph} aria-hidden="true">◇</span>
                  <div>
                    <p className={styles.panelLabel}>WHAT IT RECORDS</p>
                    <h3>User-present passkey ceremony</h3>
                    <p>A browser passkey assertion shows that the adoption-local credential participated now.</p>
                  </div>
                </div>
                <div className={styles.passkeyCaveat}>
                  <p className={styles.panelLabel}>WHAT IT DOES NOT PROVE</p>
                  <h3>Not verified identity</h3>
                  <p>It does not establish a civil name, employer, certification, fitness, or ownership of the agent.</p>
                </div>
              </div>
              <div className={styles.passkeyAction}>
                <p>Your authenticator may ask for Touch ID, Face ID, a device PIN, or a security key.</p>
                <button type="button" disabled={busy === 'passkey'} onClick={confirmPasskey}>
                  {busy === 'passkey' ? 'Waiting for passkey…' : 'Continue with passkey →'}
                </button>
              </div>
              <div className={styles.stageActions}>
                <button type="button" className={styles.backButton} onClick={() => setStageIndex(2)}>← Allowance</button>
              </div>
            </>
          )}

          {currentStage.id === 'try' && (
            <>
              <div className={styles.stageHeading}>
                <p className={styles.panelLabel}>STAGE 05 · TRY</p>
                <h2 id="stage-try">Push on the boundary.</h2>
                <p>Each attempt is a fixed template evaluated inside the no-egress challenge.</p>
              </div>
              <div className={styles.attemptGrid}>
                {ATTEMPT_TEMPLATES.map((item) => (
                  <button key={item.id} type="button" disabled={Boolean(busy) || revoked}
                    onClick={() => runAttempt(item.id)}>
                    <span className={item.tone === 'refuse' ? styles.attemptRefuse : styles.attemptPermit}>
                      {item.tone === 'refuse' ? 'BOUNDARY TEST' : 'IN-BOUNDS'}
                    </span>
                    <strong>{item.name}</strong>
                    <p>{item.detail}</p>
                    <small>{item.credits} synthetic credits · {item.target}</small>
                    <b>{busy === item.id ? 'Evaluating…' : 'Run attempt →'}</b>
                  </button>
                ))}
              </div>

              <div className={styles.decisionLog} aria-live="polite">
                <div className={styles.decisionTopline}>
                  <p className={styles.panelLabel}>DECISION LOG</p>
                  <span>{attempts.length} {attempts.length === 1 ? 'attempt' : 'attempts'}</span>
                </div>
                {attempts.length === 0 ? (
                  <div className={styles.emptyDecision}>
                    <span aria-hidden="true">◎</span>
                    <p>No decision yet.</p>
                    <small>No template can reach a provider, account, or production executor.</small>
                  </div>
                ) : (
                  <div className={styles.decisionList}>
                    {[...attempts].reverse().map((attempt) => {
                      const template = ATTEMPT_TEMPLATES.find((item) => item.id === attempt.template_id);
                      return (
                        <article key={attempt.attempt_id} className={attempt.decision === 'refuse' ? styles.refused : styles.permitted}>
                          <header>
                            <span>{attempt.decision === 'refuse' ? 'REFUSED BEFORE EGRESS' : 'PERMITTED IN SIMULATION'}</span>
                            <b>{attempt.synthetic_credits} CR</b>
                          </header>
                          <h3>{template?.name ?? 'Synthetic attempt'}</h3>
                          <p>{REASON_COPY[attempt.reason_code]}</p>
                          <code>{fingerprint(attempt.action_digest)}</code>
                        </article>
                      );
                    })}
                  </div>
                )}
              </div>

              {latestAttempt && (
                <div className={styles.refusalNext}>
                  <div>
                    <p className={styles.panelLabel}>ARENA RESULT</p>
                    <h3>Share the bounded Operating Bond—or scope the paid workflow.</h3>
                    <p>The public challenge produced a synthetic result. A pilot is separately scoped and never implied by it.</p>
                  </div>
                  <div>
                    <button type="button" onClick={() => setStageIndex(5)}>Review & share Operating Bond →</button>
                    <a href={pilotHref} onClick={openPilot}>Scope the $25K protected-workflow pilot ↗</a>
                  </div>
                </div>
              )}
            </>
          )}

          {currentStage.id === 'share' && (
            <>
              <div className={styles.stageHeading}>
                <p className={styles.panelLabel}>STAGE 06 · SHARE</p>
                <h2 id="stage-share">Publish the Operating Bond only if you choose.</h2>
                <p>The synthetic decision stays private. The public projection contains only the bounded configuration and passkey observation.</p>
              </div>
              {latestAttempt ? (
                <div className={styles.publishLayout}>
                  <article className={styles.refusalRecord}>
                    <header>
                      <span>SYNTHETIC DECISION</span>
                      <b>NO EGRESS</b>
                    </header>
                    <div className={styles.refusalSeal} aria-hidden="true">{latestAttempt.decision === 'refuse' ? 'R' : 'P'}</div>
                    <h3>{ATTEMPT_TEMPLATES.find((item) => item.id === latestAttempt.template_id)?.name}</h3>
                    <p>{REASON_COPY[latestAttempt.reason_code]}</p>
                    <dl>
                      <div><dt>Job template</dt><dd>{selectedJob?.name ?? 'Template'}</dd></div>
                      <div><dt>Arena decision</dt><dd>{latestAttempt.decision === 'refuse' ? 'refused' : 'permitted'} with no egress</dd></div>
                      <div><dt>Action fingerprint</dt><dd><code>{fingerprint(latestAttempt.action_digest)}</code></dd></div>
                      {latestAttempt.refusal_digest && (
                        <div><dt>Refusal fingerprint</dt><dd><code>{fingerprint(latestAttempt.refusal_digest)}</code></dd></div>
                      )}
                    </dl>
                    <small>This private panel shows an Arena decision over a fixed synthetic template. It is not Gate admission, identity, certification, or production history.</small>
                  </article>

                  <div className={styles.publicationPanel}>
                    {publishedAttempt?.share_url ? (
                      <div className={styles.publishedState} role="status">
                        <span aria-hidden="true">✓</span>
                        <p className={styles.panelLabel}>PUBLICATION COMPLETE</p>
                        <h3>Your unlisted Operating Bond is ready.</h3>
                        <p>Anyone with the link can inspect the bounded public projection while it remains active.</p>
                        <div>
                          <a href={publishedAttempt.share_url}>Open public record ↗</a>
                          <button type="button" onClick={() => copyShareLink(publishedAttempt.share_url!)}>Copy link</button>
                        </div>
                      </div>
                    ) : (
                      <>
                        <p className={styles.panelLabel}>INLINE PUBLICATION CONFIRMATION</p>
                        <h3>Make this bounded Operating Bond public?</h3>
                        <ul>
                          <li>Agent label and source kind</li>
                          <li>Job, allowance, action-class, concurrency, and validity limits</li>
                          <li>Operating Bond, candidate, and passkey-assertion fingerprints</li>
                        </ul>
                        <label className={styles.publishConsent}>
                          <input type="checkbox" checked={publicationConfirmed}
                            onChange={(event) => setPublicationConfirmed(event.target.checked)} />
                          <span>I understand this creates an unlisted public record viewable by anyone with the link.</span>
                        </label>
                        <button type="button" className={styles.publishButton}
                          disabled={!publicationConfirmed || busy === 'publish' || revoked}
                          onClick={publishOperatingBond}>
                          {busy === 'publish' ? 'Publishing record…' : 'Publish Operating Bond →'}
                        </button>
                        <p className={styles.publicationNote}>The source URL, raw passkey assertion, refusal, session token, provider credential, and civil identity are not published.</p>
                      </>
                    )}
                    <div className={styles.pilotCallout}>
                      <p className={styles.panelLabel}>PRODUCTION GRADUATION</p>
                      <h3>Have one workflow that needs this boundary?</h3>
                      <p>Scope a separate protected-workflow pilot. If this public record is attached, the server validates its active identifier; the synthetic result remains factual context, not production evidence.</p>
                      <a href={pilotHref} onClick={openPilot}>Explore the $25K protected-workflow pilot →</a>
                    </div>
                  </div>
                </div>
              ) : (
                <div className={styles.emptyShare}>
                  <span aria-hidden="true">◇</span>
                  <h3>Run one synthetic attempt before publication.</h3>
                  <button type="button" onClick={() => setStageIndex(4)}>Return to the challenge</button>
                </div>
              )}
            </>
          )}
        </div>

        <aside className={styles.envelopePanel} aria-label="Current authority envelope">
          <div className={styles.envelopeTopline}>
            <p className={styles.panelLabel}>AUTHORITY ENVELOPE</p>
            <span className={revoked ? styles.statusRevoked : session?.passkey_asserted ? styles.statusAsserted : styles.statusDraft}>
              {revoked ? 'REVOKED' : session?.passkey_asserted ? 'ASSERTED' : 'DRAFT'}
            </span>
          </div>
          <div className={styles.envelopeScore}>
            <strong>{Math.min(furthestStage + 1, 6)}</strong>
            <span>/ 6 stages reached</span>
          </div>
          <dl className={styles.envelopeFacts}>
            <div><dt>Agent</dt><dd>{agentLabel.trim() || 'Not named'}</dd></div>
            <div><dt>Source</dt><dd>{selectedAgentSource.name}</dd></div>
            <div><dt>Job</dt><dd>{selectedJob?.name ?? 'Not chosen'}</dd></div>
            <div><dt>Allowance</dt><dd>{selectedAllowance ? selectedAllowance.total + ' synthetic credits' : 'Not chosen'}</dd></div>
            <div><dt>Per action</dt><dd>{selectedAllowance ? selectedAllowance.perAction + ' credits' : 'Not chosen'}</dd></div>
            <div><dt>Passkey</dt><dd>{session?.passkey_asserted ? 'User-present assertion' : 'Not asserted'}</dd></div>
            <div><dt>Session expiry</dt><dd>{session?.expires_at ? new Date(session.expires_at).toISOString() : 'Not opened'}</dd></div>
            <div><dt>Egress</dt><dd>Disabled</dd></div>
          </dl>
          <div className={styles.envelopeNote}>
            <span aria-hidden="true">i</span>
            <p><strong>Passkey evidence, carefully stated.</strong> The ceremony records user presence for this adoption-local credential. It does not verify a person or account identity, or authorize later actions.</p>
          </div>

          {session && (
            <div className={styles.revokeBlock}>
              <p className={styles.panelLabel}>SESSION CONTROL</p>
              {revoked ? (
                <p className={styles.revokedCopy}>This session is closed. Attempts and publication are disabled.</p>
              ) : (
                <>
                  <button type="button" onClick={revokeSession} disabled={busy === 'revoke'}>
                    {busy === 'revoke' ? 'Revoking…' : revokeArmed ? 'Confirm revocation' : 'Revoke session authority'}
                  </button>
                  {revokeArmed && (
                    <button type="button" className={styles.cancelRevoke} onClick={() => setRevokeArmed(false)}>
                      Keep session
                    </button>
                  )}
                </>
              )}
            </div>
          )}

          <p className={styles.envelopeFinePrint}>
            This MVP issues no real money, provider credentials, civil identity, certification, marketplace status, or production authority.
          </p>
        </aside>
      </section>
    </main>
  );
}
