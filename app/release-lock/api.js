// SPDX-License-Identifier: Apache-2.0

import {
  createDemoReleaseLock,
  enrollDemoCredential,
  buildDemoEvidencePackage,
  readDemoState,
  recordDemoApproval,
} from './demo-store';
import {
  DEMO_CONTRACTOR_CAPABILITY,
  DEMO_CUSTOMER_CAPABILITY,
  CEREMONY_CO_ACCEPTANCE,
  CEREMONY_DRAW_RELEASE,
  DEMO_LOCK_ID,
  DEMO_RELEASE_LOCK,
} from './demo-fixture';

const configuredBase = process.env.NEXT_PUBLIC_RELEASE_LOCK_API_BASE?.trim() || '';
const API_BASE = configuredBase.replace(/\/+$/, '');
export const RELEASE_LOCK_DEMO_PILOT_TOKEN = 'demo-pilot-release-lock';

function encodeSegment(value) {
  return encodeURIComponent(String(value));
}

export function releaseLockRoundSegment(ceremony) {
  if (ceremony === CEREMONY_CO_ACCEPTANCE || ceremony === 'CO_ACCEPTED') {
    return 'co-accepted';
  }
  if (ceremony === CEREMONY_DRAW_RELEASE || ceremony === 'DRAW_RELEASE') {
    return 'draw-release';
  }
  throw new Error('Unknown Release Lock ceremony.');
}

export const RELEASE_LOCK_ENDPOINTS = Object.freeze({
  create: '',
  exchange: '/invitations/exchange',
  exchangePairing: '/pairings/exchange',
  get: (lockId) => `/${encodeSegment(lockId)}/view`,
  registerOptions: (lockId) => `/${encodeSegment(lockId)}/registration/options`,
  registerVerify: (lockId) => `/${encodeSegment(lockId)}/registration/verify`,
  resolutionOptions: (lockId, round) => (
    `/${encodeSegment(lockId)}/rounds/${encodeSegment(round)}/action-check/options`
  ),
  resolutionSubmit: (lockId, round) => (
    `/${encodeSegment(lockId)}/rounds/${encodeSegment(round)}/approvals`
  ),
  createPairing: (lockId, round) => (
    `/${encodeSegment(lockId)}/rounds/${encodeSegment(round)}/pairings`
  ),
  evidence: (lockId) => `/${encodeSegment(lockId)}/evidence`,
  participantEvidence: (lockId) => `/${encodeSegment(lockId)}/participant-evidence`,
  stageDraw: (lockId) => `/${encodeSegment(lockId)}/draw-release`,
  amend: (lockId) => `/${encodeSegment(lockId)}/amendments`,
});

export function isReleaseLockDemoMode() {
  return !API_BASE;
}

export function isReleaseLockDemoPilotToken(value) {
  return isReleaseLockDemoMode() && value === RELEASE_LOCK_DEMO_PILOT_TOKEN;
}

function endpoint(path) {
  return `${API_BASE}${path}`;
}

function displayMaterial(value, fallback) {
  if (typeof value === 'string' && value.length > 0) return value;
  if (value && typeof value === 'object') {
    if (typeof value.summary === 'string') return value.summary;
    if (typeof value.label === 'string') return value.label;
    return JSON.stringify(value);
  }
  return fallback;
}

function displayMoney(value, currency) {
  const numeric = Number(value);
  return Number.isFinite(numeric)
    ? new Intl.NumberFormat('en-US', { style: 'currency', currency }).format(numeric)
    : `${value} ${currency}`;
}

function participantApproval(decisions, round, role) {
  const decision = decisions.find(
    (entry) => entry.round === round && entry.role === role && entry.invalidated !== true,
  );
  if (!decision) return null;
  return {
    ceremony: round === 'CO_ACCEPTED' ? CEREMONY_CO_ACCEPTANCE : CEREMONY_DRAW_RELEASE,
    role,
    credential_id: decision.credential_id,
    approved_at: decision.decided_at,
    action_digest: decision.action_hash,
    resolution_digest: decision.resolution_digest,
  };
}

export function normalizeReleaseLockParticipantView(view) {
  const co = view?.change_order?.action;
  if (!co || co.round !== 'CO_ACCEPTED' || !view?.lock?.lock_id) {
    throw new Error('Release Lock participant view is malformed.');
  }
  const draw = view.draw_release?.action || null;
  const decisions = Array.isArray(view.decisions) ? view.decisions : [];
  const acceptances = Array.isArray(view.round_acceptances) ? view.round_acceptances : [];
  const coAccepted = acceptances.some((entry) => entry.round === 'CO_ACCEPTED');
  const drawAccepted = acceptances.some((entry) => entry.round === 'DRAW_RELEASE');
  const parties = Array.isArray(co.parties) ? co.parties : [];
  const contractor = parties.find((entry) => entry.role === 'contractor') || {};
  const customer = parties.find((entry) => entry.role === 'customer') || {};
  const scope = co.retained_change_order.scope;
  const schedule = co.retained_change_order.progress_schedule_effect;
  const currency = co.retained_change_order.currency;
  const coAmount = co.retained_change_order.price_delta;
  const drawCurrency = draw?.currency || currency;
  const drawAmount = draw?.amount || '0.00';
  const lienWaiverDocuments = (draw?.lien_waivers || []).map((entry) => ({
    payee_party_id: entry.payee_party_id || null,
    reference: entry.document?.reference || entry.reference || 'Retained waiver document',
    digest: entry.document?.digest || null,
  }));
  const lienWaiverHashes = (draw?.evidence_hashes?.lien_waiver_hashes || []).map(
    (entry) => (typeof entry === 'string'
      ? { payee_party_id: null, document_hash: entry }
      : entry),
  );
  const lienWaiverBindingDigest = lienWaiverHashes.length === 1
    ? lienWaiverHashes[0].document_hash
    : view.draw_release?.action_hash || null;
  const lock = {
    id: view.lock.lock_id,
    status: view.lock.status,
    project: scope?.project || scope?.project_name || 'Release Lock project',
    title: scope?.title || scope?.change_order_title || `Change order version ${co.version}`,
    scope_summary: displayMaterial(scope, 'Exact retained change-order scope'),
    schedule_effect: displayMaterial(schedule, 'Exact progress-schedule effect'),
    amount: {
      currency,
      display: displayMoney(coAmount, currency),
    },
    document: {
      reference: co.retained_change_order.document.reference,
      digest: co.retained_change_order.document.digest,
    },
    expiration: co.expires_at,
    contacts: {
      contractor: {
        role: 'Contractor',
        display_name: contractor.display_name || contractor.party_id || 'Contractor',
        verified_handle: 'Verified contact channel',
      },
      customer: {
        role: 'Customer',
        display_name: customer.display_name || customer.party_id || 'Customer',
        verified_handle: 'Verified contact channel',
      },
    },
    version: {
      number: co.version,
      label: `Immutable version ${co.version}`,
      created_at: co.created_at,
      digest: view.change_order.action_hash,
    },
    ceremonies: {
      [CEREMONY_CO_ACCEPTANCE]: {
        id: CEREMONY_CO_ACCEPTANCE,
        code: 'CO_ACCEPTED',
        round: 1,
        label: 'Change-order acceptance',
        digest: view.change_order.action_hash,
        pairing_phrase: view.change_order.action_hash.slice(7, 15).toUpperCase(),
        question_pool: [],
      },
      [CEREMONY_DRAW_RELEASE]: {
        id: CEREMONY_DRAW_RELEASE,
        code: 'DRAW_RELEASE',
        round: 2,
        label: 'Draw release',
        digest: view.draw_release?.action_hash || null,
        pairing_phrase: view.draw_release?.action_hash?.slice(7, 15).toUpperCase() || 'NOT STAGED',
        question_pool: [],
      },
    },
    draw: {
      id: draw?.draw_id || 'Not staged',
      amount: {
        currency: drawCurrency,
        display: displayMoney(drawAmount, drawCurrency),
      },
      payees: (draw?.payees || []).map((payee) => ({
        name: payee.party_id,
        amount: displayMoney(payee.amount, drawCurrency),
      })),
      completion_evidence: {
        reference: draw?.completion_evidence?.reference || 'Not staged',
        digest: draw?.completion_evidence?.digest || null,
      },
      lien_waiver_evidence: {
        reference: lienWaiverDocuments.map((entry) => (
          entry.payee_party_id
            ? `${entry.payee_party_id} · ${entry.reference}`
            : entry.reference
        )).join(', ') || 'Not staged',
        digest: lienWaiverBindingDigest,
        documents: lienWaiverDocuments.map((entry) => {
          const binding = lienWaiverHashes.find(
            (candidate) => candidate.payee_party_id === entry.payee_party_id,
          );
          return {
            ...entry,
            digest: binding?.document_hash || entry.digest,
          };
        }),
      },
      custodian: draw?.custodian?.provider || 'Not staged',
      instruction: draw
        ? `Make ${draw.draw_id} eligible only after both DRAW_RELEASE approvals.`
        : 'A draw and its evidence must be staged after CO_ACCEPTED.',
    },
    refusals: DEMO_RELEASE_LOCK.refusals,
    evidence: {
      package_digest: view.effect?.effect_reference || view.change_order.action_hash,
      format: 'EP-RELEASE-LOCK-EVIDENCE-v1',
    },
  };
  const state = {
    lock,
    created: true,
    enrolled: {
      contractor: view.role === 'contractor' && view.credential_enrolled === true,
      customer: view.role === 'customer' && view.credential_enrolled === true,
    },
    ceremonies: {
      [CEREMONY_CO_ACCEPTANCE]: {
        status: coAccepted ? 'CO_ACCEPTED' : 'pending',
        approvals: {
          contractor: participantApproval(decisions, 'CO_ACCEPTED', 'contractor'),
          customer: participantApproval(decisions, 'CO_ACCEPTED', 'customer'),
        },
        completed_at: acceptances.find((entry) => entry.round === 'CO_ACCEPTED')?.accepted_at || null,
      },
      [CEREMONY_DRAW_RELEASE]: {
        status: drawAccepted ? 'DRAW_RELEASE' : draw ? 'pending' : 'locked_until_milestone',
        approvals: {
          contractor: participantApproval(decisions, 'DRAW_RELEASE', 'contractor'),
          customer: participantApproval(decisions, 'DRAW_RELEASE', 'customer'),
        },
        completed_at: acceptances.find((entry) => entry.round === 'DRAW_RELEASE')?.accepted_at || null,
      },
    },
    milestone: {
      status: draw ? 'evidence_ready' : 'not_ready',
      evidence_available: Boolean(draw),
      recorded_at: draw?.created_at || null,
    },
    release_instruction: {
      status: view.effect?.status || (drawAccepted ? 'eligible_not_executed' : 'blocked'),
      eligible: drawAccepted,
      executed: view.effect?.status === 'applied',
    },
    evidence_ready: drawAccepted,
    amendment: null,
  };
  return { lock, state, role: view.role, credential_enrolled: view.credential_enrolled === true };
}

async function readError(response) {
  try {
    const body = await response.json();
    return body.detail || body.title || body.error || `Request failed (${response.status})`;
  } catch {
    return `Request failed (${response.status})`;
  }
}

async function requestJson(path, init = {}) {
  const response = await fetch(endpoint(path), {
    credentials: 'include',
    cache: 'no-store',
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      ...init.headers,
    },
  });
  if (!response.ok) throw new Error(await readError(response));
  return response.json();
}

export async function createReleaseLock({ pilotToken, lock }) {
  if (isReleaseLockDemoMode()) {
    if (!isReleaseLockDemoPilotToken(pilotToken)) {
      throw new Error('Release Lock demo creation link is invalid.');
    }
    const state = createDemoReleaseLock(lock);
    return {
      lock_id: state.lock.id,
      lock: state.lock,
      capabilities: {
        contractor: `/release-lock/c/${DEMO_CONTRACTOR_CAPABILITY}`,
        customer: `/release-lock/c/${DEMO_CUSTOMER_CAPABILITY}`,
      },
      clean_path: `/release-lock/${state.lock.id}`,
      demo: true,
    };
  }
  throw new Error(
    'Live Release Lock creation requires an authenticated server integration.',
  );
}

function safeCleanPath(value, lockId) {
  if (!value) return `/release-lock/${encodeSegment(lockId)}`;
  try {
    const parsed = new URL(value, 'https://release-lock.invalid');
    const path = parsed.pathname;
    if (!path.startsWith('/release-lock/') || path.includes('/c/')) {
      throw new Error('Capability exchange returned an invalid clean path.');
    }
    return path;
  } catch {
    throw new Error('Capability exchange returned an invalid clean path.');
  }
}

export async function exchangeReleaseLockCapability(input) {
  const token = typeof input === 'string' ? input : input?.token;
  if (isReleaseLockDemoMode()) {
    const role = token === DEMO_CONTRACTOR_CAPABILITY ? 'contractor' : 'customer';
    return {
      lock_id: DEMO_LOCK_ID,
      role,
      clean_path: `/release-lock/${DEMO_LOCK_ID}`,
      demo: true,
    };
  }

  const exchange = await requestJson(RELEASE_LOCK_ENDPOINTS.exchange, {
    method: 'POST',
    body: JSON.stringify({
      token,
      lock_id: input?.lockId,
      role: input?.role,
    }),
  });
  return {
    ...exchange,
    clean_path: safeCleanPath(`/release-lock/${exchange.lock_id}`, exchange.lock_id),
  };
}

export async function createReleaseLockPairing(lockId, ceremony) {
  if (isReleaseLockDemoMode()) {
    return {
      pairing_path: `/release-lock/${encodeSegment(lockId)}/mirror?ceremony=${encodeSegment(ceremony)}`,
      demo: true,
    };
  }
  const round = releaseLockRoundSegment(ceremony);
  const result = await requestJson(RELEASE_LOCK_ENDPOINTS.createPairing(lockId, round), {
    method: 'POST',
  });
  if (typeof result.pairing_token !== 'string'
      || !['contractor', 'customer'].includes(result.role)) {
    throw new Error('Action Mirror pairing response is malformed.');
  }
  const query = new URLSearchParams({
    lock_id: lockId,
    role: result.role,
    round,
  });
  return {
    ...result,
    pairing_path: `/release-lock/p?${query}#cap=${encodeURIComponent(result.pairing_token)}`,
  };
}

export async function exchangeReleaseLockPairing({
  token,
  lockId,
  role,
  round,
}) {
  const exchange = await requestJson(RELEASE_LOCK_ENDPOINTS.exchangePairing, {
    method: 'POST',
    body: JSON.stringify({
      token,
      lock_id: lockId,
      role,
      round: round === 'co-accepted' ? 'CO_ACCEPTED' : 'DRAW_RELEASE',
    }),
  });
  const ceremony = round === 'co-accepted'
    ? CEREMONY_CO_ACCEPTANCE
    : CEREMONY_DRAW_RELEASE;
  return {
    ...exchange,
    clean_path: `/release-lock/${encodeSegment(lockId)}/mirror?ceremony=${encodeSegment(ceremony)}`,
  };
}

export async function getReleaseLock(lockId) {
  if (isReleaseLockDemoMode()) {
    const state = typeof window === 'undefined' ? null : readDemoState();
    return {
      lock: state?.lock || DEMO_RELEASE_LOCK,
      state: state || null,
      demo: true,
    };
  }
  return normalizeReleaseLockParticipantView(
    await requestJson(RELEASE_LOCK_ENDPOINTS.get(lockId)),
  );
}

export async function getRegistrationOptions(lockId, payload) {
  if (isReleaseLockDemoMode()) {
    const state = typeof window === 'undefined' ? null : readDemoState();
    return {
      demo: true,
      registration_id: `demo-register-${payload.role}-01`,
      options: null,
      credential_already_enrolled: Boolean(state?.enrolled?.[payload.role]),
    };
  }
  const registration = await requestJson(RELEASE_LOCK_ENDPOINTS.registerOptions(lockId), {
    method: 'POST',
  });
  return {
    ...registration,
    registration_id: registration.challenge_id,
    credential_already_enrolled: false,
  };
}

export async function verifyRegistration(lockId, payload) {
  if (isReleaseLockDemoMode()) {
    enrollDemoCredential(payload.role);
    return {
      verified: true,
      credential_id: `demo-passkey-${payload.role}-01`,
      demo: true,
    };
  }
  return requestJson(RELEASE_LOCK_ENDPOINTS.registerVerify(lockId), {
    method: 'POST',
    body: JSON.stringify({
      challenge_id: payload.registration_id,
      attestation: payload.attestation,
    }),
  });
}

export async function getResolutionOptions(lockId, payload) {
  if (isReleaseLockDemoMode()) {
    return {
      demo: true,
      resolution_id: `demo-resolution-${payload.role}-01`,
      options: null,
      context: {
        ceremony: payload.ceremony,
        role: payload.role,
        action_digest: payload.action_digest,
        prompt_set_digest: payload.prompt_set_digest || null,
        answer_digest: payload.answer_digest || null,
      },
    };
  }
  const round = releaseLockRoundSegment(payload.ceremony);
  const response = await requestJson(RELEASE_LOCK_ENDPOINTS.resolutionOptions(lockId, round), {
    method: 'POST',
  });
  return {
    ...response,
    resolution_id: response.challenge_id,
    context: {
      ceremony: payload.ceremony,
      role: payload.role || response.prompt_set?.role,
      action_digest: response.action_hash,
      prompt_set_digest: response.prompt_set_digest,
      answer_digest: null,
    },
  };
}

export async function submitResolution(lockId, payload) {
  if (isReleaseLockDemoMode()) {
    const state = readDemoState();
    const ceremony = state.lock.ceremonies[payload.ceremony];
    if (!ceremony) {
      throw new Error('Unknown Release Lock ceremony.');
    }
    if (payload.action_digest !== ceremony.digest) {
      throw new Error('Action digest mismatch. Nothing was approved.');
    }
    if (payload.role === 'customer'
      && (!payload.prompt_set_digest || !payload.answer_digest)) {
      throw new Error('Action Mirror bindings are required for customer approval.');
    }
    if (payload.ceremony === CEREMONY_DRAW_RELEASE
      && state.ceremonies[CEREMONY_CO_ACCEPTANCE].status !== 'CO_ACCEPTED') {
      throw new Error('DRAW_RELEASE is locked until both CO_ACCEPTED approvals exist.');
    }
    if (payload.ceremony === CEREMONY_DRAW_RELEASE
      && !state.milestone.evidence_available) {
      throw new Error('DRAW_RELEASE is locked until milestone evidence is available.');
    }
    const next = recordDemoApproval(payload.ceremony, payload.role, payload);
    return {
      approved: true,
      ceremony: payload.ceremony,
      approval: next.ceremonies[payload.ceremony].approvals[payload.role],
      ceremony_status: next.ceremonies[payload.ceremony].status,
      release_instruction: next.release_instruction,
      demo: true,
    };
  }
  const round = releaseLockRoundSegment(payload.ceremony);
  return requestJson(RELEASE_LOCK_ENDPOINTS.resolutionSubmit(lockId, round), {
    method: 'POST',
    body: JSON.stringify({
      challenge_id: payload.resolution_id,
      answers: payload.answers,
      assertion: payload.assertion,
    }),
  });
}

export async function getReleaseLockEvidence(lockId) {
  if (isReleaseLockDemoMode()) {
    const evidence = buildDemoEvidencePackage();
    return new Blob([`${JSON.stringify(evidence, null, 2)}\n`], {
      type: 'application/json',
    });
  }

  const response = await fetch(endpoint(RELEASE_LOCK_ENDPOINTS.participantEvidence(lockId)), {
    credentials: 'include',
    cache: 'no-store',
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) throw new Error(await readError(response));
  return response.blob();
}
