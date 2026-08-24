// SPDX-License-Identifier: Apache-2.0

'use client';

export const PORTFOLIO_EVENT_CHANNEL = 'emilia:portfolio-event';

export type PortfolioEventDetail = Readonly<{
  event:
    | 'pilot_scope_started'
    | 'risk_lab_opened'
    | 'assurance_surface_opened'
    | 'sandbox_provision_started'
    | 'sandbox_provision_completed'
    | 'sandbox_scenario_selected'
    | 'sandbox_precheck_completed'
    | 'sandbox_curl_copied'
    | 'team_email_started';
  location: 'hero' | 'engagement_ladder' | 'risk_lab' | 'final_cta';
  surface?:
    | 'open_verification'
    | 'protected_workflow_pilot'
    | 'deployment_assurance'
    | 'continuous_assurance'
    | 'portfolio_authority_program'
    | 'warranted_gate';
  scenario?: 'single_signoff' | 'dual_signoff' | 'hard_refusal';
}>;

/**
 * Privacy-minimized integration hook for a consented, self-hosted analytics
 * listener. Only closed enum values leave the component. No person, company,
 * credential, action payload, URL parameter, or free-text field is dispatched.
 */
export function emitPortfolioEvent(detail: PortfolioEventDetail): void {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(new CustomEvent<PortfolioEventDetail>(PORTFOLIO_EVENT_CHANNEL, { detail }));
}
