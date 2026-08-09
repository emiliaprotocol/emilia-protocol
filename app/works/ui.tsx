// SPDX-License-Identifier: Apache-2.0
//
// EMILIA Marketplace — shared presentational pieces (server-safe, no client JS).
//
// The one visual rule that matters here: VERIFIED and ASSERTED are visually
// distinct everywhere. VERIFIED renders solid ink with its source link;
// ASSERTED renders outlined; UNKNOWN renders muted. An expired claim renders
// as UNKNOWN with an EXPIRED note — stale evidence never keeps its badge.

import type { CSSProperties } from 'react';
import { color, font, radius } from '@/lib/tokens';
import { effectiveClaimStatus, isClaimExpired, type Claim } from '@/lib/works/claims';

const badgeBase: CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: 6,
  padding: '3px 10px',
  borderRadius: radius.sm,
  fontFamily: font.mono,
  fontSize: 11,
  fontWeight: 600,
  letterSpacing: 1,
  textTransform: 'uppercase',
};

const BADGE_STYLES: Record<string, CSSProperties> = {
  VERIFIED: { ...badgeBase, background: color.t1, color: color.bg },
  ASSERTED: { ...badgeBase, background: 'transparent', color: color.t1, border: `1px solid ${color.borderHover}` },
  UNKNOWN: { ...badgeBase, background: 'transparent', color: color.t3, border: `1px dashed ${color.border}` },
};

export function ClaimBadge({ claim }: { claim: Claim }) {
  const status = effectiveClaimStatus(claim);
  const expired = isClaimExpired(claim);
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
      <span style={BADGE_STYLES[status]}>{status}</span>
      {expired ? (
        <span style={{ fontFamily: font.mono, fontSize: 11, color: color.red, letterSpacing: 1 }}>
          EXPIRED {claim.expires_at ? new Date(claim.expires_at).toISOString().slice(0, 10) : ''}
        </span>
      ) : null}
    </span>
  );
}

export function ExampleTag() {
  return (
    <span style={{
      ...badgeBase,
      background: '#F5F5F4',
      color: color.t3,
      border: `1px solid ${color.border}`,
    }}>
      Example
    </span>
  );
}

export function Tag({ children }: { children: string }) {
  return (
    <span style={{
      display: 'inline-block',
      padding: '3px 10px',
      borderRadius: radius.sm,
      border: `1px solid ${color.border}`,
      fontFamily: font.mono,
      fontSize: 12,
      color: color.t2,
    }}>
      {children}
    </span>
  );
}

/** Full claim rendering: statement, badge, scope, source, limitations. */
export function ClaimCard({ claim }: { claim: Claim }) {
  return (
    <div style={{
      background: color.card,
      border: `1px solid ${color.border}`,
      borderRadius: radius.base,
      padding: '20px 24px',
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
        <p style={{ fontSize: 15, color: color.t1, lineHeight: 1.6, margin: 0, fontWeight: 500 }}>
          {claim.statement}
        </p>
        <ClaimBadge claim={claim} />
      </div>
      <dl style={{ margin: '16px 0 0', display: 'grid', gap: 8 }}>
        <ClaimField label="Scope" value={claim.scope} />
        {claim.source ? (
          <ClaimField
            label="Source"
            value={`${claim.source.kind.replace(/_/g, ' ')} — ${claim.source.reference}${claim.source.sha256 ? ` (sha256 ${claim.source.sha256.slice(0, 16)}…)` : ''}`}
            href={/^https:\/\//.test(claim.source.reference) ? claim.source.reference : undefined}
          />
        ) : (
          <ClaimField label="Source" value="none recorded" />
        )}
        <ClaimField label="Observed" value={claim.observed_at.slice(0, 10)} />
        {claim.expires_at ? <ClaimField label="Expires" value={claim.expires_at.slice(0, 10)} /> : null}
        {claim.limitations ? <ClaimField label="Limitations" value={claim.limitations} /> : null}
      </dl>
    </div>
  );
}

function ClaimField({ label, value, href }: { label: string; value: string; href?: string }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '110px 1fr', gap: 12 }}>
      <dt style={{
        fontFamily: font.mono, fontSize: 11, letterSpacing: 1,
        textTransform: 'uppercase', color: color.t3, paddingTop: 2,
      }}>
        {label}
      </dt>
      <dd style={{ margin: 0, fontSize: 13, color: color.t2, lineHeight: 1.6, overflowWrap: 'anywhere' }}>
        {href ? (
          <a href={href} style={{ color: color.t2, textDecorationColor: color.borderHover }} rel="noopener noreferrer">
            {value}
          </a>
        ) : value}
      </dd>
    </div>
  );
}

export function SectionTitle({ children }: { children: string }) {
  return (
    <h2 style={{
      fontFamily: font.mono, fontSize: 12, letterSpacing: 2,
      textTransform: 'uppercase', color: color.t3,
      margin: '0 0 16px', fontWeight: 600,
    }}>
      {children}
    </h2>
  );
}

/** The claim-discipline statement, shown once per Works page footer area. */
export function WorksDisciplineNote() {
  return (
    <p style={{
      fontSize: 13, color: color.t3, lineHeight: 1.7,
      borderTop: `1px solid ${color.border}`, paddingTop: 20, margin: '48px 0 0',
    }}>
      Capability, funding, authority, and eligibility statements on EMILIA Works carry a status —
      VERIFIED, ASSERTED, or UNKNOWN — with exact scope, source, observation date, and limitations.
      Profile and listing fields do not become verified merely by appearing here. VERIFIED means a content-addressed
      artifact or external signer backs the claim; it is never a quality score, a ranking, or a
      judgment that anything is safe or fit for purpose. Works does not rate, rank, or endorse.
    </p>
  );
}
