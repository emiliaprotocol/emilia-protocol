// SPDX-License-Identifier: Apache-2.0

import React from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { CircleDollarSign, LockKeyhole, ShieldCheck } from 'lucide-react';
import { color, font, radius } from '@/lib/tokens';
import styles from './release-lock.module.css';

const tokenStyle: React.CSSProperties = {
  '--rl-bg': color.bg,
  '--rl-surface': color.card,
  '--rl-surface-muted': color.cardHover,
  '--rl-ink': color.t1,
  '--rl-body': color.t2,
  '--rl-muted': '#57534e',
  '--rl-gold': '#806515',
  '--rl-green': color.green,
  '--rl-blue': color.blue,
  '--rl-red': color.red,
  '--rl-line': color.border,
  '--rl-line-strong': color.borderHover,
  '--rl-radius': `${radius.base}px`,
  '--rl-radius-control': `${radius.sm}px`,
  '--rl-font-sans': font.sans,
  '--rl-font-mono': font.mono,
} as React.CSSProperties;

export function DemoBadge(): React.ReactElement {
  return (
    <span className={styles.demoBadge}>
      <CircleDollarSign aria-hidden="true" size={14} />
      DEMO
    </span>
  );
}

interface ReleaseLockShellProps {
  children?: React.ReactNode;
  demo?: boolean;
  role?: string;
  statusLabel?: string;
}

export default function ReleaseLockShell({
  children,
  demo = false,
  role,
  statusLabel,
}: ReleaseLockShellProps): React.ReactElement {
  return (
    <div className={styles.page} style={tokenStyle}>
      <header className={styles.appHeader}>
        <div className={styles.appHeaderInner}>
          <div className={styles.brandGroup}>
            <Link href="/" className={styles.brandLink} aria-label="EMILIA home">
              <Image
                src="/logo-wordmark.png"
                alt="EMILIA Protocol"
                width={110}
                height={28}
                priority
              />
            </Link>
            <span className={styles.productName}>
              <LockKeyhole aria-hidden="true" size={17} />
              Release Lock
            </span>
          </div>

          <div className={styles.headerStatus}>
            {role && <span className={styles.roleLabel}>{role} view</span>}
            {statusLabel && (
              <span className={styles.headerState}>
                <ShieldCheck aria-hidden="true" size={15} />
                {statusLabel}
              </span>
            )}
            {demo && <DemoBadge />}
          </div>
        </div>
      </header>

      {demo && (
        <div className={styles.demoRail} role="status">
          <span>DETERMINISTIC DEMO</span>
          <strong>No real money movement</strong>
          <span>Simulated credentials and custody instruction</span>
        </div>
      )}

      {children}
    </div>
  );
}
