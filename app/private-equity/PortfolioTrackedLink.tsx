// SPDX-License-Identifier: Apache-2.0

'use client';

import type { AnchorHTMLAttributes, ReactNode } from 'react';
import { emitPortfolioEvent, type PortfolioEventDetail } from './portfolio-analytics';

type PortfolioTrackedLinkProps = Readonly<{
  children: ReactNode;
  eventDetail: PortfolioEventDetail;
}> & Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'children' | 'onClick'>;

export default function PortfolioTrackedLink({
  children,
  eventDetail,
  ...anchorProps
}: PortfolioTrackedLinkProps): React.ReactElement {
  return (
    <a
      {...anchorProps}
      data-analytics-event={eventDetail.event}
      data-analytics-location={eventDetail.location}
      onClick={() => emitPortfolioEvent(eventDetail)}
    >
      {children}
    </a>
  );
}
