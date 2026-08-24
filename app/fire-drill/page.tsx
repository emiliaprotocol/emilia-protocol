// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from 'next';
import FireDrillClient from './FireDrillClient';

export const metadata: Metadata = {
  title: 'Agent Action Fire Drill for MCP Tool Schemas',
  description:
    'Run a local, browser-only static review to find documented high-risk MCP tools that omit a structurally required authorization receipt input.',
  alternates: { canonical: '/fire-drill' },
};

export default function FireDrillPage(): React.ReactElement {
  return <FireDrillClient />;
}
