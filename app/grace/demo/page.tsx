// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import GraceScreenshotStory from './GraceScreenshotStory';

export const metadata: Metadata = {
  title: 'GRACE Screenshot Story | EMILIA Protocol',
  description: 'A screenshot-led reference simulation from human approval to a simulated meter result. No physical grid event.',
  alternates: { canonical: '/grace/demo' },
  robots: { index: false, follow: false },
};

export default function GraceScreenshotDemoPage() {
  return <GraceScreenshotStory />;
}
