// SPDX-License-Identifier: Apache-2.0
import type { Metadata } from 'next';
import GraceScreenshotStory from './GraceScreenshotStory';

export const metadata: Metadata = {
  title: 'GRACE Screenshot Story | EMILIA Protocol',
  description: 'A screenshot-led reference run from human approval to measured grid effect.',
  alternates: { canonical: '/grace/demo' },
};

export default function GraceScreenshotDemoPage() {
  return <GraceScreenshotStory />;
}
