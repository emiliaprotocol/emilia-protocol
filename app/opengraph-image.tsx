// SPDX-License-Identifier: Apache-2.0

import { ImageResponse } from 'next/og';
import SocialCard from './_social/SocialCard';

export const alt = 'EMILIA: Build your AI workforce. Find specialized agents or bring your own. Give them a job, set their limits and review the work.';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function OpenGraphImage(): ImageResponse {
  return new ImageResponse(<SocialCard />, size);
}
