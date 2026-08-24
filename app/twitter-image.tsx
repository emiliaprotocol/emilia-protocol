// SPDX-License-Identifier: Apache-2.0

import { ImageResponse } from 'next/og';
import SocialCard from './_social/SocialCard';

export const alt = 'EMILIA Protocol: the authority tollgate for AI agents';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function TwitterImage(): ImageResponse {
  return new ImageResponse(<SocialCard />, size);
}
