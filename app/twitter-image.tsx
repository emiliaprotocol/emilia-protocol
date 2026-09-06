// SPDX-License-Identifier: Apache-2.0

import { ImageResponse } from 'next/og';
import SocialCard from './_social/SocialCard';

export const alt = 'EMILIA: Your AI workforce needs management. Give every agent a job, set its authority, and know what happened.';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function TwitterImage(): ImageResponse {
  return new ImageResponse(<SocialCard />, size);
}
