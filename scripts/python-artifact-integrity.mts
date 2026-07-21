// SPDX-License-Identifier: Apache-2.0
import crypto from 'node:crypto';

/** Refuse a registry wheel or sdist unless every byte matches the tested build. */
export function assertPythonArtifactBytesMatch(testedBytes: any, publishedBytes: any): string {
  const tested: Buffer = Buffer.from(testedBytes);
  const published: Buffer = Buffer.from(publishedBytes);
  if (!tested.equals(published)) throw new Error('published Python artifact bytes differ from the tested artifact');
  return crypto.createHash('sha256').update(tested).digest('hex');
}
