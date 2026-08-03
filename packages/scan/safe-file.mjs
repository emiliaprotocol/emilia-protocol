// SPDX-License-Identifier: Apache-2.0
// Bounded, regular-file-only local reads for the public Scan CLIs.
import fs from 'node:fs';
import path from 'node:path';

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function assertNoSymlinkComponents(absolutePath) {
  const parsed = path.parse(absolutePath);
  const segments = absolutePath.slice(parsed.root.length).split(path.sep).filter(Boolean);
  let cursor = parsed.root;
  for (const segment of segments) {
    cursor = path.join(cursor, segment);
    const stat = fs.lstatSync(cursor, { bigint: true });
    if (stat.isSymbolicLink()) {
      const rootOwnedSystemAlias = path.dirname(cursor) === parsed.root && stat.uid === 0n;
      if (!rootOwnedSystemAlias) throw new Error(`Refusing symlinked input path component: ${cursor}`);
    }
  }
}

export function readBoundedRegularFile(file, maxBytes) {
  const absolute = path.resolve(file);
  assertNoSymlinkComponents(absolute);
  const noFollow = typeof fs.constants.O_NOFOLLOW === 'number' ? fs.constants.O_NOFOLLOW : 0;
  const nonBlock = typeof fs.constants.O_NONBLOCK === 'number' ? fs.constants.O_NONBLOCK : 0;
  const fd = fs.openSync(absolute, fs.constants.O_RDONLY | noFollow | nonBlock);
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    if (!before.isFile()) throw new Error(`Refusing non-regular input: ${file}`);
    if (before.size > BigInt(maxBytes)) throw new Error(`Input exceeds ${maxBytes} bytes.`);

    const bytes = Buffer.allocUnsafe(maxBytes + 1);
    let offset = 0;
    while (offset <= maxBytes) {
      const read = fs.readSync(fd, bytes, offset, maxBytes + 1 - offset, null);
      if (read === 0) break;
      offset += read;
    }
    if (offset > maxBytes) throw new Error(`Input exceeds ${maxBytes} bytes.`);

    const after = fs.fstatSync(fd, { bigint: true });
    const pathStat = fs.statSync(absolute, { bigint: true });
    assertNoSymlinkComponents(absolute);
    if (
      !sameIdentity(before, after)
      || !sameIdentity(after, pathStat)
      || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs
    ) {
      throw new Error(`Refusing input changed during read: ${file}`);
    }
    return bytes.subarray(0, offset);
  } finally {
    fs.closeSync(fd);
  }
}
