// SPDX-License-Identifier: Apache-2.0
// JS conformance runner: emits [{id, valid}] for each vector. Reads vectors path from argv[2].
import { verifyReceipt } from '../../packages/verify/index.js';
import { readFileSync } from 'node:fs';
const { vectors } = JSON.parse(readFileSync(process.argv[2], 'utf8'));
process.stdout.write(JSON.stringify(vectors.map((v) => ({ id: v.id, valid: verifyReceipt(v.document, v.public_key).valid }))));
