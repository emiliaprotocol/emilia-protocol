#!/usr/bin/env node
// Generated from gen-operator-keys.mts by scripts/build-standalone-runtimes.mjs. Do not edit.
/* eslint-disable */
/**
 * EP Witness deploy: generate N operator key sets.
 *
 * Writes one keypair per operator into keys/<name>/, using the same generator
 * the single-witness path uses (witness/generate-key.mjs). Each directory gets:
 *   witness-private.pem   (mode 0600, SECRET, mounted read-only into that
 *                          operator's container; never committed, see .gitignore)
 *   witness-public.json   { witness_id, public_key, alg } to PIN at relying parties
 *
 * It also writes keys/pinned-witnesses.json: the array of { witness_id,
 * public_key } for all operators, the exact shape requireWitnessQuorum() and
 * detect-equivocation.mjs take as pinnedWitnessKeys.
 *
 *   node witness/deploy/gen-operator-keys.mjs [op1 op2 op3 ...]
 *
 * With no args it generates the three local-test operators: op1 op2 op3.
 * Refuses to overwrite an existing private key (rotate deliberately).
 *
 * @license Apache-2.0
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateWitnessKey } from '../generate-key.mjs';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const KEYS_ROOT = path.join(HERE, 'keys');
function main() {
    const names = process.argv.slice(2);
    const operators = names.length ? names : ['op1', 'op2', 'op3'];
    fs.mkdirSync(KEYS_ROOT, { recursive: true });
    const pinned = [];
    for (const name of operators) {
        if (!/^[A-Za-z0-9._-]+$/.test(name)) {
            console.error(`Refusing operator name "${name}": use [A-Za-z0-9._-] only.`);
            process.exit(2);
        }
        const dir = path.join(KEYS_ROOT, name);
        fs.mkdirSync(dir, { recursive: true });
        const privPath = path.join(dir, 'witness-private.pem');
        const pubPath = path.join(dir, 'witness-public.json');
        if (fs.existsSync(privPath)) {
            console.error(`Refusing to overwrite existing private key at ${privPath}. Remove it deliberately to rotate.`);
            process.exit(1);
        }
        const { privatePem, publicKeyB64u, witness_id } = generateWitnessKey();
        fs.writeFileSync(privPath, privatePem, { mode: 0o600 });
        const rec = { alg: 'EP-WITNESS-v1', witness_id, public_key: publicKeyB64u };
        fs.writeFileSync(pubPath, JSON.stringify(rec, null, 2) + '\n');
        pinned.push({ witness_id, public_key: publicKeyB64u });
        console.log(`  ${name.padEnd(8)} ${witness_id}  -> ${path.relative(process.cwd(), dir)}`);
    }
    const pinnedPath = path.join(KEYS_ROOT, 'pinned-witnesses.json');
    fs.writeFileSync(pinnedPath, JSON.stringify(pinned, null, 2) + '\n');
    console.log(`\nPinned set (${pinned.length}) written: ${path.relative(process.cwd(), pinnedPath)}`);
    console.log('Pin this file at relying parties as pinnedWitnessKeys for requireWitnessQuorum().');
}
main();
