import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

// 1. RFC 8785 JSON Canonicalization Scheme (JCS)
function canonicalize(data) {
    if (data === null || typeof data !== 'object') {
        return JSON.stringify(data);
    }
    if (Array.isArray(data)) {
        return '[' + data.map(item => {
            if (item === undefined || typeof item === 'function' || typeof item === 'symbol') {
                return 'null';
            }
            return canonicalize(item);
        }).join(',') + ']';
    }
    const keys = Object.keys(data).sort();
    const parts = [];
    for (const key of keys) {
        const value = data[key];
        if (value === undefined || typeof value === 'function' || typeof value === 'symbol') {
            continue;
        }
        parts.push(JSON.stringify(key) + ':' + canonicalize(value));
    }
    return '{' + parts.join(',') + '}';
}

const { vectors } = JSON.parse(readFileSync(process.argv[2], 'utf8'));

async function run() {
    const out = [];
    for (const v of vectors) {
        if (v.canonicalization) {
            try {
                if (typeof v.canonicalization.input_json !== 'string') {
                    out.push({ id: v.id, valid: false });
                    continue;
                }
                const parsed = JSON.parse(v.canonicalization.input_json);
                const canonicalBytes = Buffer.from(canonicalize(parsed), 'utf8');
                const digest = createHash('sha256').update(canonicalBytes).digest('hex');
                out.push({ id: v.id, valid: digest === v.canonicalization.expected_digest });
            } catch(e) {
                out.push({ id: v.id, valid: false });
            }
        } else {
            // Placeholder: we fail anything that is not canonicalization for now
            out.push({ id: v.id, valid: false });
        }
    }
    process.stdout.write(JSON.stringify(out));
}
run();
