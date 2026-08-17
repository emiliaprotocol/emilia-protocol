import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyExternalVerificationStatement } from '../../packages/gate/reports/external-verification.js';

// The directory where statement.json is located
const HERE = path.dirname(fileURLToPath(import.meta.url));
const STATEMENT_PATH = path.join(HERE, 'out', 'statement.json');

// Our pinned independent public key and verifier identity
const PINNED_VERIFIERS = [
  {
    verifier_id: 'ext:verifier:cleanroom:independent:v2',
    key_id: 'ep:external-verifier-key:sha256:f59f4aa5eda015d9',
    public_key: 'MCowBQYDK2VwAyEAmu5lCwp1PUgfl1D1-ltP2Y9nYGnIeYVO1A2PEoZBHt4'
  }
];

function main() {
  console.log("=== EMILIA Protocol Independent Verifier Demo ===");

  if (!fs.existsSync(STATEMENT_PATH)) {
    console.error(`Statement file not found at ${STATEMENT_PATH}`);
    console.error("Please run out/verify-and-sign.mjs to generate the statement first.");
    process.exit(1);
  }

  const statementRaw = fs.readFileSync(STATEMENT_PATH, 'utf8');
  const statement = JSON.parse(statementRaw);

  console.log("\nVerifying Statement...");
  console.log(`Reported Verifier: ${statement.verifier.id}`);
  console.log(`Reported Status: ${statement.result.status}`);

  const verificationResult = verifyExternalVerificationStatement(statement, {
    pinnedVerifierKeys: PINNED_VERIFIERS
  });

  if (verificationResult.accepted && verificationResult.verified) {
    console.log("\n✅ STATEMENT VERIFIED");
    console.log(`Statement Digest: ${verificationResult.statement_digest}`);
    console.log(`All checks passed. The independent verifier key is trusted.`);
    process.exit(0);
  } else {
    console.error("\n❌ VERIFICATION FAILED");
    console.error(`Reason: ${verificationResult.reason}`);
    console.error("Checks:", verificationResult.checks);
    process.exit(1);
  }
}

main();
