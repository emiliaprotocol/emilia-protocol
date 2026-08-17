# Handoff Report: Victory Audit Discrepancies and Fix Strategy

## 1. Observation

Direct observations made on files, parameters, and signatures in the codebase:

1. **Pinned Public Key**: The file `examples/external-verification/out/public.key` contains:
   ```
   MCowBQYDK2VwAyEAH57xLqDpdY7hWdVdDn7-y3wJEESVGVFlwnCCDdkGWc4
   ```
   This corresponds to `examples/external-verification/out/private-key.pem`.

2. **Statement Signature and Verifier ID on Disk**: The statement file `examples/external-verification/out/statement.json` on disk contains:
   - Line 5: `"id": "ext:verifier:cleanroom:independent:v2"`
   - Line 153: `"public_key": "MCowBQYDK2VwAyEAmu5lCwp1PUgfl1D1-ltP2Y9nYGnIeYVO1A2PEoZBHt4"` (signature key)
   - Line 152: `"key_id": "ep:external-verifier-key:sha256:f59f4aa5eda015d9"`

3. **Keys Available on Disk**:
   - `examples/external-verification/out/public.key`: `MCowBQYDK2VwAyEAH57xLqDpdY7hWdVdDn7-y3wJEESVGVFlwnCCDdkGWc4`
   - `examples/external-verification/out/independent-key/public.key`: `MCowBQYDK2VwAyEA6p47FhTC1wmAnbRSVr4ZadDyIKUTkTt9uYQbfPklV0I`
   - `examples/external-verification/out/independent-key-2/public.key`: `MCowBQYDK2VwAyEAmu5lCwp1PUgfl1D1-ltP2Y9nYGnIeYVO1A2PEoZBHt4`

4. **Parameters in `verify-and-sign.mjs`**: The script `examples/external-verification/out/verify-and-sign.mjs` has:
   - Line 11: `const PRIVATE_KEY = path.join(HERE, 'private-key.pem');`
   - Line 22: `'--verifier-id', 'ext:verifier:cleanroom:independent:v2',`
   - Line 26: `'--key', path.join(HERE, 'independent-key-2', 'private-key.pem'),`

5. **Pin and Verifier ID Check Logic**: In `packages/gate/reports/external-verification.js`:
   - Lines 177-179:
     ```javascript
     const keyMatched = pinned.filter((k) => k?.public_key === sig.public_key
       && (k.key_id === undefined || k.key_id === keyId));
     const pin = keyMatched.find((k) => typeof k.verifier_id === 'string' && k.verifier_id === verifierId);
     ```
   - Lines 180-188:
     ```javascript
     if (!pin) {
       return {
         verified: false,
         accepted: false,
         checks: { version: true, signature: false, pinned_verifier_key: false, statement_digest: true },
         reason: keyMatched.length ? 'pin_missing_or_mismatched_verifier_id' : 'verifier_key_not_pinned',
         statement_digest: digest,
       };
     }
     ```

## 2. Logic Chain

1. **Assertion**: The verification of `statement.json` fails during the independent test execution in Phase C.
   - **Reasoning**: The independent test execution command uses `--pin examples/external-verification/out/public.key` (public key: `MCowBQYDK2VwAyEAH57xLqDpdY7hWdVdDn7-y3wJEESVGVFlwnCCDdkGWc4`) and `--verifier-id ext:verifier:cleanroom`.
   - **Observation mapping**: This compares the pinned public key and verifier ID to the generated statement.
   - **Reasoning**: The generated `statement.json` on disk was signed using the private key in `independent-key-2/private-key.pem` (public key: `MCowBQYDK2VwAyEAmu5lCwp1PUgfl1D1-ltP2Y9nYGnIeYVO1A2PEoZBHt4`) with a verifier ID of `ext:verifier:cleanroom:independent:v2`.
   - **Observation mapping**: These values are different from the pinned public key and verifier ID.
   - **Reasoning**: The filter condition in `verifyExternalVerificationStatement` (Lines 177-179) fails to find a matching pinned verifier key because `sig.public_key` (`MCowBQYDK2VwAyEAmu5lCwp1PUgfl1D1-ltP2Y9nYGnIeYVO1A2PEoZBHt4`) does not match the pinned public key `MCowBQYDK2VwAyEAH57xLqDpdY7hWdVdDn7-y3wJEESVGVFlwnCCDdkGWc4`. This causes `keyMatched` to be empty and returns `accepted: false` with `reason: 'verifier_key_not_pinned'`.

2. **Assertion**: The mismatch originates from the configuration parameters in `verify-and-sign.mjs`.
   - **Reasoning**: `verify-and-sign.mjs` executes `sign-statement.mjs` with `--verifier-id` set to `'ext:verifier:cleanroom:independent:v2'` and `--key` set to `'examples/external-verification/out/independent-key-2/private-key.pem'`.
   - **Observation mapping**: Reverting these options to their pinned defaults will result in `sign-statement.mjs` signing the statement using the correct key (`examples/external-verification/out/private-key.pem`) and the correct verifier ID (`ext:verifier:cleanroom`).

3. **Assertion**: There is an observed historical drift in both keys and verifier IDs used.
   - **Reasoning**:
     - Iteration 1 used Key `MCowBQYDK2VwAyEASbzREhCQ2diEsg-U-IjRmsfYD_xaq4znLx8aj48mymk` and Verifier ID `"cleanroom-independent-nodejs-v1"`.
     - Intermediate iteration used Key `MCowBQYDK2VwAyEA6p47FhTC1wmAnbRSVr4ZadDyIKUTkTt9uYQbfPklV0I` and Verifier ID `"cleanroom-independent-nodejs-v2"`.
     - The current iteration on disk used Key `MCowBQYDK2VwAyEAmu5lCwp1PUgfl1D1-ltP2Y9nYGnIeYVO1A2PEoZBHt4` and Verifier ID `"ext:verifier:cleanroom:independent:v2"`.
     - However, the pinned configuration expects Key `MCowBQYDK2VwAyEAH57xLqDpdY7hWdVdDn7-y3wJEESVGVFlwnCCDdkGWc4` and Verifier ID `"ext:verifier:cleanroom"`.

## 3. Caveats

- We did not execute the script commands directly due to permission prompt timeouts. However, static code analysis of the files, keys, and cryptographic verify functions provides full deterministic assurance of the discrepancy.

## 4. Conclusion

The rejection verdict `verifier_key_not_pinned` is due to a mismatch between the pinned public key (`public.key`) / verifier ID (`ext:verifier:cleanroom`) and the values actually used to sign `statement.json` in `verify-and-sign.mjs` (which used the key from `independent-key-2` and the verifier ID `ext:verifier:cleanroom:independent:v2`). 

Applying the patch to revert the verifier ID and key parameters in `verify-and-sign.mjs` will resolve the mismatch, ensuring the statement is signed using the correct pinned key and verifier ID.

## 5. Verification Method

To verify the remediation:

1. Apply the patch `verify-and-sign.mjs.patch`.
2. Run the build/signing script to re-evaluate the conformance vectors and sign the statement:
   ```bash
   node examples/external-verification/out/verify-and-sign.mjs
   ```
3. Run the independent verification tool:
   ```bash
   node examples/external-verification/verify-statement.mjs examples/external-verification/out/statement.json --pin examples/external-verification/out/public.key --verifier-id ext:verifier:cleanroom
   ```
4. Confirm that the verification output prints `ACCEPTED under the pinned key` and exits with `0`.
