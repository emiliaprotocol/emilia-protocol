# Action Escrow kitchen-renovation reference

This local reference run keeps five claims separate:

1. The final PDF bytes and structured material-term mapping verify under
   `EP-DOCUMENT-ACTION-BINDING-v1`.
2. The e-sign provider reports final document execution.
3. Both parties separately accept those exact final bytes.
4. The homeowner and contractor separately approve the exact release action.
5. A signed, simulated external-custodian adapter reports funding and release
   state.

Document acceptance is never treated as payment authorization. The release
action binds the amount, destination, final document, structured terms,
completion evidence, and amendment version. The shipped Action Escrow kernel
invokes the simulated custodian exactly once and refuses replay.
Once a funding request enters the custodian boundary, it refuses cancellation
or amendment until an authenticated no-funds or completed unwind/rebind
ceremony exists. A missing local funding statement is never treated as proof
that the external custodian received no money.

The downloadable JSON is built by
`assembleActionEscrowEvidencePackage` and re-performed by
`verifyActionEscrowEvidencePackage`. The final PDF is a digest-joined sidecar;
it is not embedded in the manifest.

The kernel's DAB callback comes from
`createActionEscrowDocumentBindingVerifier`, including its agreement digest,
profile digest, typed amount/destination/milestone mapping, document-byte
resolver, and custodian transaction checks.

The release mutation and reconciliation run through
`createActionEscrowCustodianBridge`. Its signed portable release observation is
checked by `createActionEscrowCustodianStatementVerifier`; the example does not
implement a parallel release receipt or Gate path.

Run the executable scenario:

```bash
node examples/action-escrow/demo.mjs
```

Run the focused tests:

```bash
node --test examples/action-escrow/scenario.test.mjs
```

## Honest boundary

- Ed25519 signatures, the shipped DAB verifier, Action Escrow state kernel,
  signed durable state, and evidence-package verification are real.
- The Acrobat Sign and custodian adapters use deterministic local responses.
  No Adobe partnership, endorsement, credential, or live API call is implied.
- All parties, project details, evidence files, balances, and license references
  are fictional.
- EMILIA does not hold or move money.
- A production Escrow.com adapter requires a durable `claimEffectBinding`
  function so one release-effect reference cannot migrate to another provider
  transaction or milestone.
- The scenario does not establish legal enforceability, signer identity,
  comprehension, provider licensing, workmanship, or physical completion.
