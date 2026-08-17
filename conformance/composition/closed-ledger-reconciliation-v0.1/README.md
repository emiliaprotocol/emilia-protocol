# Closed-population reconciliation harness (v0.1)

EMILIA's coverage reconciliation run over a source population that is closed
with respect to itself: a public ledger after finality. Built for the
commitment made on the SCITT list to run this on the
draft-hawkins-scitt-attested-agent-payment testnet at EMILIA's own cost. The
testnet endpoint is not yet known, so this harness runs against a
deterministic fixture ledger; the ledger sits behind one small adapter
interface, and the real testnet is an adapter swap.

## What is reused, what is new

- The reconciliation is `packages/gate` `runCoverageReconciliation`, imported
  as-is (not forked), together with its signed source inventories and its
  signed attestation. Its bin names are its own; the harness reads them from
  the imported runner at run time and follows the upstream rename of
  `receipt_without_effect` to `receipted_without_observation`, whichever
  state the runner carries.
- The source-population completeness declaration and the reading policy are
  the harness layer. The runner's claim boundary deliberately excludes source
  completeness; this harness is where a completeness claim can honestly
  live, because the adapter that fetches the population also declares how
  that population is closed.

## The completeness ladder

As discussed on-list, the declaration takes one of four rungs:

1. `protocol_defined` - the population is closed by a stated protocol rule
   (here, a finality rule with a stated horizon)
2. `measured` - closure estimated from observation
3. `operator_declared` - the source operator asserts closure
4. `undeclared` - nothing is claimed

The fixture ledger declares `protocol_defined` and states its rule: the
finalized view at observation time T contains exactly the settlements with
consensus timestamp at or before T minus 600 seconds, and after that horizon
the finalized set for a window is closed.

## The reading the report asserts

A record in the receipted-without-observation bin is a receipt naming a
settlement absent from the finalized ledger. With a closed population that
absence supports the STRONG reading, the effect did not occur, and the report
asserts it ONLY when all three conditions hold:

1. completeness is `protocol_defined`, and
2. the receipt's settlement would land on this ledger, and
3. the finality horizon has passed at observation time, outside the declared
   clock-skew bound.

A settlement still inside the finality horizon is IN FLIGHT: its own outcome,
never collapsed into either reading. A receipt whose expected settlement time
sits at the finality boundary within the skew bound is INDETERMINATE. A
receipt for an off-ledger effect gets at most the WEAK reading: no
observation recorded, effect status unknown.

Clock skew (raised by the draft author on-list): each side declares its clock
source (`fixture-consensus-timestamp` for the ledger,
`fixture-gate-clock` for the receipt side) and the harness applies the larger
declared skew bound at the boundary.

## Cases

| id | shows |
| --- | --- |
| clean-reconciliation | all receipts match finalized settlements |
| absent-after-finality-strong-reading | strong reading asserted with its three conditions stated |
| in-flight-own-outcome | in-flight is its own outcome |
| skew-boundary-indeterminate | boundary within skew takes no reading |
| off-ledger-weak-reading | off-ledger effect capped at the weak reading |
| effect-without-receipt-still-surfaced | the opposite direction still surfaces |

## Run

```
node conformance/composition/closed-ledger-reconciliation-v0.1/run.mjs
node --test conformance/composition/closed-ledger-reconciliation-v0.1/run.test.mjs
```

Fixtures are deterministic (fixed Ed25519 seeds, fixed timestamps); the test
suite asserts two runs produce an identical report digest. No byte-exact
reference report is committed, deliberately: the runner's bin names belong to
packages/gate and are under active revision, and this harness follows the
runner rather than freezing it.

## Claim boundary

- This runs against a FIXTURE ledger, not the draft author's testnet.
  Nothing here characterizes his rail, its finality, or its clocks.
- The strong reading is conditional on the declared completeness level and
  finality rule. The fixture defines both, so they hold here by
  construction; a real rail must prove its own finality rule before the
  strong reading transfers. Swapping the adapter changes where the
  declaration comes from, not what the harness asserts.
- The reconciliation runner proves what the supplied signed populations
  contain; it never self-proves source completeness, and this harness does
  not change that. The completeness declaration is the harness's own claim,
  carried in the harness report, on the ladder above.
