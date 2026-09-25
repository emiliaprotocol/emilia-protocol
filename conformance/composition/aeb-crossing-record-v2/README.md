# AEB crossing-record v2 case catalog

`cases.catalog.json` names the positive, substitution, freshness, downgrade,
cross-version, and evaluation-binding cases exercised directly by
`packages/verify/aeb-crossing-record.test.ts`. It is an index of those tests,
not a standalone executable vector format.
Run them from `packages/verify`:

```sh
npm run build
tsx --test aeb-crossing-record.test.ts
```

The evaluation-binding cases supply the cited AEB evaluation record to the
verifier. Without it, a record still verifies but reports
`evaluation_binding: "INDETERMINATE"`: the evaluation digest is then an
unverified pointer. `BOUND` means the supplied evaluation has the committed
record digest and evaluated the same operation, CAID, action, and native
authority evidence. It does not verify the evaluation's own signature; that
remains the job of the evaluation verifier under relying-party pins.

The tests exercise the EMILIA reference implementation. They are not independent
implementation evidence, certification, deployment evidence, or authority to
perform an action.
