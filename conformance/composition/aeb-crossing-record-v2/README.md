# AEB crossing-record v2 case catalog

`cases.catalog.json` names the positive, substitution, freshness, downgrade,
and cross-version cases exercised directly by
`packages/verify/aeb-crossing-record.test.ts`. It is an index of those tests,
not a standalone executable vector format.
Run them from `packages/verify`:

```sh
npm run build
tsx --test aeb-crossing-record.test.ts
```

The tests exercise the EMILIA reference implementation. They are not independent
implementation evidence, certification, deployment evidence, or authority to
perform an action.
