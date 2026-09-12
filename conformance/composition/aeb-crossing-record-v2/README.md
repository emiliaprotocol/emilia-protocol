# AEB crossing-record v2 vectors

These vectors name the positive, substitution, freshness, downgrade, and
cross-version cases exercised by `packages/verify/aeb-crossing-record.test.ts`.
Run them from `packages/verify`:

```sh
npm run build
tsx --test aeb-crossing-record.test.ts
```

The vectors test the EMILIA reference implementation. They are not independent
implementation evidence, certification, deployment evidence, or authority to
perform an action.
