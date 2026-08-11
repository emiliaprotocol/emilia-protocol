# Validation record

Validated on 2026-08-11 against the retained candidate bytes:

- `xmllint --noout` accepted the RFCXML source.
- `xml2rfc --no-network` used the locally cached RFC references and generated
  the retained TXT and HTML renderings.
- `idnits 3.1.0 -m submission` reported `PASS - No nit found` for the retained
  TXT rendering.
- `node scripts/check-human-authorization-binding-01.mjs` verified the source,
  renderings, B1-B7 requirements, AIMS and AE-CHALLENGE composition boundaries,
  checksums, and the immutable posted `-00` source.
- `node examples/binding/human-authorization-binding-vector.mjs` passed the
  deterministic positive case and hostile cases for digest tampering, action
  substitution, unpinned discovery, absence, inconsistent forms,
  self-asserted identity, enrolled-subject relabeling, and
  terminal-authority/approver collapse.
- `node --test packages/verify/aeb-wimse-oauth-adapter.test.js` passed 22 tests,
  including the unpinned discovered-authorization-server case and the six
  principal-confusion classes.
- `npm --prefix packages/verify run build` passed, and
  `npm run check:standalone-runtimes` confirmed 574 generated companions are
  synchronized.
- `npm run check:standards-staged`, `npm run check:repository-boundary`, and
  `npm run lint` passed. Lint reported only existing warnings.
- `npm run build` completed the production build successfully without a
  network font dependency.

The packet remains a review candidate. These local results are same-repository
evidence, not an independent implementation, working-group adoption, or filing
authorization. Nothing in this packet has been submitted.
