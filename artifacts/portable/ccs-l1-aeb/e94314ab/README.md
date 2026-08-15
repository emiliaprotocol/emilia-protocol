# Portable CCS 1.1.14 to AEB profile

This directory publishes the portable, no-install reproduction bundle for the
source-locked CCS 1.1.14 to AEB composition profile introduced at source commit
`e94314ab2e6979aba271afae61f645b6c035faa8`.

The archive contains the exact profile source, pinned public test fixture,
readable bundled runtime, deterministic reference report, and runner tests. It
requires Node.js 20 or newer and does not require `npm install`.

```sh
tar -xzf emilia-ccs-l1-aeb-portable-e94314ab.tar.gz
cd emilia-ccs-l1-aeb-portable-e94314ab
npm test
```

Expected result: both runner tests pass, all eight profile checks pass, and
`report.reference.json` remains byte-identical to the deterministic output.

Verify the archive before extraction:

```sh
shasum -a 256 -c SHA256SUMS
```

This is a reproduction of the EMILIA reference adapter. It is not an
independent implementation, deployment, certification, IETF adoption, or
endorsement.
