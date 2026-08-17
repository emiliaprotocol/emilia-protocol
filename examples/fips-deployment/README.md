<!-- SPDX-License-Identifier: Apache-2.0 -->
# Runnable FIPS posture check

This directory turns `docs/deployment/FIPS-MODE.md` from a document you read into
a program you run. It answers one question about the process it is running in:
which EP cryptographic operations does this host's posture permit, and for the
ones it refuses, by what name.

- `posture-check.mjs` - the reporter. Runs anywhere Node runs. Exits 0 on an
  ordinary non-FIPS machine.
- `Containerfile.rocky9` - a reference container. **Reviewed reference material,
  never built.** See [what was and was not verified](#what-was-verified-and-what-was-not).

## The boundary, quoted from the deployment document

These sentences are reproduced verbatim from `docs/deployment/FIPS-MODE.md` and
they govern everything in this directory:

> FIPS-based algorithms, with a validated-provider deployment mode.

> It does not earn "FIPS compliant" and it does not earn "FIPS validated".

> EP is not FIPS compliant and not FIPS validated. No EP package, receipt, or
> deployment carries a CMVP certificate. What the deployment mode gives you is a
> defensible, testable statement about which algorithms run inside a validated
> module's boundary and which do not, plus a runtime that refuses by name when
> it cannot tell.

A PASS from `posture-check.mjs` earns the first sentence and nothing beyond it.
It is not a compliance finding, it is not an assessment, and it says nothing
about whether the provider binary on the host is the exact CMVP-validated build.

## Running it

```bash
npm run build -w packages/verify     # once, so dist/fips-mode.js exists
node examples/fips-deployment/posture-check.mjs
```

The check imports `@emilia-protocol/verify/fips-mode`, the package subpath
export, and falls back to the repo-relative root shim and then the emitted
`dist` module so it also runs from a bare checkout. The line at the top of the
output names which path it actually used.

Two optional inputs, both read only as exact literals:

| Variable | Values | Effect |
|---|---|---|
| `EP_FIPS_ED25519_IN_BOUNDARY` | `true` / `false` | Your declaration, read off your CMVP certificate, of whether EdDSA is Approved in your provider. Anything else leaves it UNDECLARED. |
| `NODE_OPTIONS=--force-fips` | - | Node refuses to start at all unless a provider named `fips` loads. The production posture. |

No runtime check can settle the Ed25519 declaration. It is read off a security
policy PDF, which is why the module treats it as an operator input and refuses
an undeclared boundary under an active FIPS mode instead of guessing.

### Exit codes

| Verdict | Exit | Meaning |
|---|---|---|
| `PASS` | 0 | FIPS mode active and an approved operation completed in this process. |
| `INACTIVE` | 0 | FIPS mode verifiably off. The expected result on a dev machine or CI runner. Not an error. |
| `INDETERMINATE` | 1 | The build cannot report a FIPS status at all. Indeterminate is not "off". |
| `MISCONFIGURED` | 1 | The FIPS flag is set and OpenSSL cannot service a SHA-256 digest. Trap 1 from the deployment document. |
| `UNRESOLVED` | 2 | The `fips-mode` module could not be imported. Build the verify package. |

## Expected output

### State 1: development machine, FIPS inactive

Captured on this repository's development host on 2026-08-17 (Node v26.5.0,
statically linked OpenSSL 3.6.3), exit code 0:

```
EP FIPS posture check (EP-FIPS-MODE-v1)
module imported via: package subpath export -- @emilia-protocol/verify/fips-mode
------------------------------------------------------------------------------
PROCESS POSTURE
  fips_status                   : inactive
  fips_mode_active              : false
  node_version                  : 26.5.0
  openssl_version               : 3.6.3
  openssl_operational (probed)  : true
  ed25519_operational (probed)  : true
  ed25519_in_validated_boundary : undeclared   [operator declaration: unset (UNDECLARED)]
...
  algorithm  acknowledgment flag             decision   reason  boundary
  ---------  ------------------------------  ---------  ------  ---------------------------------------
  Ed25519    allow_unvalidated_mldsa absent  PERMITTED  -       openssl_provider
  Ed25519    allow_unvalidated_mldsa=true    PERMITTED  -       openssl_provider
  ML-DSA-65  allow_unvalidated_mldsa absent  PERMITTED  -       javascript_outside_any_validated_module
  ML-DSA-65  allow_unvalidated_mldsa=true    PERMITTED  -       javascript_outside_any_validated_module
...
CLASSICAL (OpenSSL-backed) ASSERTION
  ok     : false
  reason : fips_mode_inactive

VERDICT: INACTIVE
```

The named reason is `fips_mode_inactive`: FIPS mode is verifiably off, which is
a real answer rather than an absence. Every algorithm is permitted, the ML-DSA
acknowledgment is not armed, and the two ML-DSA rows are identical. That is the
point of the design. Adopting `checkOperationPolicy()` at an existing call site
changes nothing for a deployment in this state.

### State 2: the trap, reproduced

Also captured on the same host, by setting the flag with no provider behind it
(`crypto.setFips(true)` before loading the check). Exit code 1:

```
  algorithm  acknowledgment flag             decision   reason                            boundary
  ---------  ------------------------------  ---------  --------------------------------  ---------------------------------------
  Ed25519    allow_unvalidated_mldsa absent  REFUSED    openssl_provider_not_operational  openssl_provider
  Ed25519    allow_unvalidated_mldsa=true    REFUSED    openssl_provider_not_operational  openssl_provider
  ML-DSA-65  allow_unvalidated_mldsa absent  REFUSED    mldsa_implementation_unvalidated  javascript_outside_any_validated_module
  ML-DSA-65  allow_unvalidated_mldsa=true    PERMITTED  -                                 javascript_outside_any_validated_module

VERDICT: MISCONFIGURED
```

`getFips()` returns 1 here and a SHA-256 digest fails. A dashboard reading the
flag alone would report this dead process as a hardened one. Note the fourth
row: the acknowledgment flag flips ML-DSA to PERMITTED even in this state,
because permission has never been a validation claim.

### State 3: Rocky Linux 9 on a FIPS-enabled host

**NOT CAPTURED.** No FIPS host was available to the session that wrote this, and
nothing below was observed running. What follows is what the module's decision
table requires, and that table is exercised cell by cell against injected
posture objects in `packages/verify/fips-mode.test.ts`. It is a prediction from
tested logic, not a recorded run. Do not quote it as a result.

With the host in FIPS mode, the distro Node loading the distro provider, and no
boundary declaration:

```
  fips_status                   : active
  openssl_operational (probed)  : true
  ed25519_operational (probed)  : true | false   (provider-version dependent)
  ed25519_in_validated_boundary : undeclared

  Ed25519    ...  REFUSED    ed25519_boundary_undeclared        (if the probe said true)
  Ed25519    ...  REFUSED    ed25519_unavailable_in_provider    (if the probe said false)
  ML-DSA-65  ...  REFUSED    mldsa_implementation_unvalidated
  ML-DSA-65  (flag=true) ...  PERMITTED
  VERDICT: PASS
```

The PASS is about SHA-256 and ES256, the two algorithms Approved in every
certificate in the deployment document's tables. Ed25519 stays refused until you
declare the boundary, and declaring it is a statement about your certificate
that you are making, not one the runtime made for you:

```bash
EP_FIPS_ED25519_IN_BOUNDARY=true node examples/fips-deployment/posture-check.mjs
```

Declare `true` only if the certificate governing your provider lists EdDSA among
its Approved algorithms. Per the deployment document's tables, Rocky Linux 9
(#5116), Chainguard (#5132), and TuxCare (#5373) do; upstream OpenSSL (#4282,
#4985), RHEL 9 (#4857), Ubuntu (#4794, #5115), and Amazon Linux 2023 (#5021,
#5438) do not.

## The container

`Containerfile.rocky9` was written, reviewed, and never built. It exists to be
read. The two findings that shaped it:

**A container cannot enable FIPS mode by itself.** Red Hat states, for RHEL 9,
which Rocky Linux 9 rebuilds: "To enable the full set of cryptographic module
self-checks mandated by the Federal Information Processing Standard Publication
140 (FIPS mode), the host system kernel must be running in FIPS mode. The podman
utility automatically enables FIPS mode on supported containers." And: "The
fips-mode-setup command does not work correctly in containers, and it cannot be
used to enable or check FIPS mode in this scenario." The section's stated
prerequisite is one line: "The host system must be in FIPS mode." So the image
installs the provider and wires the paths; the FIPS state is inherited from the
host, enabled there once with `fips-mode-setup --enable` followed by a reboot.
On a host that is not in FIPS mode, the image runs and reports INACTIVE. That is
the honest report, and installing FIPS-related packages in an image proves
nothing on its own.

**The Node package decides whether the check can ever go active.** Rocky 9's
AppStream `nodejs-libs` declares ELF dependencies on `libcrypto.so.3` and
`libssl.so.3`, so the distro Node is dynamically linked against the system
OpenSSL and loads the `fips.so` that `openssl-fips-provider` installs. A Node
from a nodejs.org tarball carries its own statically linked OpenSSL and no
provider module, so it can never load one. Use `dnf module enable nodejs:22`
(streams 18, 20, 22, and 24 are available), never a downloaded tarball.

## What was verified, and what was not

Every host-requirement claim above and in the Containerfile, labelled. VERIFIED
means the cited source was retrieved and read on 2026-08-17 by the session that
wrote this file. REPORTED means secondary or inferential. UNCHECKED means what
it says.

| Claim | Label | Source |
|---|---|---|
| A container needs the host system kernel in FIPS mode for the full set of module self-checks | VERIFIED | [RHEL 9 Security hardening 3.4](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/switching-rhel-to-fips-mode_security-hardening) |
| `fips-mode-setup` does not work correctly in containers | VERIFIED | same, 3.4 |
| `podman` automatically enables FIPS mode on supported containers when the host has it | VERIFIED | same, 3.4 |
| Host enablement is `fips-mode-setup --enable`, then reboot, then `--check` | VERIFIED | same, 3.3 |
| `fips-mode-setup` adds, on top of `update-crypto-policies --set FIPS`, the FIPS dracut module via `fips-finish-install`, the `fips=1` kernel option, and an initramfs regeneration | VERIFIED | same, 3.3 |
| Rocky 9 BaseOS ships `openssl-fips-provider`, whose only shared object is `/usr/lib64/ossl-modules/fips.so` | VERIFIED | Rocky 9 BaseOS `primary.xml` and `filelists.xml` from `dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/repodata/` |
| `openssl-libs` owns `/etc/pki/tls/openssl.cnf` and `/etc/pki/tls/fips_local.cnf` | VERIFIED | same filelists |
| No Rocky 9 BaseOS package ships a `fipsmodule.cnf` | VERIFIED (negative claim; scope: Rocky 9 BaseOS x86_64 filelists, string `fipsmodule`, all packages) | same filelists |
| `crypto-policies-scripts` owns `/usr/bin/fips-mode-setup` and `/usr/bin/fips-finish-install` | VERIFIED | same filelists |
| Rocky 9 AppStream offers nodejs module streams 18, 20, 22, 24 | VERIFIED | Rocky 9 AppStream `modules.yaml` |
| Rocky 9 `nodejs-libs` (22.23.1, 24.18.0) requires `libcrypto.so.3` and `libssl.so.3`, so distro Node is dynamically linked against system OpenSSL | VERIFIED | Rocky 9 AppStream `primary.xml` |
| The Red Hat source spec for that package configures Node with `--shared-openssl` | VERIFIED | [centos-stream rpms/nodejs](https://gitlab.com/redhat/centos-stream/rpms/nodejs), branches `c9s` and `stream-nodejs-22-rhel-9.9.0` |
| That spec applies `--openssl-is-fips` only on Fedora 36+, so the el9 build does not carry it | VERIFIED | same spec, the `%if 0%{?fedora} >= 36` guard around `%global openssl_fips_configure` |
| That does not block FIPS on OpenSSL 3, because Node's FIPS path is provider-shaped: `--enable-fips` / `--force-fips` call `OSSL_PROVIDER_load(nullptr, "fips")` and return false when it is null | VERIFIED | Node v22.x `src/crypto/crypto_util.cc`, `ProcessFipsOptions()` |
| A failed FIPS enable is fatal at process startup, not a warning | VERIFIED | Node v22.x `src/node.cc`, the `ProcessFipsOptions()` call site emitting "OpenSSL error when trying to enable FIPS" |
| `--force-fips` is accepted inside `NODE_OPTIONS` | VERIFIED | Node v22.x `src/node_options.cc`, both flags registered `kAllowedInEnvvar`; reproduced locally, exit 1 |
| Node's own documentation requires Node to be built against a FIPS-capable OpenSSL for those flags | VERIFIED | [nodejs.org/api/cli.html](https://nodejs.org/api/cli.html) |
| CMVP #5116 is "Rocky Linux 9 OpenSSL FIPS Provider", vendor Ctrl IQ, FIPS 140-3, Active, initial validation 2026-01-06 | VERIFIED | [CMVP certificate #5116](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5116) |
| #5116, #5132, and #5373 list EdDSA among Approved algorithms | REPORTED here | `docs/deployment/FIPS-MODE.md` records this as VERIFIED from the security policies; the PDFs were not re-read by this session |
| A nodejs.org Node ships no FIPS provider module, so `--enable-fips` finds nothing to load | REPORTED, with one local measurement | `docs/deployment/FIPS-MODE.md` labels it REPORTED; on this dev host `node --force-fips` exits 1 with "OpenSSL error when trying to enable FIPS" |
| Rocky 9's public `openssl-fips-provider` RPM is the exact binary covered by #5116 | **UNCHECKED, and do not assume it** | see below |
| `Containerfile.rocky9` builds and runs | **UNCHECKED** | never built, no image produced, no command in it executed |

### The version caveat, stated plainly

The `openssl-fips-provider` package currently in Rocky 9 BaseOS is
`3.5.5-6.el9_8` (VERIFIED from the repository metadata). The module version
recorded for CMVP #5116 in `docs/deployment/FIPS-MODE.md` is `Rocky9.20250210`,
and the certificate's vendor is Ctrl IQ with a product URL pointing at CIQ's
Rocky Linux offering (VERIFIED from the certificate page). Those are not
obviously the same artifact. A certificate attaches to a specific build of a
specific module on a specific platform, so before any deployment claims coverage
under #5116, compare the installed package to the module version and tested
configuration named in the security policy, and take the answer from there
rather than from the fact that a package with "fips" in its name is installed.

## Related

- `docs/deployment/FIPS-MODE.md` - the certificate tables, the two traps, and the
  full decision table.
- `packages/verify/src/fips-mode.ts` - EP-FIPS-MODE-v1, the module this check
  reports from.
- `packages/verify/fips-mode.test.ts` - the decision table exercised cell by cell
  against injected postures, so the matrix is deterministic on FIPS and non-FIPS
  hosts alike.
