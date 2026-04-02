# Developer Certificate of Origin (DCO)

All contributions to the EMILIA Protocol repository must be signed off with the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO).

## What is the DCO?

The DCO is a lightweight alternative to a Contributor License Agreement (CLA). It
certifies that you have the right to submit the contribution and that you agree to
the project's open-source license.

Full text of the DCO (version 1.1):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

## How to sign your commits

Add a `Signed-off-by` trailer to each commit message:

```
git commit -s -m "feat: add handshake expiry cascade"
```

This appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

To add a sign-off to the most recent commit:

```
git commit --amend --signoff
```

To add sign-offs to all commits in a branch (rebasing onto main):

```
git rebase --signoff main
```

## CI enforcement

Every pull request is checked by the DCO bot (`.github/workflows/dco.yml`).
The check fails if any commit in the PR is missing a `Signed-off-by` line.
The PR cannot be merged until all commits are signed off.

## Questions

Open an issue or contact the maintainers at the addresses listed in `SECURITY.md`.
