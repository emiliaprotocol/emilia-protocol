# Submitting draft-schrock-ep-authorization-receipts-01

Step-by-step instructions for the author (Iman Schrock) to submit revision
**-01** to the IETF Datatracker. Nobody but the author submits; these notes
produce the file and tell you exactly what to upload.

## TL;DR

1. Build the text + (re)validate the XML with `xml2rfc` (commands below).
2. Go to <https://datatracker.ietf.org/submit/>, log in as the -00 author.
3. Upload the **XML** (`draft-schrock-ep-authorization-receipts-01.xml`).
   Datatracker renders the `.txt`/`.html` itself; the XML is the source of
   record, exactly as for -00.
4. Confirm the metadata: this **replaces** `draft-schrock-ep-authorization-receipts-00`
   (Datatracker auto-detects this from the matching base name + bumped `-01`).
5. Approve the email confirmation Datatracker sends.

## 0. What format was -00, and what -01 is

-00 was generated and validated with **xml2rfc 3.34.0** from
`draft-schrock-ep-authorization-receipts-00.xml` (xml2rfc v3 XML — the
`<rfc version="3">` vocabulary), per `standards/README.md`. The `.txt` is a
rendered artifact, not the source.

-01 keeps the same path:

- `draft-schrock-ep-authorization-receipts-01.xml` — **the submission source**
  (xml2rfc v3).
- `draft-schrock-ep-authorization-receipts-01.md` — the human-readable parallel
  copy, maintained by hand alongside the XML. **Not** submitted; not generated
  by kramdown-rfc.
- `draft-schrock-ep-authorization-receipts-01.txt` — rendered output of the XML,
  produced by the build below. You do not strictly need to upload this (XML is
  enough), but it is what reviewers read.

There is no kramdown-rfc step in this repo. The toolchain is xml2rfc only.

## 1. Build / validate the toolchain

`xml2rfc` is not installed system-wide on this machine, and the Homebrew Python
is externally managed (PEP 668), so install it in a throwaway virtualenv:

```bash
python3 -m venv /tmp/xml2rfc-venv
/tmp/xml2rfc-venv/bin/pip install xml2rfc
/tmp/xml2rfc-venv/bin/xml2rfc --version      # expect: xml2rfc 3.34.0 (or newer)
```

(If you prefer a permanent install: `pipx install xml2rfc`, or
`pip install --user xml2rfc`, or `pip install --break-system-packages xml2rfc`
— the venv route is the least invasive.)

The XML pulls normative/informative references via `xi:include` from
`bib.ietf.org`, so the build needs network access the first time (it caches).

## 2. Build the text and re-validate

```bash
cd /Users/imanschrock/Documents/GitHub.nosync/emilia-protocol/standards
/tmp/xml2rfc-venv/bin/xml2rfc draft-schrock-ep-authorization-receipts-01.xml --text
```

Expected: `Created file draft-schrock-ep-authorization-receipts-01.txt` with **no
warnings** (the long-line warning on the example `statement` was already fixed;
a clean build is the bar — -00 built clean and so does -01).

Optional extra renders for your own review:

```bash
/tmp/xml2rfc-venv/bin/xml2rfc draft-schrock-ep-authorization-receipts-01.xml --html
/tmp/xml2rfc-venv/bin/xml2rfc draft-schrock-ep-authorization-receipts-01.xml --v3   # round-trip lint
```

## 3. (Recommended) Run idnits before uploading

Datatracker runs its own checks at submit time, but catching nits locally is
faster. `idnits` is not installed here; either install it or use the web tool:

- Web: <https://author-tools.ietf.org/idnits> — upload the `.txt`.
- CLI (if you want it): `idnits` ships in the IETF author-tools; or use the
  online API at <https://author-tools.ietf.org/api/idnits>.

-00 passed idnits with zero errors; its one warning was non-ASCII em-dashes /
curly quotes. The -01 still uses Unicode em-dashes (—) throughout, the ≤ sign
in two places (Section 8 "depth ≤ 2"; Appendix A "≤ 280 character"), and one
arrow (→) in Section 11.9 ("prompt-injection → social-engineering"). xml2rfc
accepts these; idnits may emit the same non-ASCII **warning** (not error). If
you want a zero-warning idnits run, replace `—` with ` - `, `≤` with `<=`, `→`
with `->`, and any curly quotes with straight quotes in the XML, then rebuild.
This is cosmetic and does not block submission.

## 4. Submit on Datatracker

1. Go to <https://datatracker.ietf.org/submit/>.
2. Log in with the **same account** that submitted -00 (the draft is tied to
   that author identity).
3. Upload `draft-schrock-ep-authorization-receipts-01.xml`. Datatracker will
   render and run its automated checks.
4. **Replaces field:** Datatracker recognizes this as a revision of
   `draft-schrock-ep-authorization-receipts` because the base name matches and
   the version is `-01`. Confirm the "Replaces" / "Revision of" line points at
   `draft-schrock-ep-authorization-receipts-00`. No separate "replaces a
   different draft" entry is needed — this is the same draft, next revision.
5. Verify author email on the submission matches the address on file
   (`team@emiliaprotocol.ai`) so the confirmation email reaches you.
6. Submit, then click the confirmation link emailed to the author address.

The draft auto-expires 185 days after posting unless further revised; posting
-01 resets that clock.

## 5. Check the I-D submission cutoff calendar FIRST

**Before uploading, check whether an IETF meeting is near.** The Datatracker
**closes I-D submissions** from roughly two weeks before an IETF meeting until
shortly after it begins (the "I-D cutoff"). If a meeting is within ~3 weeks,
submit ahead of the cutoff or wait until the window reopens.

- Meeting + cutoff calendar: <https://datatracker.ietf.org/meeting/important-dates/>
- Current/next meeting at a glance: <https://www.ietf.org/how/meetings/>

Confirm the live dates yourself at submission time — do not rely on a date
hardcoded here.

## 6. After -01 is posted

- The -00 "Next" list in `standards/README.md` still applies: announce on
  `secdispatch@ietf.org` (dispatch guidance), and the courtesy note to the DRP
  author (`ryan@authproof.dev`) re: Section 10 framing.
- For -01 specifically, the substantive change reviewers will care about is the
  new OPTIONAL `initiator_attestation` member (Section 4.1) and its security
  treatment (Section 11.9). Appendix A "Changes since -00" summarizes the diff;
  point reviewers there.
- Update `standards/README.md` to note -01 is posted and what changed (the
  README currently describes -00 as frozen with changes going into -01).
