# How to submit EP-QUORUM — IETF I-D + arXiv preprint

Both artifacts are prepared and validated. The only steps left are the
account-authenticated submissions, which must be done from **your** logged-in
accounts. Everything below is copy-paste ready.

---

## A. IETF Internet-Draft — `draft-schrock-ep-quorum-00`

**Artifact (validated):** `standards/draft-schrock-ep-quorum-00.xml`
(rendered `.txt` alongside it). Built with xml2rfc 3.34.0: **0 warnings,
0 errors, 0 lines over 72 chars, ASCII-only, 14 pages.** It is the same
xml2rfc v3 format as your `-authorization-receipts-01` submission.

**Steps (≈3 min):**
1. Log in at https://datatracker.ietf.org/ (same account you used for the
   `-01` submission, #164385).
2. Go to **https://datatracker.ietf.org/submit/**.
3. Upload `draft-schrock-ep-quorum-00.xml`. Datatracker runs its own
   idnits/format checks and **renders the .txt itself** — you do not need to
   upload the .txt (you may, but the .xml is canonical).
4. Confirm the metadata it extracts (title, author, date 2026-06-20). It
   will email you a confirmation link; click it to finalize.
5. The draft posts at
   `https://datatracker.ietf.org/doc/draft-schrock-ep-quorum/00/`.

**Notes:**
- There is no co-author to approve, so confirmation is single-click from
  your email.
- If datatracker is in a pre-meeting submission **blackout** (it will say
  so), the draft queues and posts when the window reopens — no action needed.
- The draft references your base draft normatively
  (`draft-schrock-ep-authorization-receipts`); that reference is a manual
  `<reference>` entry, so it resolves regardless of bibxml availability.
- **After it posts:** reply on the secdispatch thread noting the companion
  multi-party draft is up (same list rhythm you've been using).

---

## B. arXiv preprint (cs.CR)

**Artifacts (both compile-verified):**
- `docs/papers/ep-quorum-arxiv.tex` — standalone LaTeX, **fully ASCII**
  (no Unicode characters that break arXiv's pdflatex), uses only standard
  packages (longtable, booktabs, hyperref, amsmath). **Compiled clean with
  tectonic** (only cosmetic hbox warnings).
- `docs/papers/ep-quorum-arxiv.pdf` — the built PDF (8 pages), in case you
  prefer to upload a PDF directly.

arXiv prefers LaTeX **source**, so uploading the `.tex` is the recommended
path and it is proven to build; the PDF is a guaranteed-render fallback.
Regenerate from the Markdown with:
`pandoc ep-quorum-preprint.md -t latex --standalone -o ep-quorum-arxiv.tex`
(after stripping the leading HTML comment + byline, as the build does).

**Steps (≈10 min + possible endorsement wait):**
1. Log in / create an account at https://arxiv.org/ . Use your ORCID
   **0009-0004-0290-5433** to pre-fill author identity.
2. **Endorsement:** first-time submitters to **cs.CR** may need an
   endorsement. arXiv shows an endorsement code/link if so; ask a colleague
   who has published in cs.CR to endorse, or submit and follow arXiv's
   prompt. (This is the one step that can introduce a wait.)
3. Start a new submission → upload `ep-quorum-arxiv.tex`. Let arXiv compile;
   review the generated PDF preview.
4. Paste the metadata below.
5. Submit. arXiv assigns an identifier (e.g., `arXiv:2506.NNNNN`) after its
   moderation hold (typically same/next business day).

**Metadata to paste:**

- **Title:** The Two-Person Rule for AI Agents: Fail-Closed Multi-Party
  Authorization with Offline-Verifiable Receipts
- **Authors:** Iman Schrock (EMILIA Protocol, Inc.)
- **Primary category:** cs.CR (Cryptography and Security)
- **Cross-list:** cs.CY (Computers and Society)
- **License:** CC BY 4.0 (matches the source header)
- **Comments:** 8 pages. Companion to the IETF Internet-Draft
  draft-schrock-ep-quorum. Reference implementations and EP-QUORUM-v1
  conformance vectors are open source (Apache-2.0).
- **Abstract:** (paste verbatim)

> Autonomous agents increasingly hold credentials sufficient to perform
> irreversible operations: releasing payments, changing beneficiary records,
> rotating production credentials, deleting data. Existing controls
> authenticate and authorize sessions and scopes; they do not answer the
> question that matters at the moment of execution -- should this exact
> action happen, and which accountable humans said yes? We present
> EP-QUORUM, a multi-party authorization mechanism that ports the two-person
> rule -- the control that governs nuclear release and large-value treasury
> movement -- to AI-agent actions. EP-QUORUM binds a set of
> pairwise-distinct, accountable human approvers, each holding their own
> device-bound signing key, to one exact action, such that the action is
> authorized only when a fail-closed predicate over all of their signatures
> holds. The predicate enforces all-signatures-valid, action-binding,
> separation of duties (distinct humans), role admission, an M-of-N
> threshold, an optional total order, and a bounded approval window. Each
> quorum member is an unmodified single-approver authorization receipt over
> the same action hash, so the construction is additive: a single-approver
> policy is the degenerate one-member case, and the existing offline receipt
> verifier is reused per member. We give the predicate, an incremental
> server-side admission rule that keeps a non-conforming signer out of the
> trail before it is recorded, and an adversarial conformance suite of nine
> vectors that three independent implementations (JavaScript, Python, Go)
> are required to agree on. We are deliberate about limitations: a quorum
> raises the cost of unilateral action and makes every approval
> attributable, but it does not defeat collusion among the required number
> of humans, an enrollment that lets one human hold multiple identities, or
> simultaneous coercion -- and we argue that honesty about these boundaries
> is a security property, not a caveat.

**Sequence:** file the I-D first (or same session), so the arXiv "Comments"
cross-reference points at a live datatracker URL.
