# Authorization Receipts -11 upload packet

This is the isolated, unsubmitted candidate packet for
`draft-schrock-ep-authorization-receipts-11`, prepared on 2026-08-09.

Submitted file:

- `UPLOAD-THIS/draft-schrock-ep-authorization-receipts-11.xml`

The normative CAID reference is pinned to
`draft-schrock-canonical-action-identifier-02`.

Revision -11:

- defines the closed `EP-AUTHORIZATION-BUNDLE-v1` pre-execution object and
  three-state verification algorithm;
- adds the missing relying-party `audience` commitment;
- defines an optional OAuth/RAR binding covering the authorization server,
  transaction, actor, delegated subject, RAR digest, and pinned action map;
- composes with OAuth Transaction Authorization Challenge without defining a
  competing OAuth flow;
- requires current policy, policy-selected approvers, current status when
  configured, and fail-closed handling of unavailable inputs;
- publishes one TypeScript/JavaScript verifier and 21 generated hostile cases;
  and
- requests `application/ep-authorization-bundle+json` in addition to the
  receipt media type already requested by -10.

The document remains an individual Internet-Draft. Submission would not make
it an RFC, a working-group document, IETF consensus, or IETF endorsement.
