<!-- SPDX-License-Identifier: Apache-2.0 -->
# Assurance-letter migration: retirement record

**Status: superseded on 2026-07-14. Do not execute this migration.**

The standalone S/H/V/Q assurance-class draft was retired before filing. It
created a second cross-protocol taxonomy while deployed receipts, authority
records, and application profiles already carried different, context-specific
values. Migrating stored data would have changed authority-result hashes
without creating an interoperable proof property.

The durable rule is now:

1. receipt wire aliases remain `software`, `class_a`, and `quorum`;
2. existing authority-registry A/B/C values remain deployment-local until that
   registry receives its own versioned migration;
3. relying-party requirements SHOULD name verifier-visible predicates such as
   `user_verified`, `named_human_bound`, `initiator_excluded`,
   `distinct_humans`, `freshness`, and `revocation_currency` rather than infer
   them from a universal letter; and
4. a higher-level assurance profile may be proposed later only when an external
   host protocol needs a shared mapping and the mapping is backed by
   conformance vectors.

No alias migration, database rewrite, or public API rename is authorized by
this record. Any future shared assurance vocabulary requires a new proposal,
an external interoperability need, explicit mappings from native verifier
outputs, and executable conformance vectors.
