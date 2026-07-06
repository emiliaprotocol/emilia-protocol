// SPDX-License-Identifier: Apache-2.0
//
// EP-CURRENCY-v1 — the two-valued verification result EP's prose already
// requires, mechanized. Faithful port of packages/verify/currency.js.
//
// There are TWO different questions about a receipt, and conflating them is a
// security defect:
//
//  1. AUTHENTIC-AS-OF-COMMIT — "was this authorization genuinely issued and does
//     its offline cryptography verify?" This is what the offline verifier
//     answers from the artifact alone. It is a statement about the PAST.
//
//  2. CURRENCY-AT-T — "is this authorization STILL valid right now (at time T)?"
//     An offline package CANNOT answer this. Offline verification alone yields
//     currency status "unknown" — the honest, fail-safe default. A caller earns
//     "fresh" ONLY by supplying a FreshHead (a signed, recent head/status entry)
//     whose age is within the action policy's staleness bound AND which does not
//     revoke this receipt. Anything short of that is "unknown" or "stale", never
//     "fresh".
//
// HONESTY IS A SECURITY PROPERTY: reporting "fresh" (i.e. current validity) from
// an offline-only check would be a security defect. This module refuses to let
// the offline default masquerade as currency. EvaluateCurrency does NOT itself
// verify the receipt's offline cryptography (the caller passes in the
// already-computed authentic_as_of_commit); it does NOT prove the FreshHead is
// the log's globally-latest head, and it does NOT detect split-view equivocation.
package emiliaverify

import (
	"regexp"
	"strings"
	"time"
)

// CurrencyVersion identifies the two-valued verification profile.
const CurrencyVersion = "EP-CURRENCY-v1"

// CurrencyStatus values. "fresh" is the ONLY value that asserts current
// validity, reachable ONLY with a policy-satisfying FreshHead. "unknown" is the
// honest offline default; "stale" means the head is too old, was required but
// absent, or shows revocation.
var CurrencyStatus = []string{"fresh", "stale", "unknown"}

// CurrencyReason stable identifiers, byte-identical to currency.js CURRENCY_REASON.
const (
	// status: "unknown"
	CurrencyReasonOfflineOnlyNoFreshHead = "offline_only_no_fresh_head"
	CurrencyReasonFreshHeadMalformed     = "fresh_head_malformed"
	CurrencyReasonNowInvalid             = "now_invalid"
	// status: "stale"
	CurrencyReasonFreshHeadStale             = "fresh_head_stale"
	CurrencyReasonFreshHeadRequiredButAbsent = "fresh_head_required_but_absent"
	CurrencyReasonRevokedByFreshHead         = "revoked_by_fresh_head"
	CurrencyReasonMaxStalenessInvalid        = "max_staleness_invalid"
	// status: "fresh"
	CurrencyReasonFreshHeadWithinWindow = "fresh_head_within_window"
)

// FreshHead is a SIGNED, recent directory/log head or status-list entry the
// caller obtained ONLINE and (by contract) already verified the signature of.
// Supplying a FreshHead is the ONLY way to reach "fresh".
//
// Present is a tri-state pointer so that "absent" (nil FreshHead) is
// distinguishable from a supplied-but-malformed head — mirroring the JS
// undefined/null-vs-object distinction. ObservedAt/IssuedAt are the observation
// instants (RFC 3339); Revoked is the scalar revocation signal;
// RevokedTargetHashes is the status-list of revoked digests; TargetHash is this
// receipt's resolved status-list target.
type FreshHead struct {
	ObservedAt          string
	IssuedAt            string
	Revoked             bool
	RevokedTargetHashes []string
	TargetHash          string
}

// CurrencyReceipt is the minimal receipt view EvaluateCurrency needs: only the
// action_hash, used to match a FreshHead revocation signal to this
// authorization. Its offline cryptography is NOT re-checked here.
type CurrencyReceipt struct {
	ActionHash string
}

// CurrencyArgs are the EvaluateCurrency inputs. Pointer fields model the JS
// optional/undefined semantics: a nil Now uses the current wall clock; a nil
// FreshHead is the offline-only path; a nil MaxStalenessSeconds is a missing
// policy bound.
type CurrencyArgs struct {
	Receipt             *CurrencyReceipt
	AuthenticAsOfCommit bool
	Now                 *string // reference instant T (RFC 3339); nil => current wall clock
	MaxStalenessSeconds *float64
	FreshHead           *FreshHead
	FreshHeadRequired   bool
}

// CurrencyAtT is the computed currency sub-result.
type CurrencyAtT struct {
	Status      string  `json:"status"`
	EvaluatedAt *string `json:"evaluated_at"`
	Reason      string  `json:"reason"`
}

// CurrencyResult is the two-valued verification result.
type CurrencyResult struct {
	AuthenticAsOfCommit bool        `json:"authentic_as_of_commit"`
	CurrencyAtT         CurrencyAtT `json:"currency_at_T"`
}

var currencyHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// currencyHexOf validates to a well-formed 64-char SHA-256; malformed => "" so
// comparisons fail closed (never match a real digest). Mirrors currency.js hexOf.
func currencyHexOf(h string) string {
	s := strings.ToLower(strings.TrimPrefix(h, "sha256:"))
	if currencyHex64.MatchString(s) {
		return s
	}
	return ""
}

// instantMs parses an RFC 3339 instant to epoch milliseconds. Returns (0, false)
// on any unparseable input — the fail-safe convention (a bad clock never
// silently becomes "now"). Mirrors currency.js instantMs / Date.parse for the
// RFC 3339 shapes EP timestamps use.
func instantMs(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
		if err != nil {
			return 0, false
		}
	}
	return t.UnixMilli(), true
}

// isoFromMs renders epoch ms as the millisecond-precision ISO 8601 UTC string
// JS `new Date(ms).toISOString()` produces: YYYY-MM-DDTHH:MM:SS.sssZ.
func isoFromMs(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z07:00")
}

// headRevokesReceipt reports whether a signed head revokes the given receipt.
// A FreshHead MAY carry a revocation signal as Revoked==true (scalar) or a
// RevokedTargetHashes status-list matched against the receipt's action_hash
// (and/or an explicit TargetHash). Fail-safe: a malformed/ambiguous field is
// treated as NON-revoking here. Mirrors currency.js headRevokesReceipt.
func headRevokesReceipt(head *FreshHead, receipt *CurrencyReceipt) bool {
	if head == nil {
		return false
	}
	if head.Revoked {
		return true
	}
	if len(head.RevokedTargetHashes) > 0 {
		targets := map[string]struct{}{}
		for _, t := range head.RevokedTargetHashes {
			if h := currencyHexOf(t); h != "" {
				targets[h] = struct{}{}
			}
		}
		if len(targets) == 0 {
			return false
		}
		var receiptActionHash string
		if receipt != nil {
			receiptActionHash = currencyHexOf(receipt.ActionHash)
		}
		explicitTarget := currencyHexOf(head.TargetHash)
		if receiptActionHash != "" {
			if _, ok := targets[receiptActionHash]; ok {
				return true
			}
		}
		if explicitTarget != "" {
			if _, ok := targets[explicitTarget]; ok {
				return true
			}
		}
	}
	return false
}

// EvaluateCurrency computes the two-valued verification result:
// authenticity-as-of-commit (passed through from the caller's offline check) and
// currency-at-T (which offline CANNOT establish and which is therefore "unknown"
// by default). Faithful port of currency.js evaluateCurrency.
func EvaluateCurrency(args CurrencyArgs) CurrencyResult {
	authentic := args.AuthenticAsOfCommit

	// Resolve reference time T. A bad clock must NOT silently become "now": an
	// unparseable Now yields "unknown" (we will not measure age against it).
	var nowMs int64
	var nowOK bool
	if args.Now == nil {
		nowMs = time.Now().UnixMilli()
		nowOK = true
	} else {
		nowMs, nowOK = instantMs(*args.Now)
	}
	var evaluatedAt *string
	if nowOK {
		iso := isoFromMs(nowMs)
		evaluatedAt = &iso
	}

	result := func(status, reason string) CurrencyResult {
		return CurrencyResult{
			AuthenticAsOfCommit: authentic,
			CurrencyAtT:         CurrencyAtT{Status: status, EvaluatedAt: evaluatedAt, Reason: reason},
		}
	}

	// No fresh head: offline CANNOT prove currency. This is the fail-safe path.
	if args.FreshHead == nil {
		if args.FreshHeadRequired {
			return result("stale", CurrencyReasonFreshHeadRequiredButAbsent)
		}
		return result("unknown", CurrencyReasonOfflineOnlyNoFreshHead)
	}

	// A fresh head was supplied. If T is unusable, we cannot compute the head's
	// age, so we cannot certify freshness — fall back to the honest "unknown".
	if !nowOK {
		return result("unknown", CurrencyReasonNowInvalid)
	}

	// The head must carry a well-formed observation instant. A malformed head
	// cannot certify freshness => "unknown" (not "fresh", not "stale").
	headMs, headOK := instantMs(args.FreshHead.ObservedAt)
	if !headOK {
		headMs, headOK = instantMs(args.FreshHead.IssuedAt)
	}
	if !headOK {
		return result("unknown", CurrencyReasonFreshHeadMalformed)
	}

	// MaxStalenessSeconds is the action-policy bound. Without a valid bound we
	// refuse to certify freshness: fail-safe to "stale".
	if args.MaxStalenessSeconds == nil || *args.MaxStalenessSeconds < 0 {
		return result("stale", CurrencyReasonMaxStalenessInvalid)
	}

	// Revocation shown by the head dominates: a revoked authorization is not
	// current regardless of how recent the head is.
	if headRevokesReceipt(args.FreshHead, args.Receipt) {
		return result("stale", CurrencyReasonRevokedByFreshHead)
	}

	// Age gate. A future-dated head has a negative age; that is within any
	// non-negative window, so it is not stale on age alone.
	ageSeconds := float64(nowMs-headMs) / 1000.0
	if ageSeconds > *args.MaxStalenessSeconds {
		return result("stale", CurrencyReasonFreshHeadStale)
	}

	// Recent, signed (by caller contract), non-revoking head within the policy
	// window: this is the ONLY path to "fresh".
	return result("fresh", CurrencyReasonFreshHeadWithinWindow)
}
