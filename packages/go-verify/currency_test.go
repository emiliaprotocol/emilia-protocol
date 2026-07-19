// SPDX-License-Identifier: Apache-2.0
//
// EP-CURRENCY-v1 Go parity tests. Assert the SAME two-valued verification result
// as packages/verify/currency.test.js: authentic_as_of_commit passes through, and
// currency_at_T is the COMPUTED value offline verification cannot supply. Covers
// all four status outcomes plus every fail-safe branch, matching the JS reason
// strings exactly.
package emiliaverify

import (
	"sort"
	"testing"
	"time"
)

const curNow = "2026-07-05T12:00:00.000Z"

var (
	curActionHash = "sha256:" + repeat("a", 64)
	curOtherHash  = "sha256:" + repeat("b", 64)
)

func repeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func f64(v float64) *float64 { return &v }
func sp(v string) *string    { return &v }

// headAt returns a head observed sec seconds before curNow.
func headAt(sec int, extra func(*FreshHead)) *FreshHead {
	base, _ := time.Parse(time.RFC3339Nano, curNow)
	observed := base.Add(-time.Duration(sec) * time.Second).UTC().Format("2006-01-02T15:04:05.000Z07:00")
	h := &FreshHead{ObservedAt: observed}
	if extra != nil {
		extra(h)
	}
	return h
}

func curReceipt() *CurrencyReceipt { return &CurrencyReceipt{ActionHash: curActionHash} }

func TestCurrencyEnumAndVersion(t *testing.T) {
	got := append([]string{}, CurrencyStatus...)
	sort.Strings(got)
	want := []string{"fresh", "stale", "unknown"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CurrencyStatus=%v want %v", got, want)
		}
	}
	if CurrencyVersion != "EP-CURRENCY-v1" {
		t.Fatalf("CurrencyVersion=%q", CurrencyVersion)
	}
}

func TestCurrencyNoFreshHeadUnknown(t *testing.T) {
	r := EvaluateCurrency(CurrencyArgs{Receipt: curReceipt(), AuthenticAsOfCommit: true, Now: sp(curNow)})
	if !r.AuthenticAsOfCommit {
		t.Fatal("authentic should pass through true")
	}
	if r.CurrencyAtT.Status != "unknown" {
		t.Fatalf("status=%q want unknown", r.CurrencyAtT.Status)
	}
	if r.CurrencyAtT.Reason != CurrencyReasonOfflineOnlyNoFreshHead {
		t.Fatalf("reason=%q", r.CurrencyAtT.Reason)
	}
	if r.CurrencyAtT.EvaluatedAt == nil || *r.CurrencyAtT.EvaluatedAt != curNow {
		t.Fatalf("evaluated_at=%v want %q", r.CurrencyAtT.EvaluatedAt, curNow)
	}
}

func TestCurrencyFreshWithinWindow(t *testing.T) {
	r := EvaluateCurrency(CurrencyArgs{
		Receipt: curReceipt(), AuthenticAsOfCommit: true, Now: sp(curNow),
		MaxStalenessSeconds: f64(300), FreshHead: headAt(60, nil),
	})
	if r.CurrencyAtT.Status != "fresh" {
		t.Fatalf("status=%q want fresh", r.CurrencyAtT.Status)
	}
	if r.CurrencyAtT.Reason != CurrencyReasonFreshHeadWithinWindow {
		t.Fatalf("reason=%q", r.CurrencyAtT.Reason)
	}
	if r.CurrencyAtT.EvaluatedAt == nil || *r.CurrencyAtT.EvaluatedAt != curNow {
		t.Fatalf("evaluated_at=%v", r.CurrencyAtT.EvaluatedAt)
	}
}

func TestCurrencyFreshIndependentOfAuthenticity(t *testing.T) {
	r := EvaluateCurrency(CurrencyArgs{
		Receipt: curReceipt(), AuthenticAsOfCommit: false, Now: sp(curNow),
		MaxStalenessSeconds: f64(300), FreshHead: headAt(10, nil),
	})
	if r.AuthenticAsOfCommit {
		t.Fatal("authentic should be false")
	}
	if r.CurrencyAtT.Status != "fresh" {
		t.Fatalf("status=%q want fresh", r.CurrencyAtT.Status)
	}
}

func TestCurrencyStaleTooOld(t *testing.T) {
	r := EvaluateCurrency(CurrencyArgs{
		Receipt: curReceipt(), AuthenticAsOfCommit: true, Now: sp(curNow),
		MaxStalenessSeconds: f64(300), FreshHead: headAt(600, nil),
	})
	if r.CurrencyAtT.Status != "stale" || r.CurrencyAtT.Reason != CurrencyReasonFreshHeadStale {
		t.Fatalf("got %+v", r.CurrencyAtT)
	}
}

func TestCurrencyFutureHeadStale(t *testing.T) {
	r := EvaluateCurrency(CurrencyArgs{
		Receipt: curReceipt(), AuthenticAsOfCommit: true, Now: sp(curNow),
		MaxStalenessSeconds: f64(300), FreshHead: headAt(-60, nil),
	})
	if r.CurrencyAtT.Status != "stale" || r.CurrencyAtT.Reason != CurrencyReasonFreshHeadInFuture {
		t.Fatalf("got %+v", r.CurrencyAtT)
	}
}

func TestCurrencyRevokedScalar(t *testing.T) {
	r := EvaluateCurrency(CurrencyArgs{
		Receipt: curReceipt(), AuthenticAsOfCommit: true, Now: sp(curNow),
		MaxStalenessSeconds: f64(300),
		FreshHead:           headAt(5, func(h *FreshHead) { h.Revoked = true }),
	})
	if r.CurrencyAtT.Status != "stale" || r.CurrencyAtT.Reason != CurrencyReasonRevokedByFreshHead {
		t.Fatalf("got %+v", r.CurrencyAtT)
	}
}

func TestCurrencyRevokedByStatusList(t *testing.T) {
	r := EvaluateCurrency(CurrencyArgs{
		Receipt: curReceipt(), AuthenticAsOfCommit: true, Now: sp(curNow),
		MaxStalenessSeconds: f64(300),
		FreshHead:           headAt(5, func(h *FreshHead) { h.RevokedTargetHashes = []string{curActionHash} }),
	})
	if r.CurrencyAtT.Status != "stale" || r.CurrencyAtT.Reason != CurrencyReasonRevokedByFreshHead {
		t.Fatalf("got %+v", r.CurrencyAtT)
	}
}

func TestCurrencyStatusListDifferentTargetStaysFresh(t *testing.T) {
	r := EvaluateCurrency(CurrencyArgs{
		Receipt: curReceipt(), AuthenticAsOfCommit: true, Now: sp(curNow),
		MaxStalenessSeconds: f64(300),
		FreshHead:           headAt(5, func(h *FreshHead) { h.RevokedTargetHashes = []string{curOtherHash} }),
	})
	if r.CurrencyAtT.Status != "fresh" {
		t.Fatalf("status=%q want fresh", r.CurrencyAtT.Status)
	}
}

func TestCurrencyRequiredButAbsent(t *testing.T) {
	r := EvaluateCurrency(CurrencyArgs{
		Receipt: curReceipt(), AuthenticAsOfCommit: true, Now: sp(curNow),
		FreshHeadRequired: true,
	})
	if r.CurrencyAtT.Status != "stale" || r.CurrencyAtT.Reason != CurrencyReasonFreshHeadRequiredButAbsent {
		t.Fatalf("got %+v", r.CurrencyAtT)
	}
}

func TestCurrencyNoPolicyBound(t *testing.T) {
	r := EvaluateCurrency(CurrencyArgs{
		Receipt: curReceipt(), AuthenticAsOfCommit: true, Now: sp(curNow),
		FreshHead: headAt(1, nil), // no MaxStalenessSeconds
	})
	if r.CurrencyAtT.Status != "stale" || r.CurrencyAtT.Reason != CurrencyReasonMaxStalenessInvalid {
		t.Fatalf("got %+v", r.CurrencyAtT)
	}
}

func TestCurrencyNegativeBound(t *testing.T) {
	r := EvaluateCurrency(CurrencyArgs{
		Receipt: curReceipt(), AuthenticAsOfCommit: true, Now: sp(curNow),
		MaxStalenessSeconds: f64(-1), FreshHead: headAt(1, nil),
	})
	if r.CurrencyAtT.Status != "stale" || r.CurrencyAtT.Reason != CurrencyReasonMaxStalenessInvalid {
		t.Fatalf("got %+v", r.CurrencyAtT)
	}
}

func TestCurrencyUnparseableNow(t *testing.T) {
	r := EvaluateCurrency(CurrencyArgs{
		Receipt: curReceipt(), AuthenticAsOfCommit: true, Now: sp("not-a-time"),
		MaxStalenessSeconds: f64(300), FreshHead: headAt(1, nil),
	})
	if r.CurrencyAtT.Status != "unknown" || r.CurrencyAtT.Reason != CurrencyReasonNowInvalid {
		t.Fatalf("got %+v", r.CurrencyAtT)
	}
	if r.CurrencyAtT.EvaluatedAt != nil {
		t.Fatalf("evaluated_at should be nil, got %v", *r.CurrencyAtT.EvaluatedAt)
	}
}

func TestCurrencyMalformedHead(t *testing.T) {
	// head with no observation instant.
	r := EvaluateCurrency(CurrencyArgs{
		Receipt: curReceipt(), AuthenticAsOfCommit: true, Now: sp(curNow),
		MaxStalenessSeconds: f64(300), FreshHead: &FreshHead{},
	})
	if r.CurrencyAtT.Status != "unknown" || r.CurrencyAtT.Reason != CurrencyReasonFreshHeadMalformed {
		t.Fatalf("got %+v", r.CurrencyAtT)
	}
}

func TestCurrencyAuthenticPassThroughAndFailSafe(t *testing.T) {
	// authentic omitted (zero value false).
	r := EvaluateCurrency(CurrencyArgs{Receipt: curReceipt(), Now: sp(curNow)})
	if r.AuthenticAsOfCommit {
		t.Fatal("omitted authentic should be false")
	}
}

func TestCurrencyEmptyArgsFailSafeDefault(t *testing.T) {
	r := EvaluateCurrency(CurrencyArgs{})
	if r.AuthenticAsOfCommit {
		t.Fatal("authentic default false")
	}
	if r.CurrencyAtT.Status != "unknown" || r.CurrencyAtT.Reason != CurrencyReasonOfflineOnlyNoFreshHead {
		t.Fatalf("got %+v", r.CurrencyAtT)
	}
}
