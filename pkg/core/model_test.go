package core

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDecisionJSONRoundTrip(t *testing.T) {
	d := Decision{
		Result:    ResultDeny,
		Policy:    "slsa-l3@v1alpha1",
		Reasons:   []Reason{{Code: "SLSA_LEVEL_BELOW_THRESHOLD", Severity: SeverityHigh, Detail: "got 2 want 3", Met: false}},
		Evidence:  EvidenceSummary{Image: ImageRef{Name: "r/x:1", Digest: "sha256:abc"}, AttestationTypes: []string{"slsa"}},
		DecidedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var got Decision
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Result != ResultDeny || got.Policy != "slsa-l3@v1alpha1" || len(got.Reasons) != 1 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestFixedClock(t *testing.T) {
	want := time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)
	if (FixedClock{T: want}).Now() != want {
		t.Fatal("clock not fixed")
	}
}
