package testfix_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sns45/assayward/internal/testfix"
	"github.com/sns45/assayward/pkg/core/verify"
)

// fixtureCase describes a fixture file and the predicateType we expect in its
// decoded in-toto statement payload.
type fixtureCase struct {
	rel           string
	predicateType string
}

// fixtureSmoke decodes every fixture through verify.DecodeDSSE and checks that
// the decoded payload is a JSON object whose predicateType matches the expected
// value.
func TestFixturesDecodeDSSE(t *testing.T) {
	cases := []fixtureCase{
		{
			rel:           "slsa/valid-l3.dsse.json",
			predicateType: "https://slsa.dev/provenance/v1",
		},
		{
			rel:           "slsa/digest-mismatch.dsse.json",
			predicateType: "https://slsa.dev/provenance/v1",
		},
		{
			rel:           "sbom/cyclonedx.dsse.json",
			predicateType: "https://cyclonedx.org/bom",
		},
		{
			rel:           "vex/affected-critical.dsse.json",
			predicateType: "https://openvex.dev/ns/v0.2.0",
		},
		{
			rel:           "vex/not-affected.dsse.json",
			predicateType: "https://openvex.dev/ns/v0.2.0",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.rel, func(t *testing.T) {
			raw := testfix.Load(t, tc.rel)

			decoded, err := verify.DecodeDSSE(raw)
			if err != nil {
				t.Fatalf("DecodeDSSE(%q): unexpected error: %v", tc.rel, err)
			}

			// Sanity: payloadType must be application/vnd.in-toto+json.
			const wantPayloadType = "application/vnd.in-toto+json"
			if decoded.PayloadType != wantPayloadType {
				t.Errorf("PayloadType = %q; want %q", decoded.PayloadType, wantPayloadType)
			}

			// Decode the payload as a generic JSON object and extract predicateType.
			var stmt map[string]json.RawMessage
			if err := json.Unmarshal(decoded.Payload, &stmt); err != nil {
				t.Fatalf("unmarshal payload as JSON object: %v", err)
			}

			rawPT, ok := stmt["predicateType"]
			if !ok {
				t.Fatal("payload JSON has no 'predicateType' key")
			}

			var gotPT string
			if err := json.Unmarshal(rawPT, &gotPT); err != nil {
				t.Fatalf("unmarshal predicateType: %v", err)
			}

			if gotPT != tc.predicateType {
				t.Errorf("predicateType = %q; want %q", gotPT, tc.predicateType)
			}
		})
	}
}

// TestFixturesSLSASubjectDigest verifies the valid-l3 fixture references
// TestImageDigest and the digest-mismatch fixture does NOT.
func TestFixturesSLSASubjectDigest(t *testing.T) {
	type subjectEntry struct {
		Digest map[string]string `json:"digest"`
	}
	type stmtShape struct {
		Subject []subjectEntry `json:"subject"`
	}

	decodeSubject := func(t *testing.T, rel string) string {
		t.Helper()
		raw := testfix.Load(t, rel)
		decoded, err := verify.DecodeDSSE(raw)
		if err != nil {
			t.Fatalf("DecodeDSSE(%q): %v", rel, err)
		}
		var s stmtShape
		if err := json.Unmarshal(decoded.Payload, &s); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if len(s.Subject) == 0 {
			t.Fatal("no subjects in statement")
		}
		return s.Subject[0].Digest["sha256"]
	}

	wantHex := strings.TrimPrefix(testfix.TestImageDigest, "sha256:")

	t.Run("valid-l3 matches TestImageDigest", func(t *testing.T) {
		got := decodeSubject(t, "slsa/valid-l3.dsse.json")
		if got != wantHex {
			t.Errorf("digest = %q; want %q", got, wantHex)
		}
	})

	t.Run("digest-mismatch does NOT match TestImageDigest", func(t *testing.T) {
		got := decodeSubject(t, "slsa/digest-mismatch.dsse.json")
		if got == wantHex {
			t.Errorf("expected a different digest, but got the same %q", got)
		}
	})
}

// TestVEXStatuses checks that the two VEX fixtures carry distinct statuses.
func TestVEXStatuses(t *testing.T) {
	type stmtInner struct {
		Statements []struct {
			Status string `json:"status"`
		} `json:"statements"`
	}
	type stmtShape struct {
		Predicate stmtInner `json:"predicate"`
	}

	getStatus := func(t *testing.T, rel string) string {
		t.Helper()
		raw := testfix.Load(t, rel)
		decoded, err := verify.DecodeDSSE(raw)
		if err != nil {
			t.Fatalf("DecodeDSSE(%q): %v", rel, err)
		}
		var s stmtShape
		if err := json.Unmarshal(decoded.Payload, &s); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if len(s.Predicate.Statements) == 0 {
			t.Fatal("no VEX statements in predicate")
		}
		return s.Predicate.Statements[0].Status
	}

	t.Run("affected-critical has status=affected", func(t *testing.T) {
		got := getStatus(t, "vex/affected-critical.dsse.json")
		if got != "affected" {
			t.Errorf("status = %q; want %q", got, "affected")
		}
	})

	t.Run("not-affected has status=not_affected", func(t *testing.T) {
		got := getStatus(t, "vex/not-affected.dsse.json")
		if got != "not_affected" {
			t.Errorf("status = %q; want %q", got, "not_affected")
		}
	})
}
