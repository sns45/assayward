// Package discover provides file-based attestation discovery for the assayward CLI.
// It is a pure adapter: no verification or policy logic lives here.
package discover

import (
	"fmt"
	"os"

	core "github.com/sns45/assayward/pkg/core"
)

// FromBundles reads each file path and returns one core.Attestation per file.
// The Envelope field is set to the raw file bytes; the engine classifies bundle
// vs DSSE itself. An error is returned immediately if any path is unreadable.
func FromBundles(paths []string) ([]core.Attestation, error) {
	atts := make([]core.Attestation, 0, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("discover: read bundle %q: %w", p, err)
		}
		atts = append(atts, core.Attestation{Envelope: data})
	}
	return atts, nil
}
