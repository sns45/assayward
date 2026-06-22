// Package builtin provides the three built-in TrustPolicy definitions shipped
// with assayward. Each policy is embedded at compile time via go:embed so that
// the binary is self-contained and works in wasm/wasip1 environments where
// filesystem access is restricted.
package builtin

import _ "embed"

//go:embed baseline.yaml
var Baseline []byte

//go:embed slsa-l3.yaml
var SLSAL3 []byte

//go:embed serverless-edge.yaml
var ServerlessEdge []byte

// All returns a map of policy name to raw YAML bytes for iteration and tests.
func All() map[string][]byte {
	return map[string][]byte{
		"baseline":        Baseline,
		"slsa-l3":         SLSAL3,
		"serverless-edge": ServerlessEdge,
	}
}
