//go:build wasip1

package main

import (
	"fmt"
	"io"
	"os"
)

// main is the wasip1 entrypoint.
// It reads the full ABI envelope JSON from stdin, calls runEvaluate,
// and writes the compact Decision JSON to stdout (exit 0).
// On any error it writes the error message to stderr and exits 1.
func main() {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wasm: read stdin: %v\n", err)
		os.Exit(1)
	}

	out, err := runEvaluate(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if _, err := os.Stdout.Write(out); err != nil {
		fmt.Fprintf(os.Stderr, "wasm: write stdout: %v\n", err)
		os.Exit(1)
	}
}
