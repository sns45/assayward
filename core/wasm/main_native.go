//go:build !wasm

package main

// main is a no-op stub for native (non-wasm) builds.
// It exists so that `go build ./...` succeeds natively; the real entrypoints
// are in main_wasip1.go (//go:build wasip1) and main_js.go (//go:build js && wasm).
// Without this stub `go build ./core/wasm` on a native host would fail with
// "runtime.main_main·f: relocation target main.main not defined" because the
// package is `package main` with no main() visible under the native build
// constraints.
func main() {}
