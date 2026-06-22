//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"
)

// main is the js/wasm entrypoint.
// It registers a global JS function `assayEvaluate` that accepts a single
// string argument (the ABI envelope JSON) and returns the compact Decision
// JSON as a string. On error it returns a JSON object {"error":"..."}.
// The goroutine then blocks forever (select{}) so the module stays alive
// for the host page to invoke the function.
func main() {
	js.Global().Set("assayEvaluate", js.FuncOf(jsEvaluate))
	// Block forever: the module must remain alive for JS to call assayEvaluate.
	select {}
}

// jsEvaluate is the Go-side implementation of the exported JS function.
func jsEvaluate(_ js.Value, args []js.Value) any {
	if len(args) < 1 {
		return errorJSON("assayEvaluate: expected 1 string argument")
	}
	envelope := args[0].String()

	out, err := runEvaluate([]byte(envelope))
	if err != nil {
		return errorJSON(err.Error())
	}
	return string(out)
}

// errorJSON returns a JSON string encoding {"error":"<msg>"}.
func errorJSON(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b)
}
