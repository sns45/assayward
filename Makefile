.PHONY: build test lint wasm wasm-clean

build:
	go build ./...

test:
	go test ./...

lint:
	go vet ./...

wasm:
	mkdir -p dist
	GOOS=wasip1 GOARCH=wasm go build -o dist/assayward.wasm ./core/wasm
	GOOS=js GOARCH=wasm go build -o dist/assayward_js.wasm ./core/wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" dist/wasm_exec.js

wasm-clean:
	rm -f dist/assayward.wasm dist/assayward_js.wasm dist/wasm_exec.js
