.PHONY: build test lint fmt adversarial run-node clean smoke

build:        ## build daemon + CLI
	go build -o bin/federloomd ./cmd/federloomd
	go build -o bin/federloomctl ./cmd/federloomctl

test:         ## unit + integration tests
	go test ./...

adversarial:  ## poisoning / sybil scenario suite (CI gate)
	go test -tags adversarial ./test/adversarial/...

lint:
	go vet ./...

fmt:
	gofmt -w .

clean:
	rm -rf bin/

smoke:        ## manual smoke test — real docker containers (~30s, requires Docker)
	./scripts/dev/smoke-test.sh
