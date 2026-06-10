.PHONY: build test lint fmt adversarial run-node clean smoke

build:        ## build daemon + CLI
	go build -o bin/swarmd ./cmd/swarmd
	go build -o bin/swarmctl ./cmd/swarmctl

test:         ## unit + integration tests
	go test ./...

adversarial:  ## poisoning / sybil scenario suite (CI gate)
	go test ./test/adversarial/...

lint:
	go vet ./...

fmt:
	gofmt -w .

clean:
	rm -rf bin/

smoke:        ## manual smoke test — real docker containers (~30s, requires Docker)
	./scripts/dev/smoke-test.sh
