.PHONY: build test lint fmt adversarial run-node clean smoke validate-examples

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

validate-examples:  ## strict-validate example configs/rules + compose files (CI gate)
	go run ./tools/validate-examples deploy/examples $(wildcard examples)
	@set -e; for f in $$(find examples -name 'docker-compose*.yml' 2>/dev/null); do \
		echo "compose config $$f"; \
		docker compose -f $$f config -q; \
	done

clean:
	rm -rf bin/

smoke:        ## manual smoke test — real docker containers (~30s, requires Docker)
	./scripts/dev/smoke-test.sh
