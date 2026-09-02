GO ?= go
GOLANGCI_LINT_VERSION ?= v2.13.1
GOVULNCHECK_VERSION ?= v1.7.0

.PHONY: check race lint vuln images bench ci

check:
	$(GO) mod verify
	$(GO) build ./...
	$(GO) vet ./...
	$(GO) test ./... -count=1

race:
	$(GO) test -race ./... -count=1

lint:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

images:
	docker build -f Dockerfile.railway -t arkade-vault-server:railway .
	docker build -f Dockerfile.mutinynet -t arkade-vault-server:mutinynet .
	docker run --rm --entrypoint sh \
		--mount type=volume,destination=/app/data \
		--mount type=volume,destination=/app/sequence \
		arkade-vault-server:mutinynet \
		-c 'test -w /app/data && test -w /app/sequence'

bench:
	$(GO) test ./internal/policy -run '^$$' -bench . -benchmem

ci: check race vuln lint images
