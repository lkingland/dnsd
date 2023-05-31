all: check test

.PHONY: check
check: vet fmt lint staticcheck

.PHONY: vet
vet:
	@echo "Running go vet"
	@go vet ./...

.PHONY: fmt
fmt:
	@echo "Running gofmt"
	@find . -name '*.go' -not -path "./vendor/*" | xargs gofmt -s -l
	@if [ "`find . -name '*.go' -not -path "./vendor/*" | xargs gofmt -s -l`" ]; then echo "Code is not formatted properly with gofmt."; exit 1; fi

.PHONY: lint
lint:
	@echo "Running golangci-lint"
	@golangci-lint run ./...

.PHONY: staticcheck
staticcheck:
	@echo "Running staticcheck"
	@staticcheck ./...

.PHONY: test
test: 
	@echo "Testing"
	@go test -cover -race ./...
