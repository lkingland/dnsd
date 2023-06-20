all: clean check test

.PHONY: clean
clean:
	@echo "\nCleaning"


.PHONY: check
check: vet fmt lint staticcheck

.PHONY: vet
vet:
	@echo "\nVetting"
	@go vet ./...

.PHONY: fmt
fmt:
	@echo "\nChecking Formatting"
	@find . -name '*.go' -not -path "./vendor/*" | xargs gofmt -s -l
	@if [ "`find . -name '*.go' -not -path "./vendor/*" | xargs gofmt -s -l`" ]; then echo "Code is not formatted properly with gofmt."; exit 1; fi

.PHONY: lint
lint:
	@echo "\nLinting"
	@golangci-lint run ./...

.PHONY: staticcheck
staticcheck:
	@echo "\nStaticcheck"
	@staticcheck ./...

.PHONY: test
test: 
	@echo "\nTesting"
	@go test -cover -race ./...
