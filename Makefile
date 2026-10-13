# otinv build and test targets. See CLAUDE.md, "Commands".

BIN        := bin/otinv
PKG        := ./...
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# One static binary, no libpcap: captures are read with pure Go.
export CGO_ENABLED := 0

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(BUILD_DATE)

.PHONY: all build generate test test-integration test-update fuzz lint fmt tidy ci clean

all: build

build: generate
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/otinv

# templ generate and the OUI table regeneration hook in here once internal/web
# and internal/oui exist. Kept as a no-op so `make generate lint test` works.
generate:
	@echo "generate: nothing to generate yet (no templ components, no OUI table)"

test:
	go test $(PKG)

test-integration:
	go test -tags integration $(PKG)

# Regenerate the golden files. Review the diff before committing.
test-update:
	go test ./internal/ingest -update

# Short fuzz run for every dissector that has a fuzz target.
fuzz:
	@for pkg in $$(go list $(PKG)); do \
		dir=$$(go list -f '{{.Dir}}' $$pkg); \
		if grep -lq 'func Fuzz' $$dir/*_test.go 2>/dev/null; then \
			echo "fuzzing $$pkg"; \
			go test $$pkg -run '^$$' -fuzz 'Fuzz' -fuzztime 30s || exit 1; \
		fi; \
	done

lint:
	go vet $(PKG)
	golangci-lint run

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

ci: generate lint test

clean:
	rm -rf bin
