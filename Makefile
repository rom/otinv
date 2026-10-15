# otinv build and test targets. See CLAUDE.md, "Commands".

BIN        := bin/otinv
PKG        := ./...
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
TEMPL_VERSION := v0.3.898

# golangci-lint refuses a module whose Go version is newer than the one it was
# built with, so the linter has to keep pace with go.mod. This is the oldest
# release that can analyse the version in go.mod.
GOLANGCI_VERSION := v2.14.0

# Where `make oui` reads the IEEE registry from, and what the provenance note
# should say about it. OUI_DIR is empty by default, which makes that target
# explain itself and change nothing.
OUI_DIR ?=
OUI_SOURCE ?= https://standards-oui.ieee.org/

# How long each fuzz target runs in `make fuzz`. Long enough to catch a
# regression in a changed dissector, short enough to run on every change.
FUZZTIME ?= 30s

# One static binary, no libpcap: captures are read with pure Go.
export CGO_ENABLED := 0

# Never download a toolchain: the build must work on an air-gapped laptop, and
# this fails loudly if a dependency raises the Go floor above the installed
# toolchain instead of silently fetching another one. Override it
# (make GOTOOLCHAIN=auto test) where fetching one is acceptable, such as a
# container whose installed toolchain is older than go.mod asks for.
GOTOOLCHAIN ?= local
export GOTOOLCHAIN

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.buildDate=$(BUILD_DATE)

.PHONY: all build generate generate-templ oui test test-integration test-update fuzz lint fmt tidy ci verify-generated clean

all: build

# Building needs nothing but the Go toolchain: the generated *_templ.go files
# are committed, so templ is only needed when a .templ file changes.
build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/otinv

# Regenerates what is generated and committed: the templ components and the
# embedded IEEE MAC vendor table.
generate: generate-templ oui

# The generated *_templ.go files are committed, so building needs no tools
# beyond the Go toolchain; only changing a .templ file needs templ itself.
generate-templ:
	@command -v templ >/dev/null 2>&1 || { \
		echo "templ is needed only when a .templ file changes; building and testing do not need it."; \
		echo "To install it:"; \
		echo "    go install github.com/a-h/templ/cmd/templ@$(TEMPL_VERSION)"; \
		echo "    # then make sure \$$(go env GOPATH)/bin is on your PATH"; \
		exit 1; }
	templ generate

# Rebuilds internal/oui/table.txt.gz, which names the maker of a network card
# from a MAC address, from the IEEE registry files oui.txt and iab.txt.
#
# The table is committed, so this is a deliberate refresh and never part of a
# build: the files come from https://standards-oui.ieee.org/, which the
# air-gapped laptop otinv is built for cannot reach. Download them where there
# is a network, copy them across, and point OUI_DIR at them. The generator
# records in internal/oui/PROVENANCE.md where they came from, when, and what
# they contained.
oui:
	@if [ -z "$(OUI_DIR)" ]; then \
		echo "skipping the MAC vendor table: it is committed, and a refresh needs the IEEE registry."; \
		echo "To refresh it:"; \
		echo "    make oui OUI_DIR=/path/to/dir/holding/oui.txt/and/iab.txt"; \
	else \
		go run ./internal/oui/ouigen \
			-oui "$(OUI_DIR)/oui.txt" -iab "$(OUI_DIR)/iab.txt" \
			-out internal/oui -source "$(OUI_SOURCE)"; \
	fi

test:
	go test $(PKG)

test-integration:
	go test -tags integration $(PKG)

# Regenerate the golden files. Review the diff before committing.
test-update:
	go test ./internal/ingest -update

# Short fuzz run for every fuzz target in the tree. Go fuzzes one target per
# run, so each is named in turn rather than matched by a pattern.
fuzz:
	@for pkg in $$(go list $(PKG)); do \
		dir=$$(go list -f '{{.Dir}}' $$pkg); \
		for target in $$(sed -n 's/^func \(Fuzz[A-Za-z0-9_]*\)(.*/\1/p' $$dir/*_test.go 2>/dev/null | sort -u); do \
			echo "fuzzing $$pkg $$target"; \
			go test $$pkg -run '^$$$$' -fuzz "^$$target$$$$" -fuzztime $(FUZZTIME) || exit 1; \
		done; \
	done

lint:
	go vet $(PKG)
	@command -v golangci-lint >/dev/null 2>&1 || { \
		echo "golangci-lint is not installed. To install it:"; \
		echo "    go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)"; \
		exit 1; }
	golangci-lint run

fmt:
	gofmt -l -w .

tidy:
	go mod tidy

# Everything a change has to pass, using only the Go toolchain and
# golangci-lint. After editing a .templ file, run `make generate` as well; the
# verify-generated target checks that the committed output is current.
ci: lint test

verify-generated: generate
	@git diff --quiet -- '*_templ.go' || { \
		echo "generated templ output is stale; commit the result of 'make generate'"; \
		git diff --stat -- '*_templ.go'; \
		exit 1; }
	@echo "generated templ output is up to date"

clean:
	rm -rf bin
