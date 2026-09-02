# Peerbeam build and release targets.
#
# Development builds and tests run on the host with `make build` and `make test`. Release artifacts
# are cross-compiled with `make release`, which produces one self-contained executable per supported
# operating system and architecture (Req 12.2) and checks each against the 50 MiB ceiling (Req 12.7).

BINARY      := peerbeam
CMD         := ./cmd/peerbeam
DIST        := dist
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

# Trim paths and strip the symbol table and DWARF. This is what keeps the binary well under the
# Req 12.7 ceiling of 50 MiB, and -trimpath also keeps the build machine's directory layout out of
# the shipped artifact.
LDFLAGS  := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)
GOFLAGS  := -trimpath

# The release targets from the design: x86-64 and arm64 across the three supported operating systems
# (Req 12.2). windows/arm64 is omitted because Requirement 12.1 names Windows 11 on x86-64 only.
TARGETS := \
	darwin/arm64 \
	darwin/amd64 \
	windows/amd64 \
	linux/amd64 \
	linux/arm64

.PHONY: all build test test-race vet fmt check release clean smoke help

all: check build

## build: compile for the host
build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) $(CMD)

## test: run every test
test:
	go test ./...

## test-race: run every test under the race detector
test-race:
	go test -race ./...

## vet: run go vet for the host and for every release target
vet:
	go vet ./...
	@for target in $(TARGETS); do \
		os=$${target%%/*}; arch=$${target##*/}; \
		printf 'vet %s/%s ... ' "$$os" "$$arch"; \
		GOOS=$$os GOARCH=$$arch go vet ./... >/dev/null || exit 1; \
		echo ok; \
	done

## fmt: check that every file is gofmt clean
fmt:
	@unformatted=$$(gofmt -l ./cmd ./internal); \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt clean:"; echo "$$unformatted"; exit 1; \
	fi; \
	echo "gofmt clean"

## check: fmt, vet, and the full test suite under the race detector
check: fmt vet test-race

## release: cross-compile one self-contained executable per target
#
# CGO_ENABLED is 0 here, and that is a deliberate, temporary state rather than an oversight. The
# design reaches Bluetooth through a per-OS native shim over cgo, and once that shim is linked in
# (Option A) these builds need CGO_ENABLED=1 plus a cross toolchain per target. Until then the Go
# side talks to the shim as a helper process (Option B), nothing in the tree needs cgo, and building
# with it off is what keeps every target reproducible from one machine and the binary statically
# linked. Flipping this to 1 is part of landing the linked shim, not a separate decision.
release: clean
	@mkdir -p $(DIST)
	@for target in $(TARGETS); do \
		os=$${target%%/*}; arch=$${target##*/}; \
		out=$(DIST)/$(BINARY)-$$os-$$arch; \
		if [ "$$os" = "windows" ]; then out=$$out.exe; fi; \
		printf 'building %s/%s ... ' "$$os" "$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $$out $(CMD) || exit 1; \
		size=$$(wc -c < $$out); \
		echo "$$(($$size / 1024 / 1024)) MiB"; \
		if [ $$size -gt 52428800 ]; then \
			echo "  FAIL: $$out is $$size bytes, over the 50 MiB ceiling of Req 12.7"; \
			exit 1; \
		fi; \
	done
	@echo
	@echo "artifacts in $(DIST):"
	@ls -lh $(DIST)

## smoke: check a freshly built host binary reaches a ready state and writes an owner-only key
#
# This is the automatable part of Req 12.1 and 12.7. The rest of Req 12.1 - an empty container with
# no runtime installed - needs a container per operating system and is a release procedure rather
# than a make target.
smoke: build
	@set -e; \
	dir=$$(mktemp -d); \
	trap 'rm -rf "$$dir"' EXIT; \
	start=$$(date +%s); \
	./$(BINARY) --state-dir "$$dir" status >/dev/null; \
	end=$$(date +%s); \
	elapsed=$$((end - start)); \
	echo "reached a ready state in $${elapsed}s (Req 12.1 allows 5)"; \
	if [ $$elapsed -gt 5 ]; then echo "  FAIL: startup took $${elapsed}s"; exit 1; fi; \
	if [ ! -f "$$dir/identity.key" ]; then echo "  FAIL: no identity.key was created"; exit 1; fi; \
	mode=$$(ls -l "$$dir/identity.key" | cut -c1-10); \
	echo "identity.key permissions: $$mode (Req 9.1 wants owner-only)"; \
	case "$$mode" in -rw-------*) ;; *) echo "  FAIL: identity.key is $$mode"; exit 1 ;; esac; \
	size=$$(wc -c < ./$(BINARY)); \
	echo "host binary: $$(($$size / 1024 / 1024)) MiB (Req 12.7 allows 50)"; \
	./$(BINARY) --help >/dev/null; \
	echo "smoke checks passed"

## clean: remove build artifacts
clean:
	rm -rf $(DIST) $(BINARY)

## help: list the targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
