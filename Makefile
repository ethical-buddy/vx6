.PHONY: build clean install test bench ebpf

VERSION ?= 1.0.0
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
GO ?= go
GOCACHE ?= /tmp/vx6-go-build
GOMODCACHE ?= /tmp/vx6-go-mod
VX6_BIN ?= vx6
EBPF_SRC := internal/ebpf/onion_relay.c
EBPF_OBJ := internal/onion/onion_relay.o

build:
	mkdir -p "$(GOCACHE)" "$(GOMODCACHE)"
	GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)" $(GO) build -ldflags "-X main.Version=$(VERSION)" -o "$(VX6_BIN)" ./cmd/vx6

ebpf:
	clang -O2 -target bpf -c "$(EBPF_SRC)" -o "$(EBPF_OBJ)"

clean:
	rm -f "$(VX6_BIN)"

install: build
	install -Dm755 "$(VX6_BIN)" "$(DESTDIR)$(BINDIR)/vx6"
	install -Dm644 deployments/systemd/vx6.service "$(DESTDIR)$(PREFIX)/lib/systemd/user/vx6.service"

test:
	mkdir -p "$(GOCACHE)" "$(GOMODCACHE)"
	GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)" $(GO) test ./...

bench:
	mkdir -p "$(GOCACHE)" "$(GOMODCACHE)"
	GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)" $(GO) test ./internal/dht ./internal/identity ./internal/onion ./internal/secure -run '^$$' -bench . -benchmem
