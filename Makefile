.PHONY: build clean install test bench ebpf

VERSION ?= 1.0.0
PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
GO ?= go
GOCACHE ?= /tmp/vx6-go-build
GOMODCACHE ?= /tmp/vx6-go-mod
VX6_BIN ?= vx6
IPSECD_BIN ?= vx6-ipsecd
EBPF_SRC := internal/ebpf/onion_relay.c
EBPF_OBJ := internal/onion/onion_relay.o

build:
	mkdir -p "$(GOCACHE)" "$(GOMODCACHE)"
	GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)" $(GO) build -ldflags "-X main.Version=$(VERSION)" -o "$(VX6_BIN)" ./cmd/vx6
	GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)" $(GO) build -o "$(IPSECD_BIN)" ./cmd/vx6-ipsecd

ebpf:
	clang -O2 -target bpf -c "$(EBPF_SRC)" -o "$(EBPF_OBJ)"

clean:
	rm -f "$(VX6_BIN)" "$(IPSECD_BIN)"

install: build
	install -Dm755 "$(VX6_BIN)" "$(DESTDIR)$(BINDIR)/vx6"
	install -Dm755 "$(IPSECD_BIN)" "$(DESTDIR)$(BINDIR)/vx6-ipsecd"
	install -Dm644 deployments/systemd/vx6.service "$(DESTDIR)$(PREFIX)/lib/systemd/user/vx6.service"
	install -Dm644 deployments/systemd/vx6-ipsecd.service "$(DESTDIR)$(PREFIX)/lib/systemd/system/vx6-ipsecd.service"
	install -Dm644 deployments/systemd/ipsecd.json.example "$(DESTDIR)/etc/vx6/ipsecd.json.example"

test:
	mkdir -p "$(GOCACHE)" "$(GOMODCACHE)"
	GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)" $(GO) test ./...

bench:
	mkdir -p "$(GOCACHE)" "$(GOMODCACHE)"
	GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)" $(GO) test ./internal/dht ./internal/identity ./internal/onion ./internal/secure -run '^$$' -bench . -benchmem
