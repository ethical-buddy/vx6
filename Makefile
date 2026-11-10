.PHONY: build clean install package-linux test bench ebpf

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
	install -Dm755 deployments/linux/vx6-setup "$(DESTDIR)$(BINDIR)/vx6-setup"
	install -Dm644 LICENSE-COMMERCIAL.md "$(DESTDIR)$(PREFIX)/share/licenses/vx6/LICENSE-COMMERCIAL.md"
	install -Dm644 deployments/systemd/vx6.service "$(DESTDIR)$(PREFIX)/lib/systemd/user/vx6.service"
	install -Dm644 deployments/systemd/vx6-ipsecd.service "$(DESTDIR)$(PREFIX)/lib/systemd/system/vx6-ipsecd.service"
	install -Dm644 deployments/systemd/ipsecd.json.example "$(DESTDIR)/etc/vx6/ipsecd.json.example"

package-linux:
	mkdir -p dist/linux
	GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)" $(GO) build -ldflags "-X main.Version=$(VERSION)" -o dist/linux/vx6 ./cmd/vx6
	GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)" $(GO) build -o dist/linux/vx6-ipsecd ./cmd/vx6-ipsecd
	install -m755 deployments/linux/vx6-setup dist/linux/vx6-setup
	install -m755 deployments/linux/install.sh dist/linux/install.sh
	install -m644 deployments/systemd/vx6.service dist/linux/vx6.service
	install -m644 deployments/systemd/vx6-ipsecd.service dist/linux/vx6-ipsecd.service
	install -m644 deployments/systemd/ipsecd.json.example dist/linux/ipsecd.json.example
	install -m644 LICENSE-COMMERCIAL.md dist/linux/LICENSE-COMMERCIAL.md
	tar -czf dist/vx6-linux-amd64.tar.gz -C dist/linux \
		vx6 vx6-ipsecd vx6-setup install.sh vx6.service vx6-ipsecd.service \
		ipsecd.json.example LICENSE-COMMERCIAL.md

test:
	mkdir -p "$(GOCACHE)" "$(GOMODCACHE)"
	GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)" $(GO) test ./...

bench:
	mkdir -p "$(GOCACHE)" "$(GOMODCACHE)"
	GOCACHE="$(GOCACHE)" GOMODCACHE="$(GOMODCACHE)" $(GO) test ./internal/dht ./internal/identity ./internal/onion ./internal/secure -run '^$$' -bench . -benchmem
