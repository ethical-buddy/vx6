package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/vx6/vx6/internal/config"
	"github.com/vx6/vx6/internal/dht"
	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/hidden"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/ipsec"
	"github.com/vx6/vx6/internal/netutil"
	"github.com/vx6/vx6/internal/node"
	"github.com/vx6/vx6/internal/onion"
	"github.com/vx6/vx6/internal/proto"
	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/runtimectl"
	"github.com/vx6/vx6/internal/serviceproxy"
	"github.com/vx6/vx6/internal/transfer"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

type stringListFlag []string

func (s *stringListFlag) String() string { return fmt.Sprint([]string(*s)) }

func (s *stringListFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return errors.New("missing command")
	}

	switch args[0] {
	case "init":
		return runInit(ctx, args[1:])
	case "list":
		return runList(ctx, args[1:])
	case "send":
		return runSend(ctx, args[1:])
	case "receive":
		return runReceive(args[1:])
	case "connect":
		return runConnect(ctx, args[1:])
	case "status":
		return runStatus(ctx, args[1:])
	case "node":
		return runNode(ctx, args[1:])
	case "reload":
		return runReload(args[1:])
	case "peer":
		return runPeer(args[1:])
	case "service":
		return runService(args[1:])
	case "identity":
		return runIdentity(ctx, args[1:])
	case "debug":
		return runDebug(ctx, args[1:])
	case "-h", "--help", "help":
		printUsage(os.Stdout)
		return nil
	default:
		printUsage(os.Stderr)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "VX6")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "IPv6-first overlay transport with signed discovery, encrypted sessions, direct service sharing,")
	fmt.Fprintln(w, "DHT-backed metadata lookup, and optional 5-hop proxy forwarding.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  vx6 init --name NAME [--listen [::]:4242] [--advertise [ipv6]:port] [--transport auto|tcp] [--relay on|off] [--relay-percent N] [--peer [ipv6]:port] [--hidden-node] [--setup-firewall] [--data-dir DIR] [--downloads-dir DIR]")
	fmt.Fprintln(w, "  vx6 node")
	fmt.Fprintln(w, "  vx6 reload")
	fmt.Fprintln(w, "  vx6 service add --name NAME --target 127.0.0.1:22 [--private] [--hidden --alias NAME --profile fast|balanced --intro-mode random|manual|hybrid --intro NODE]")
	fmt.Fprintln(w, "  vx6 service remove --name NAME")
	fmt.Fprintln(w, "  vx6 connect --service NAME [--listen 127.0.0.1:2222] [--proxy] [--addr [ipv6]:port]")
	fmt.Fprintln(w, "  vx6 send --file PATH (--to PEER | --addr [ipv6]:port) [--proxy]")
	fmt.Fprintln(w, "  vx6 receive status")
	fmt.Fprintln(w, "  vx6 receive allow --all | --node NAME")
	fmt.Fprintln(w, "  vx6 receive deny --node NAME")
	fmt.Fprintln(w, "  vx6 receive disable")
	fmt.Fprintln(w, "  vx6 service")
	fmt.Fprintln(w, "  vx6 peer")
	fmt.Fprintln(w, "  vx6 list [--user USER] [--hidden]")
	fmt.Fprintln(w, "  vx6 peer add --record ENDPOINT.json")
	fmt.Fprintln(w, "  vx6 peer add --addr [ipv6]:port [--name NAME] (address only; IPsec requires a signed record)")
	fmt.Fprintln(w, "  vx6 peer revoke --node-id ID (local, persistent deny)")
	fmt.Fprintln(w, "  vx6 identity")
	fmt.Fprintln(w, "  vx6 identity rename --name NAME")
	fmt.Fprintln(w, "  vx6 identity export-endpoint --addr [ipv6]:port --out FILE [--ttl 24h]")
	fmt.Fprintln(w, "  vx6 status")
	fmt.Fprintln(w, "  vx6 debug registry")
	fmt.Fprintln(w, "  vx6 debug dht-get (--service NODE.SERVICE | --node NAME | --node-id ID | --key KEY)")
	fmt.Fprintln(w, "  vx6 debug dht-status")
	fmt.Fprintln(w, "  vx6 debug ebpf-status            (Linux only)")
	fmt.Fprintln(w, "  vx6 debug ebpf-attach --iface IFACE   (Linux only)")
	fmt.Fprintln(w, "  vx6 debug ebpf-detach --iface IFACE   (Linux only)")
	fmt.Fprintln(w, "  vx6-gui")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Working features:")
	fmt.Fprintln(w, "  - Signed endpoint and service discovery via peer-to-peer registry sync")
	fmt.Fprintln(w, "  - DHT-backed endpoint/service key lookup")
	fmt.Fprintln(w, "  - Encrypted file transfer with local receive permissions")
	fmt.Fprintln(w, "  - Direct TCP service sharing")
	fmt.Fprintln(w, "  - 5-hop proxy forwarding for direct services and files")
	fmt.Fprintln(w, "  - Plain-TCP hidden services via 3 active intros, 2 standby intros, guards, and rendezvous relay")
	fmt.Fprintln(w, "  - Direct IPv6 service sharing without peer sync using --addr")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Experimental / not complete:")
	fmt.Fprintln(w, "  - eBPF loader and attach path (embedded bytecode is present and tested)")
	fmt.Fprintln(w, "  - QUIC transport is not active in this build; all network traffic uses TCP")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Examples:")
	fmt.Fprintln(w, "  vx6 init --name alice --listen '[::]:4242' --peer '[::1]:4242'")
	fmt.Fprintln(w, "  vx6 reload")
	fmt.Fprintln(w, "  vx6 identity rename --name ally")
	fmt.Fprintln(w, "  vx6 init --name ghost --advertise '[2001:db8::10]:4242' --hidden-node")
	fmt.Fprintln(w, "  vx6 service add --name ssh --target 127.0.0.1:22")
	fmt.Fprintln(w, "  vx6 service add --name admin --target 127.0.0.1:22 --hidden --alias hs-admin --intro-mode random")
	fmt.Fprintln(w, "  vx6 service remove --name ssh")
	fmt.Fprintln(w, "  vx6 connect --service alice.ssh --listen 127.0.0.1:2222")
	fmt.Fprintln(w, "  vx6 connect --service ssh --addr '[2001:db8::10]:4242' --listen 127.0.0.1:2222")
	fmt.Fprintln(w, "  vx6 connect --service alice.ssh --listen 127.0.0.1:2222 --proxy")
	fmt.Fprintln(w, "  vx6 debug dht-get --service alice.ssh")
	fmt.Fprintln(w, "  vx6 debug dht-get --service hs-admin")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Storage:")
	for _, line := range defaultStorageLines() {
		fmt.Fprintln(w, line)
	}
}

func prompt(label string) string {
	fmt.Printf("%s: ", label)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}

func runInit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	name := fs.String("name", "", "local human-readable node name")
	listenAddr := fs.String("listen", "[::]:4242", "default IPv6 listen address in [addr]:port form")
	advertiseAddr := fs.String("advertise", "", "public IPv6 address in [addr]:port form for discovery records")
	transportMode := fs.String("transport", vxtransport.ModeAuto, "neighbor transport mode: auto or tcp (quic is reserved for a future transport)")
	hiddenNode := fs.Bool("hidden-node", false, "do not publish the node endpoint record; publish services only")
	relayMode := fs.String("relay", config.RelayModeOn, "relay participation: on or off")
	relayPercent := fs.Int("relay-percent", 33, "maximum share of local relay capacity reserved for transit work")
	dataDir := fs.String("data-dir", defaultDataDirValue(), "directory for VX6 runtime state")
	downloadDir := fs.String("downloads-dir", defaultDownloadDirValue(), "directory for received files")
	setupFirewall := fs.Bool("setup-firewall", false, "create firewall exceptions for the listen port (Windows: requires admin privileges)")
	var peers stringListFlag
	fs.Var(&peers, "peer", "known peer IPv6 address in [addr]:port form; repeatable")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" && len(fs.Args()) > 0 {
		*name = fs.Args()[0]
	}
	if *name == "" {
		*name = prompt("Enter node name")
	}
	if *name == "" {
		return errors.New("init requires --name")
	}
	if err := record.ValidateNodeName(*name); err != nil {
		return err
	}
	if err := transfer.ValidateIPv6Address(*listenAddr); err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	if *advertiseAddr != "" {
		if err := transfer.ValidateIPv6Address(*advertiseAddr); err != nil {
			return fmt.Errorf("invalid advertise address: %w", err)
		}
	}
	normalizedTransport := vxtransport.NormalizeMode(*transportMode)
	if normalizedTransport == "" {
		return fmt.Errorf("invalid transport mode %q", *transportMode)
	}
	normalizedRelayMode := config.NormalizeRelayMode(*relayMode)
	if normalizedRelayMode == "" {
		return fmt.Errorf("invalid relay mode %q", *relayMode)
	}
	for _, addr := range peers {
		if err := transfer.ValidateIPv6Address(addr); err != nil {
			return fmt.Errorf("invalid peer address %q: %w", addr, err)
		}
	}

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}
	cfg.Node.Name = *name
	cfg.Node.ListenAddr = *listenAddr
	cfg.Node.AdvertiseAddr = *advertiseAddr
	cfg.Node.TransportMode = normalizedTransport
	cfg.Node.HideEndpoint = *hiddenNode
	cfg.Node.RelayMode = normalizedRelayMode
	cfg.Node.RelayResourcePercent = config.NormalizeRelayResourcePercent(*relayPercent)
	cfg.Node.DataDir = *dataDir
	cfg.Node.DownloadDir = *downloadDir
	cfg.Node.FileReceiveMode = config.NormalizeFileReceiveMode(cfg.Node.FileReceiveMode)
	if len(peers) > 0 {
		cfg.Node.KnownPeers = nil
		cfg.Node.KnownPeerAddrs = append([]string(nil), peers...)
		cfg.Node.Bootstraps = nil
		cfg.Node.BootstrapAddrs = nil
	}

	idStore, err := identity.NewStoreForConfig(store.Path())
	if err != nil {
		return err
	}
	id, _, err := idStore.Ensure()
	if err != nil {
		return err
	}
	if err := waitForNodeNameAvailability(ctx, cfg, *name, id.NodeID, time.Minute); err != nil {
		return err
	}
	if err := store.Save(cfg); err != nil {
		return err
	}
	fmt.Printf("node_initialized\t%s\t%s\n", *name, id.NodeID)
	fmt.Printf("config_path\t%s\n", store.Path())
	fmt.Printf("identity_path\t%s\n", idStore.Path())

	// Setup firewall exceptions if requested
	if *setupFirewall {
		port, err := ExtractPortFromAddress(*listenAddr)
		if err != nil {
			return fmt.Errorf("extract port for firewall setup: %w", err)
		}
		if err := SetupFirewallException(port, "Both"); err != nil {
			fmt.Printf("firewall_setup\tport=%d\tstatus=failed\terror=%v\n", port, err)
		} else {
			fmt.Printf("firewall_setup\tport=%d\tprotocol=tcp,udp\tstatus=success\n", port)
		}
	}

	return nil
}

func runList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "", "path to the VX6 config file")
	userFilter := fs.String("user", "", "show direct services for a single user")
	hiddenOnly := fs.Bool("hidden", false, "show hidden aliases from the local registry")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := config.NewStore(*configPath)
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}
	names, _, err := store.ListPeers()
	if err != nil {
		return err
	}
	printSectionHeader("PEERS", len(names))
	for _, n := range names {
		fmt.Printf("  %-15s configured\n", n)
	}
	if len(names) == 0 {
		fmt.Println("  (none)")
	}

	serviceNames, localServices, err := store.ListServices()
	if err != nil {
		return err
	}
	localPublicCount := 0
	localHiddenCount := 0
	localPrivateCount := 0
	for _, name := range serviceNames {
		if localServices[name].IsHidden {
			localHiddenCount++
		} else if localServices[name].IsPrivate {
			localPrivateCount++
		} else {
			localPublicCount++
		}
	}
	if !*hiddenOnly {
		printSectionHeader("LOCAL PUBLIC SERVICES", localPublicCount)
		printed := 0
		for _, name := range serviceNames {
			svc := localServices[name]
			if svc.IsHidden {
				continue
			}
			fmt.Printf("  %-15s target=%s\n", name, svc.Target)
			printed++
		}
		if printed == 0 {
			fmt.Println("  (none)")
		}
	}

	printSectionHeader("LOCAL HIDDEN SERVICES", localHiddenCount)
	printedHidden := 0
	for _, name := range serviceNames {
		svc := localServices[name]
		if !svc.IsHidden {
			continue
		}
		label := svc.Alias
		if label == "" {
			label = name
		}
		fmt.Printf("  %-15s alias=%s profile=%s\n", name, label, record.NormalizeHiddenProfile(svc.HiddenProfile))
		printedHidden++
	}
	if printedHidden == 0 {
		fmt.Println("  (none)")
	}
	if !*hiddenOnly {
		printSectionHeader("LOCAL PRIVATE SERVICES", localPrivateCount)
		printedPrivate := 0
		for _, name := range serviceNames {
			svc := localServices[name]
			if !svc.IsPrivate || svc.IsHidden {
				continue
			}
			fmt.Printf("  %-15s target=%s\n", name, svc.Target)
			printedPrivate++
		}
		if printedPrivate == 0 {
			fmt.Println("  (none)")
		}
	}

	reg, err := loadLocalRegistry(cfg.Node.DataDir)
	if err != nil {
		return err
	}
	recs, svcs := reg.Snapshot()
	printSectionHeader("DISCOVERED NODES", len(recs))
	for _, r := range recs {
		fmt.Printf("  %-15s discovered\n", r.NodeName)
	}
	if len(recs) == 0 {
		fmt.Println("  (none)")
	}

	publicPrinted := 0
	hiddenPrinted := 0
	privateServices := []record.ServiceRecord(nil)
	if *userFilter != "" && !*hiddenOnly {
		privateServices, _ = lookupPrivateServicesForUser(ctx, cfg, *userFilter)
	}
	if !*hiddenOnly {
		for _, s := range svcs {
			if s.IsHidden || s.IsPrivate {
				continue
			}
			if *userFilter != "" && s.NodeName != *userFilter {
				continue
			}
			publicPrinted++
		}
		printSectionHeader("DISCOVERED PUBLIC SERVICES", publicPrinted)
		for _, s := range svcs {
			if s.IsHidden || s.IsPrivate {
				continue
			}
			if *userFilter != "" && s.NodeName != *userFilter {
				continue
			}
			fmt.Printf("  %-15s node=%s\n", record.FullServiceName(s.NodeName, s.ServiceName), s.NodeName)
		}
		if publicPrinted == 0 {
			fmt.Println("  (none)")
		}
		if *userFilter != "" {
			printSectionHeader("DISCOVERED PRIVATE SERVICES", len(privateServices))
			for _, s := range privateServices {
				fmt.Printf("  %-15s node=%s\n", record.FullServiceName(s.NodeName, s.ServiceName), s.NodeName)
			}
			if len(privateServices) == 0 {
				fmt.Println("  (none)")
			}
		}
	}

	for _, s := range svcs {
		if !s.IsHidden {
			continue
		}
		hiddenPrinted++
	}
	printSectionHeader("DISCOVERED HIDDEN ALIASES", hiddenPrinted)
	for _, s := range svcs {
		if !s.IsHidden {
			continue
		}
		fmt.Printf("  %-15s profile=%s\n", record.ServiceLookupKey(s), record.NormalizeHiddenProfile(s.HiddenProfile))
	}
	if hiddenPrinted == 0 {
		fmt.Println("  (none)")
	}
	return nil
}

func printSectionHeader(title string, count int) {
	fmt.Printf("\n== %s (%d) ==\n", title, count)
}

func runNode(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("node", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	nodeName := fs.String("name", "", "local human-readable node name")
	listenAddr := fs.String("listen", "", "IPv6 listen address in [addr]:port form")
	dataDir := fs.String("data-dir", "", "directory for VX6 runtime state")
	downloadDir := fs.String("downloads-dir", "", "directory for received files")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfgFile, err := store.Load()
	if err != nil {
		return err
	}
	idStore, err := identity.NewStoreForConfig(store.Path())
	if err != nil {
		return err
	}
	id, err := idStore.Load()
	if err != nil {
		return err
	}
	if *nodeName == "" {
		*nodeName = cfgFile.Node.Name
	}
	if *listenAddr == "" {
		*listenAddr = cfgFile.Node.ListenAddr
	}
	if *dataDir == "" {
		*dataDir = cfgFile.Node.DataDir
	}
	if *downloadDir == "" {
		*downloadDir = cfgFile.Node.DownloadDir
	}
	lock, err := acquireNodeLock(store.Path())
	if err != nil {
		return err
	}
	defer lock.Close()

	reloadCh := make(chan struct{}, 1)
	sigCh := make(chan os.Signal, 1)
	registerReloadSignal(sigCh)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigCh:
				select {
				case reloadCh <- struct{}{}:
				default:
				}
			}
		}
	}()

	services := make(map[string]string, len(cfgFile.Services))
	for name, svc := range cfgFile.Services {
		services[name] = svc.Target
	}
	registry, err := discovery.NewRegistry(filepath.Join(*dataDir, "registry.json"))
	if err != nil {
		return err
	}
	bootstrapRecords := make([]record.EndpointRecord, 0, len(cfgFile.Node.KnownPeers))
	for _, peer := range cfgFile.Node.KnownPeers {
		rec := record.EndpointRecord{
			NodeID: peer.NodeID, NodeName: peer.NodeName, Address: peer.Address,
			PublicKey: peer.PublicKey, IssuedAt: peer.IdentityIssuedAt,
			ExpiresAt: peer.IdentityExpiresAt, Signature: peer.IdentitySignature,
		}
		if record.VerifyEndpointRecord(rec, time.Now()) == nil {
			bootstrapRecords = append(bootstrapRecords, rec)
		}
	}
	if err := registry.Import(bootstrapRecords, nil); err != nil {
		return fmt.Errorf("load signed bootstrap identities: %w", err)
	}
	controlInfoPath, err := config.RuntimeControlPath(store.Path())
	if err != nil {
		return err
	}

	cfg := node.Config{
		Name:                 *nodeName,
		NodeID:               id.NodeID,
		ListenAddr:           *listenAddr,
		AdvertiseAddr:        cfgFile.Node.AdvertiseAddr,
		AdvertiseExplicit:    cfgFile.Node.AdvertiseAddr != "",
		TransportMode:        cfgFile.Node.TransportMode,
		HideEndpoint:         cfgFile.Node.HideEndpoint,
		RelayMode:            cfgFile.Node.RelayMode,
		RelayResourcePercent: cfgFile.Node.RelayResourcePercent,
		DataDir:              *dataDir,
		ReceiveDir:           *downloadDir,
		ConfigPath:           store.Path(),
		ControlInfoPath:      controlInfoPath,
		Identity:             id,
		FileReceiveMode:      cfgFile.Node.FileReceiveMode,
		AllowedFileSenders:   append([]string(nil), cfgFile.Node.AllowedFileSenders...),
		DHT:                  dht.NewServerWithIdentity(id),
		PeerAddrs:            config.ConfiguredPeerAddresses(cfgFile),
		Services:             services,
		Registry:             registry,
		Reload:               reloadCh,
		RefreshServices: func() map[string]string {
			c, err := store.Load()
			if err != nil {
				return nil
			}
			m := make(map[string]string, len(c.Services))
			for k, v := range c.Services {
				m[k] = v.Target
			}
			return m
		},
	}
	return node.Run(ctx, os.Stdout, cfg)
}

func runReload(args []string) error {
	fs := flag.NewFlagSet("reload", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	controlPath, err := config.RuntimeControlPath(store.Path())
	if err != nil {
		return err
	}
	if err := runtimectl.RequestReload(context.Background(), controlPath); err == nil {
		fmt.Println("reload_sent\tmode=control")
		return nil
	}

	pidPath, err := config.RuntimePIDPath(store.Path())
	if err != nil {
		return err
	}
	pid, err := readNodePID(pidPath)
	if err != nil {
		return fmt.Errorf("read node pid file: %w", err)
	}
	if err := processExists(pid); err != nil {
		return fmt.Errorf("check node process: %w", err)
	}
	if err := sendReloadSignal(pid); err != nil {
		return fmt.Errorf("signal node reload: %w", err)
	}
	fmt.Printf("reload_sent\tmode=signal\tpid=%d\n", pid)
	return nil
}

func runConnect(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	svc := fs.String("service", "", "service")
	localListen := fs.String("listen", "127.0.0.1:2222", "local TCP listener address")
	addrFlag := fs.String("addr", "", "direct VX6 node IPv6 address")
	proxy := fs.Bool("proxy", false, "force proxy")
	finalSvc, parseArgs := extractLeadingConnectService(args)
	if err := fs.Parse(parseArgs); err != nil {
		return err
	}
	if *svc != "" {
		finalSvc = *svc
	}
	if finalSvc == "" && len(fs.Args()) > 0 {
		finalSvc = fs.Args()[0]
	}
	if finalSvc == "" {
		finalSvc = prompt("Enter service name")
	}

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}
	_, _ = dht.ConfigureASNResolver(store.Path())
	idStore, err := identity.NewStoreForConfig(store.Path())
	if err != nil {
		return err
	}
	id, err := idStore.Load()
	if err != nil {
		return err
	}
	registry, err := loadLocalRegistry(cfg.Node.DataDir)
	if err != nil {
		return err
	}
	if err := importConfiguredKnownPeers(cfg, registry); err != nil {
		return err
	}
	_, guard, err := newIPsecDialGuard(cfg, id, registry, nil)
	if err != nil {
		return err
	}
	ctx = vxtransport.WithDialGuard(ctx, guard)

	requestServiceName := requestedServiceName(finalSvc)
	serviceRec := record.ServiceRecord{}
	if *addrFlag != "" {
		if err := transfer.ValidateIPv6Address(*addrFlag); err != nil {
			return err
		}
		serviceRec = record.ServiceRecord{
			NodeName:    "direct",
			ServiceName: requestServiceName,
			Address:     *addrFlag,
		}
	} else {
		var err error
		serviceRec, err = resolveServiceDistributed(ctx, cfg, finalSvc)
		if err != nil {
			return fmt.Errorf("service %q not found. try running 'vx6 list --user NAME' or 'vx6 list --hidden' to verify", finalSvc)
		}
	}
	if !serviceRec.IsHidden && *addrFlag == "" {
		peer, err := resolveNodeDistributed(ctx, cfg, serviceRec.NodeName)
		if err != nil {
			return fmt.Errorf("resolve signed peer identity for service %s: %w", finalSvc, err)
		}
		if peer.NodeID != serviceRec.NodeID || peer.Address != serviceRec.Address || peer.PublicKey != serviceRec.PublicKey {
			return fmt.Errorf("service record does not match its signed node endpoint")
		}
		if err := registry.Import([]record.EndpointRecord{peer}, nil); err != nil {
			return fmt.Errorf("cache verified peer identity: %w", err)
		}
	}

	dialer := func(rctx context.Context) (net.Conn, error) {
		if serviceRec.IsHidden {
			reg, err := loadLocalRegistry(cfg.Node.DataDir)
			if err != nil {
				return nil, err
			}
			conn, err := hidden.DialHiddenServiceWithOptions(rctx, serviceRec, reg, hidden.DialOptions{
				SelfAddr:      cfg.Node.AdvertiseAddr,
				Identity:      id,
				TransportMode: cfg.Node.TransportMode,
			})
			if err != nil {
				return nil, friendlyRelayPathError(err, "hidden-service mode")
			}
			return conn, nil
		}
		if *proxy {
			fmt.Printf("[CIRCUIT] Building 5-hop circuit to %s\n", finalSvc)
			reg, err := loadLocalRegistry(cfg.Node.DataDir)
			if err != nil {
				return nil, err
			}
			peers, _ := reg.Snapshot()
			conn, err := onion.BuildAutomatedCircuit(rctx, serviceRec, peers, onion.ClientOptions{
				Identity:      id,
				TransportMode: cfg.Node.TransportMode,
			})
			if err != nil {
				return nil, friendlyRelayPathError(err, "proxy mode")
			}
			return conn, nil
		}
		return vxtransport.DialContext(rctx, cfg.Node.TransportMode, serviceRec.Address)
	}
	fmt.Printf("tunnel_active\t%s\t%s\n", *localListen, finalSvc)
	return serviceproxy.ServeLocalForward(ctx, *localListen, serviceRec, id, dialer)
}

func extractLeadingConnectService(args []string) (string, []string) {
	if len(args) == 0 {
		return "", args
	}
	if strings.HasPrefix(args[0], "-") {
		return "", args
	}
	return args[0], args[1:]
}

func runService(args []string) error {
	if len(args) >= 1 && args[0] == "add" {
		fs := flag.NewFlagSet("service add", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		name := fs.String("name", "", "local service name")
		target := fs.String("target", "", "local TCP target")
		private := fs.Bool("private", false, "publish only through per-user private catalog")
		h := fs.Bool("hidden", false, "hidden")
		alias := fs.String("alias", "", "hidden alias; defaults to the local service name")
		profile := fs.String("profile", "fast", "hidden routing profile: fast or balanced")
		introMode := fs.String("intro-mode", "", "hidden intro selection mode: random, manual, or hybrid")
		var intros stringListFlag
		fs.Var(&intros, "intro", "preferred intro node name or IPv6 address; repeatable")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" {
			*name = prompt("Service Name")
		}
		if *target == "" {
			*target = prompt("Target (e.g. :8000)")
		}
		store, err := config.NewStore("")
		if err != nil {
			return err
		}
		entry := config.ServiceEntry{
			Target:        *target,
			IsPrivate:     *private,
			IsHidden:      *h,
			Alias:         *alias,
			HiddenProfile: record.NormalizeHiddenProfile(*profile),
			IntroMode:     "",
			IntroNodes:    append([]string(nil), intros...),
		}
		if entry.IsPrivate && entry.IsHidden {
			return errors.New("service cannot be both hidden and private")
		}
		if entry.IsHidden {
			if entry.Alias == "" {
				entry.Alias = *name
			}
			if entry.HiddenLookupSecret == "" {
				secret, err := dht.NewHiddenLookupSecret()
				if err != nil {
					return err
				}
				entry.HiddenLookupSecret = secret
			}
			if entry.HiddenProfile == "" {
				return fmt.Errorf("invalid hidden profile %q", *profile)
			}
			if *introMode != "" {
				entry.IntroMode = hidden.NormalizeIntroMode(*introMode)
				if entry.IntroMode == "" {
					return fmt.Errorf("invalid intro mode %q", *introMode)
				}
			}
			if entry.IntroMode == "" {
				if len(entry.IntroNodes) > 0 {
					entry.IntroMode = hidden.IntroModeManual
				} else {
					entry.IntroMode = hidden.IntroModeRandom
				}
			}
		} else {
			entry.IntroMode = ""
			entry.HiddenProfile = ""
			entry.Alias = ""
		}
		if err := store.SetService(*name, entry); err != nil {
			return err
		}
		if entry.IsHidden {
			fmt.Printf("hidden_alias\t%s\nhidden_invite\t%s\nhidden_profile\t%s\nintro_mode\t%s\n", entry.Alias, dht.ComposeHiddenLookupInvite(entry.Alias, entry.HiddenLookupSecret), entry.HiddenProfile, entry.IntroMode)
		} else if entry.IsPrivate {
			fmt.Println("visibility\tPRIVATE")
		}
		return nil
	}
	if len(args) >= 1 && args[0] == "remove" {
		fs := flag.NewFlagSet("service remove", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		name := fs.String("name", "", "local service name")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" {
			*name = prompt("Service Name")
		}
		if *name == "" {
			return errors.New("service remove requires --name")
		}
		store, err := config.NewStore("")
		if err != nil {
			return err
		}
		if err := store.RemoveService(*name); err != nil {
			return err
		}
		fmt.Printf("service_removed\t%s\n", *name)
		return nil
	}
	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	c, err := store.Load()
	if err != nil {
		return err
	}
	for n, s := range c.Services {
		mode := "DIRECT"
		label := n
		if s.IsHidden {
			mode = "HIDDEN"
			if s.Alias != "" {
				label = s.Alias
			}
		} else if s.IsPrivate {
			mode = "PRIVATE"
		}
		fmt.Printf("%s\t%s\t%s\n", label, s.Target, mode)
	}
	return nil
}

func runPeer(args []string) error {
	if len(args) > 0 && args[0] == "revoke" {
		fs := flag.NewFlagSet("peer revoke", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		nodeID := fs.String("node-id", "", "verified peer node ID to revoke locally")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *nodeID == "" {
			return errors.New("peer revoke requires --node-id")
		}
		store, err := config.NewStore("")
		if err != nil {
			return err
		}
		cfg, err := store.Load()
		if err != nil {
			return err
		}
		var peer record.EndpointRecord
		for _, entry := range cfg.Node.KnownPeers {
			if entry.NodeID == *nodeID {
				peer = record.EndpointRecord{NodeID: entry.NodeID, NodeName: entry.NodeName, Address: entry.Address, PublicKey: entry.PublicKey, IssuedAt: entry.IdentityIssuedAt, ExpiresAt: entry.IdentityExpiresAt, Signature: entry.IdentitySignature}
				break
			}
		}
		if peer.NodeID == "" {
			return fmt.Errorf("no signed endpoint record for peer %q in the local peer directory", *nodeID)
		}
		if err := record.VerifyEndpointRecord(peer, time.Now()); err != nil {
			return fmt.Errorf("cannot revoke peer without a current verified endpoint record: %w", err)
		}
		idStore, err := identity.NewStoreForConfig(store.Path())
		if err != nil {
			return err
		}
		id, err := idStore.Load()
		if err != nil {
			return err
		}
		localAddress := cfg.Node.AdvertiseAddr
		if localAddress == "" {
			_, port, err := net.SplitHostPort(cfg.Node.ListenAddr)
			if err != nil {
				return fmt.Errorf("invalid configured listener address: %w", err)
			}
			localAddress, err = netutil.DetectAdvertiseAddress(port)
			if err != nil {
				return err
			}
		}
		client, err := ipsec.NewClient(ipsec.DefaultSocket(), localAddress, id)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := client.RevokePeer(ctx, peer); err != nil {
			return err
		}
		fmt.Printf("peer_revoked_locally\t%s\n", peer.NodeID)
		return nil
	}
	if len(args) >= 1 && args[0] == "add" {
		fs := flag.NewFlagSet("peer add", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		name := fs.String("name", "", "peer name")
		addr := fs.String("addr", "", "peer address")
		recordPath := fs.String("record", "", "verified signed endpoint record JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *recordPath != "" {
			data, err := os.ReadFile(*recordPath)
			if err != nil {
				return fmt.Errorf("read endpoint record: %w", err)
			}
			var peer record.EndpointRecord
			if err := json.Unmarshal(data, &peer); err != nil {
				return fmt.Errorf("decode endpoint record: %w", err)
			}
			if err := record.VerifyEndpointRecord(peer, time.Now()); err != nil {
				return fmt.Errorf("reject endpoint record: %w", err)
			}
			if *addr != "" && *addr != peer.Address {
				return fmt.Errorf("--addr does not match the signed endpoint record")
			}
			if *name != "" && *name != peer.NodeName {
				return fmt.Errorf("--name does not match the signed endpoint record")
			}
			store, err := config.NewStore("")
			if err != nil {
				return err
			}
			if err := store.UpsertKnownPeerRecord(peer); err != nil {
				return err
			}
			cfg, err := store.Load()
			if err != nil {
				return err
			}
			registry, err := loadLocalRegistry(cfg.Node.DataDir)
			if err != nil {
				return err
			}
			if err := registry.Import([]record.EndpointRecord{peer}, nil); err != nil {
				return err
			}
			fmt.Printf("known_peer\t%s\t%s\n", peer.NodeName, peer.Address)
			return nil
		}
		if *addr == "" {
			*addr = prompt("Peer Address")
		}
		if *addr == "" {
			return errors.New("peer add requires --addr")
		}
		store, err := config.NewStore("")
		if err != nil {
			return err
		}
		if *name == "" {
			return store.AddKnownPeerAddress(*addr)
		}
		if err := record.ValidateNodeName(*name); err != nil {
			return err
		}
		return store.AddPeer(*name, *addr)
	}
	fs := flag.NewFlagSet("peer", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	names, peers, err := store.ListPeers()
	if err != nil {
		return err
	}
	knownPeers, err := store.ListKnownPeerEntries()
	if err != nil {
		return err
	}
	printSectionHeader("KNOWN PEERS", len(knownPeers))
	for _, entry := range knownPeers {
		switch {
		case entry.NodeName != "" && entry.NodeID != "":
			fmt.Printf("  %-39s %s (%s)\n", entry.Address, entry.NodeName, entry.NodeID)
		case entry.NodeName != "":
			fmt.Printf("  %-39s %s\n", entry.Address, entry.NodeName)
		case entry.NodeID != "":
			fmt.Printf("  %-39s %s\n", entry.Address, entry.NodeID)
		default:
			fmt.Printf("  %s\n", entry.Address)
		}
	}
	if len(knownPeers) == 0 {
		fmt.Println("  (none)")
	}
	printSectionHeader("PEER DIRECTORY", len(names))
	for _, n := range names {
		fmt.Printf("  %-15s %s\n", n, peerDirectoryState(peers[n].Address))
	}
	if len(names) == 0 {
		fmt.Println("  (none)")
	}
	return nil
}

func runSend(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	file := fs.String("file", "", "path to file")
	to := fs.String("to", "", "peer name")
	addrFlag := fs.String("addr", "", "peer IPv6 address")
	nodeName := fs.String("name", "", "local node name")
	proxy := fs.Bool("proxy", false, "proxy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		*file = prompt("File Path")
	}
	if *to == "" && *addrFlag == "" {
		*to = prompt("Receiver Name")
	}
	if *file == "" {
		return errors.New("send requires --file")
	}
	if *to == "" && *addrFlag == "" {
		return errors.New("send requires --to or --addr")
	}
	if *to != "" && *addrFlag != "" {
		return errors.New("send accepts only one of --to or --addr")
	}

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}
	idStore, err := identity.NewStoreForConfig(store.Path())
	if err != nil {
		return err
	}
	id, err := idStore.Load()
	if err != nil {
		return err
	}
	registry, err := loadLocalRegistry(cfg.Node.DataDir)
	if err != nil {
		return err
	}
	if err := importConfiguredKnownPeers(cfg, registry); err != nil {
		return err
	}
	_, guard, err := newIPsecDialGuard(cfg, id, registry, nil)
	if err != nil {
		return err
	}
	ctx = vxtransport.WithDialGuard(ctx, guard)
	if *nodeName == "" {
		*nodeName = cfg.Node.Name
	}
	if err := record.ValidateNodeName(*nodeName); err != nil {
		return err
	}

	addr := *addrFlag
	if addr == "" {
		addr, err = resolvePeerForSend(ctx, store, cfg, *to)
		if err != nil {
			return err
		}
	}

	dialer := func(rctx context.Context) (net.Conn, error) {
		if *proxy {
			reg, err := loadLocalRegistry(cfg.Node.DataDir)
			if err != nil {
				return nil, err
			}
			peers, _ := reg.Snapshot()
			conn, err := onion.BuildAutomatedCircuit(rctx, record.ServiceRecord{Address: addr}, peers, onion.ClientOptions{
				Identity:      id,
				TransportMode: cfg.Node.TransportMode,
			})
			if err != nil {
				return nil, friendlyRelayPathError(err, "proxy mode")
			}
			return conn, nil
		}
		return vxtransport.DialContext(rctx, cfg.Node.TransportMode, addr)
	}
	conn, err := dialer(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	res, err := transfer.SendFileWithConn(ctx, conn, transfer.SendRequest{NodeName: *nodeName, FilePath: *file, Address: addr, Identity: id})
	if err != nil {
		return err
	}
	fmt.Printf("sent\t%s\n", res.FileName)
	return nil
}

func runReceive(args []string) error {
	if len(args) == 0 {
		return runReceiveStatus(nil)
	}
	if args[0] == "status" {
		return runReceiveStatus(args[1:])
	}

	switch args[0] {
	case "allow":
		return runReceiveAllow(args[1:])
	case "deny":
		return runReceiveDeny(args[1:])
	case "disable":
		return runReceiveDisable(args[1:])
	default:
		return fmt.Errorf("unknown receive subcommand %q", args[0])
	}
}

func runReceiveStatus(args []string) error {
	fs := flag.NewFlagSet("receive status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}

	configPath, err := config.DefaultPath()
	if err != nil {
		return err
	}
	fmt.Printf("config_path\t%s\n", configPath)

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}

	downloadDir := cfg.Node.DownloadDir
	if downloadDir == "" {
		downloadDir, err = config.DefaultDownloadDir()
		if err != nil {
			return err
		}
	}
	fmt.Printf("download_dir\t%s\n", downloadDir)
	fmt.Printf("file_receive_mode\t%s\n", strings.ToUpper(cfg.Node.FileReceiveMode))

	switch strings.ToLower(cfg.Node.FileReceiveMode) {
	case config.FileReceiveOpen:
		fmt.Printf("allowed_senders\t%d\n", len(cfg.Node.AllowedFileSenders))
		fmt.Println("allowed_senders_note\topen mode: all senders are allowed")
	case config.FileReceiveTrusted:
		fmt.Printf("allowed_senders\t%d\n", len(cfg.Node.AllowedFileSenders))
		for _, sender := range cfg.Node.AllowedFileSenders {
			fmt.Printf("allow\t%s\n", sender)
		}
	default:
		fmt.Printf("allowed_senders\t%d\n", len(cfg.Node.AllowedFileSenders))
		if strings.ToLower(cfg.Node.FileReceiveMode) == config.FileReceiveOff {
			fmt.Println("allowed_senders_note\treceiving disabled")
		}
	}
	return nil
}

func runReceiveAllow(args []string) error {
	fs := flag.NewFlagSet("receive allow", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	all := fs.Bool("all", false, "allow files from any sender")
	nodeName := fs.String("node", "", "allow files from one node name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *all == (*nodeName != "") {
		return errors.New("receive allow requires exactly one of --all or --node")
	}

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}

	if *all {
		cfg.Node.FileReceiveMode = config.FileReceiveOpen
		cfg.Node.AllowedFileSenders = nil
		if err := store.Save(cfg); err != nil {
			return err
		}
		fmt.Println("file_receive\tOPEN")
		return nil
	}

	if err := record.ValidateNodeName(*nodeName); err != nil {
		return err
	}
	cfg.Node.FileReceiveMode = config.FileReceiveTrusted
	cfg.Node.AllowedFileSenders = append(cfg.Node.AllowedFileSenders, *nodeName)
	if err := store.Save(cfg); err != nil {
		return err
	}
	fmt.Printf("file_receive\tTRUSTED\nallow\t%s\n", *nodeName)
	return nil
}

func runReceiveDeny(args []string) error {
	fs := flag.NewFlagSet("receive deny", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	nodeName := fs.String("node", "", "deny files from one node name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *nodeName == "" {
		return errors.New("receive deny requires --node")
	}
	if err := record.ValidateNodeName(*nodeName); err != nil {
		return err
	}

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}

	filtered := cfg.Node.AllowedFileSenders[:0]
	for _, sender := range cfg.Node.AllowedFileSenders {
		if sender == *nodeName {
			continue
		}
		filtered = append(filtered, sender)
	}
	cfg.Node.AllowedFileSenders = filtered
	if len(cfg.Node.AllowedFileSenders) == 0 {
		cfg.Node.FileReceiveMode = config.FileReceiveOff
	}
	if err := store.Save(cfg); err != nil {
		return err
	}
	fmt.Printf("file_receive\t%s\ndeny\t%s\n", strings.ToUpper(cfg.Node.FileReceiveMode), *nodeName)
	return nil
}

func runReceiveDisable(args []string) error {
	fs := flag.NewFlagSet("receive disable", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}
	cfg.Node.FileReceiveMode = config.FileReceiveOff
	cfg.Node.AllowedFileSenders = nil
	if err := store.Save(cfg); err != nil {
		return err
	}
	fmt.Println("file_receive\tOFF")
	return nil
}

func runStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}
	controlPath, err := config.RuntimeControlPath(store.Path())
	if err != nil {
		return err
	}
	if status, err := runtimectl.RequestStatus(ctx, controlPath); err == nil {
		printRuntimeStatus("ONLINE", status)
		return nil
	}

	printRuntimeStatus("OFFLINE", runtimectl.Status{
		NodeName:        cfg.Node.Name,
		AdvertiseAddr:   cfg.Node.AdvertiseAddr,
		EndpointPublish: endpointPublishMode(cfg.Node.HideEndpoint),
		TransportConfig: cfg.Node.TransportMode,
		TransportActive: vxtransport.EffectiveMode(cfg.Node.TransportMode),
		RelayMode:       cfg.Node.RelayMode,
		RelayPercent:    cfg.Node.RelayResourcePercent,
	})
	return nil
}

func printRuntimeStatus(label string, status runtimectl.Status) {
	fmt.Printf("status\t%s\n", label)
	if status.NodeName != "" {
		fmt.Printf("node_name\t%s\n", status.NodeName)
	}
	if status.AdvertiseAddr != "" {
		fmt.Printf("advertise_addr\t%s\n", status.AdvertiseAddr)
	}
	if status.EndpointPublish != "" {
		fmt.Printf("endpoint_publish\t%s\n", status.EndpointPublish)
	}
	fmt.Printf("transport_config\t%s\n", status.TransportConfig)
	fmt.Printf("transport_active\t%s\n", status.TransportActive)
	fmt.Printf("relay_mode\t%s\n", status.RelayMode)
	fmt.Printf("relay_percent\t%d\n", status.RelayPercent)
	if status.PID > 0 {
		fmt.Printf("pid\t%d\n", status.PID)
	}
	if status.UptimeSeconds > 0 {
		fmt.Printf("uptime_seconds\t%d\n", status.UptimeSeconds)
	}
	fmt.Printf("registry_nodes\t%d\n", status.RegistryNodes)
	fmt.Printf("registry_services\t%d\n", status.RegistryServices)
	if status.DHTRefreshIntervalSeconds > 0 {
		fmt.Printf("dht_refresh_interval_seconds\t%d\n", status.DHTRefreshIntervalSeconds)
	}
	if status.HiddenDescriptorRotationSeconds > 0 {
		fmt.Printf("hidden_descriptor_rotation_seconds\t%d\n", status.HiddenDescriptorRotationSeconds)
	}
	if status.HiddenDescriptorOverlapKeys > 0 {
		fmt.Printf("hidden_descriptor_overlap_keys\t%d\n", status.HiddenDescriptorOverlapKeys)
	}
	fmt.Printf("asn_resolver_loaded\t%v\n", status.ASNResolverLoaded)
	if status.ASNResolverSource != "" {
		fmt.Printf("asn_resolver_source\t%s\n", status.ASNResolverSource)
	}
	if status.ASNResolverEntries > 0 {
		fmt.Printf("asn_resolver_entries\t%d\n", status.ASNResolverEntries)
	}
	fmt.Printf("dht_tracked_keys\t%d\n", status.DHTTrackedKeys)
	fmt.Printf("dht_healthy_keys\t%d\n", status.DHTHealthyKeys)
	fmt.Printf("dht_degraded_keys\t%d\n", status.DHTDegradedKeys)
	fmt.Printf("dht_stale_keys\t%d\n", status.DHTStaleKeys)
	fmt.Printf("hidden_descriptor_keys\t%d\n", status.HiddenDescriptorKeys)
	fmt.Printf("hidden_descriptor_healthy\t%d\n", status.HiddenDescriptorHealthy)
	fmt.Printf("hidden_descriptor_degraded\t%d\n", status.HiddenDescriptorDegraded)
	fmt.Printf("hidden_descriptor_stale\t%d\n", status.HiddenDescriptorStale)
}

func runIdentity(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("identity", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) > 0 {
		switch fs.Args()[0] {
		case "rename":
			return runIdentityRename(ctx, fs.Args()[1:])
		case "export-endpoint":
			return runIdentityExportEndpoint(fs.Args()[1:])
		default:
			return fmt.Errorf("unknown identity subcommand %q", fs.Args()[0])
		}
	}
	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	idStore, err := identity.NewStoreForConfig(store.Path())
	if err != nil {
		return err
	}
	id, err := idStore.Load()
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}
	fmt.Printf("node_name\t%s\n", cfg.Node.Name)
	fmt.Printf("node_id\t%s\n", id.NodeID)
	fmt.Printf("endpoint_publish\t%s\n", endpointPublishMode(cfg.Node.HideEndpoint))
	fmt.Printf("transport_config\t%s\n", cfg.Node.TransportMode)
	fmt.Printf("transport_active\t%s\n", vxtransport.EffectiveMode(cfg.Node.TransportMode))
	fmt.Printf("relay_mode\t%s\n", cfg.Node.RelayMode)
	fmt.Printf("relay_percent\t%d\n", cfg.Node.RelayResourcePercent)
	fmt.Printf("config_path\t%s\n", store.Path())
	return nil
}

func runIdentityExportEndpoint(args []string) error {
	fs := flag.NewFlagSet("identity export-endpoint", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("addr", "", "IPv6 VX6 endpoint")
	name := fs.String("name", "", "node name (defaults to configured name)")
	outPath := fs.String("out", "", "output file (defaults to stdout)")
	ttl := fs.Duration("ttl", 24*time.Hour, "record validity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}
	if *name == "" {
		*name = cfg.Node.Name
	}
	if *addr == "" {
		*addr = cfg.Node.AdvertiseAddr
	}
	if *name == "" || *addr == "" {
		return errors.New("identity export-endpoint requires a configured node name and --addr")
	}
	idStore, err := identity.NewStoreForConfig(store.Path())
	if err != nil {
		return err
	}
	id, err := idStore.Load()
	if err != nil {
		return err
	}
	endpoint, err := record.NewEndpointRecord(id, *name, *addr, *ttl, time.Now())
	if err != nil {
		return err
	}
	data, err := record.JSON(endpoint)
	if err != nil {
		return err
	}
	if *outPath == "" {
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(*outPath, data, 0o600); err != nil {
		return fmt.Errorf("write signed endpoint record: %w", err)
	}
	fmt.Printf("endpoint_record\t%s\t%s\n", endpoint.NodeName, endpoint.Address)
	return nil
}

func runIdentityRename(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("identity rename", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	name := fs.String("name", "", "new node name")
	waitFlag := fs.Duration("wait", time.Minute, "how long to probe for name clashes before accepting the rename")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("identity rename requires --name")
	}
	if err := record.ValidateNodeName(*name); err != nil {
		return err
	}

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}
	idStore, err := identity.NewStoreForConfig(store.Path())
	if err != nil {
		return err
	}
	id, err := idStore.Load()
	if err != nil {
		return err
	}
	if err := waitForNodeNameAvailability(ctx, cfg, *name, id.NodeID, *waitFlag); err != nil {
		return err
	}
	cfg.Node.Name = *name
	if err := store.Save(cfg); err != nil {
		return err
	}
	fmt.Printf("node_renamed\t%s\t%s\n", id.NodeID, *name)
	return nil
}

func runDebug(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printDebugUsage(os.Stderr)
		return errors.New("missing debug subcommand")
	}

	switch args[0] {
	case "registry":
		return runDebugRegistry(args[1:])
	case "dht-get":
		return runDebugDHTGet(ctx, args[1:])
	case "dht-status":
		return runDebugDHTStatus(ctx, args[1:])
	case "ebpf-status":
		return runDebugEBPFStatus(args[1:]...)
	case "ebpf-attach":
		return runDebugEBPFAttach(ctx, args[1:])
	case "ebpf-detach":
		return runDebugEBPFDetach(ctx, args[1:])
	case "firewall-clear":
		return runDebugFirewallClear(args[1:])
	case "bootstrap-info":
		return runDebugBootstrapInfo(args[1:])
	default:
		printDebugUsage(os.Stderr)
		return fmt.Errorf("unknown debug subcommand %q", args[0])
	}
}

func printDebugUsage(w io.Writer) {
	fmt.Fprintln(w, "Debug commands:")
	fmt.Fprintln(w, "  vx6 debug registry")
	fmt.Fprintln(w, "  vx6 debug dht-get (--service NODE.SERVICE | --node NAME | --node-id ID | --key KEY)")
	fmt.Fprintln(w, "  vx6 debug dht-status")
	fmt.Fprintln(w, "  vx6 debug bootstrap-info")
	printDebugEBPFUsage(w)
	printDebugFirewallUsage(w)
}

func printDebugEBPFUsage(w io.Writer) {
	fmt.Fprintln(w, "  vx6 debug ebpf-status [--iface IFACE]")
	fmt.Fprintln(w, "  vx6 debug ebpf-attach --iface IFACE")
	fmt.Fprintln(w, "  vx6 debug ebpf-detach --iface IFACE")
}

func printDebugFirewallUsage(w io.Writer) {
	if runtime.GOOS == "windows" {
		fmt.Fprintln(w, "  vx6 debug firewall-clear --port PORT")
	}
}

func runDebugRegistry(args []string) error {
	fs := flag.NewFlagSet("debug registry", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}
	reg, err := loadLocalRegistry(cfg.Node.DataDir)
	if err != nil {
		return err
	}

	nodes, services := reg.Snapshot()
	fmt.Printf("registry_path\t%s\n", filepath.Join(cfg.Node.DataDir, "registry.json"))
	fmt.Printf("node_records\t%d\n", len(nodes))
	fmt.Printf("service_records\t%d\n", len(services))
	for _, rec := range nodes {
		fmt.Printf("node\t%s\t%s\tendpoint=%s\n", rec.NodeName, rec.NodeID, endpointVisibilitySummary(rec.Address, false))
	}
	for _, svc := range services {
		fmt.Printf("service\tkey=%s\tnode=%s\tservice=%s\tendpoint=%s\thidden=%v\n", record.ServiceLookupKey(svc), svc.NodeName, svc.ServiceName, endpointVisibilitySummary(svc.Address, svc.IsHidden), svc.IsHidden)
	}
	return nil
}

func endpointPublishMode(hidden bool) string {
	if hidden {
		return "hidden"
	}
	return "published"
}

func peerDirectoryState(address string) string {
	if address == "" {
		return "missing"
	}
	return "configured"
}

func endpointVisibilitySummary(address string, isHidden bool) string {
	switch {
	case isHidden:
		return "hidden"
	case address != "":
		return "sealed"
	default:
		return "missing"
	}
}

func runDebugDHTGet(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("debug dht-get", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	key := fs.String("key", "", "raw DHT key")
	service := fs.String("service", "", "service name in node.service form")
	nodeName := fs.String("node", "", "node name")
	nodeID := fs.String("node-id", "", "node id")
	if err := fs.Parse(args); err != nil {
		return err
	}

	chosen := 0
	for _, value := range []string{*key, *service, *nodeName, *nodeID} {
		if value != "" {
			chosen++
		}
	}
	if chosen != 1 {
		return errors.New("debug dht-get requires exactly one of --key, --service, --node, or --node-id")
	}

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}

	client, err := newDHTClient(cfg)
	if err != nil {
		return err
	}
	switch {
	case *service != "":
		if strings.Contains(*service, ".") {
			*key = dht.ServiceKey(*service)
		} else {
			rec, err := client.ResolveHiddenService(ctx, *service, time.Now())
			if err == nil {
				formatted, _ := json.MarshalIndent(rec, "", "  ")
				fmt.Printf("%s\n", formatted)
				return nil
			}
			return fmt.Errorf("hidden service %q not found", *service)
		}
	case *nodeName != "":
		*key = dht.NodeNameKey(*nodeName)
	case *nodeID != "":
		*key = dht.NodeIDKey(*nodeID)
	}

	result, err := client.RecursiveFindValueDetailed(ctx, *key)
	if err != nil {
		if errors.Is(err, dht.ErrConflictingValues) {
			printDHTConflictCandidates(*key, result.ConflictValues)
			return err
		}
		return err
	}

	if len(result.ConflictValues) > 1 {
		printDHTConflictCandidates(*key, result.ConflictValues)
		return fmt.Errorf("conflicting values returned for %s", *key)
	}

	var pretty any
	if err := json.Unmarshal([]byte(result.Value), &pretty); err == nil {
		formatted, _ := json.MarshalIndent(pretty, "", "  ")
		fmt.Printf("%s\n", formatted)
		return nil
	}

	fmt.Println(result.Value)
	return nil
}

func printDHTConflictCandidates(key string, rawValues []string) {
	if len(rawValues) == 0 {
		fmt.Printf("conflict\tkey=%s\tcandidates=0\n", key)
		return
	}
	fmt.Printf("conflict\tkey=%s\tcandidates=%d\n", key, len(rawValues))
	for i, raw := range rawValues {
		fmt.Printf("  [%d] %s\n", i+1, summarizeConflictValue(raw))
	}
}

func summarizeConflictValue(raw string) string {
	var ep record.EndpointRecord
	if err := json.Unmarshal([]byte(raw), &ep); err == nil && ep.NodeID != "" {
		return fmt.Sprintf("node=%s id=%s addr=%s", ep.NodeName, ep.NodeID, ep.Address)
	}
	var svc record.ServiceRecord
	if err := json.Unmarshal([]byte(raw), &svc); err == nil && svc.NodeID != "" {
		return fmt.Sprintf("service=%s node=%s hidden=%v private=%v", record.ServiceLookupKey(svc), svc.NodeName, svc.IsHidden, svc.IsPrivate)
	}
	return raw
}

func runDebugDHTStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("debug dht-status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	controlPath, err := config.RuntimeControlPath(store.Path())
	if err != nil {
		return err
	}
	status, err := runtimectl.RequestStatus(ctx, controlPath)
	if err != nil {
		return err
	}
	printRuntimeStatus("ONLINE", status)
	return nil
}

func runDebugEBPFStatus(args ...string) error {
	if runtime.GOOS == "windows" {
		PrintEBPFPlatformNote()
		return nil
	}

	fs := flag.NewFlagSet("debug ebpf-status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	iface := fs.String("iface", "", "network interface name")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *iface == "" {
		warning := "embedded XDP program targets the legacy VX6 onion header and is not yet the active fast path for the current encrypted relay data path"
		printXDPStatus(onion.XDPStatus{
			EmbeddedBytecode:     onion.IsEBPFAvailable(),
			BytecodeSize:         len(onion.OnionRelayBytecode),
			CompatibilityWarning: warning,
		})
		fmt.Println("attach_state\tuse --iface IFACE for live kernel status")
		return nil
	}

	status, err := onion.NewXDPManager().Status(context.Background(), *iface)
	if err != nil {
		return err
	}
	printXDPStatus(status)
	return nil
}

func runDebugEBPFAttach(ctx context.Context, args []string) error {
	if runtime.GOOS == "windows" {
		PrintEBPFPlatformNote()
		return nil
	}

	fs := flag.NewFlagSet("debug ebpf-attach", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	iface := fs.String("iface", "", "network interface name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" {
		return errors.New("debug ebpf-attach requires --iface")
	}

	status, err := onion.NewXDPManager().Attach(ctx, *iface)
	if err != nil {
		return err
	}
	fmt.Println("ebpf_attach\tok")
	printXDPStatus(status)
	return nil
}

func runDebugEBPFDetach(ctx context.Context, args []string) error {
	if runtime.GOOS == "windows" {
		PrintEBPFPlatformNote()
		return nil
	}

	fs := flag.NewFlagSet("debug ebpf-detach", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	iface := fs.String("iface", "", "network interface name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" {
		return errors.New("debug ebpf-detach requires --iface")
	}

	status, err := onion.NewXDPManager().Detach(ctx, *iface)
	if err != nil {
		return err
	}
	fmt.Println("ebpf_detach\tok")
	printXDPStatus(status)
	return nil
}

func runDebugFirewallClear(args []string) error {
	fs := flag.NewFlagSet("debug firewall-clear", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	port := fs.Int("port", 0, "port number to clear firewall rules for")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *port == 0 {
		return errors.New("debug firewall-clear requires --port")
	}

	if err := RemoveFirewallException(*port); err != nil {
		return err
	}
	fmt.Printf("firewall_clear\tport=%d\tstatus=ok\n", *port)
	return nil
}

func runDebugBootstrapInfo(args []string) error {
	fs := flag.NewFlagSet("debug bootstrap-info", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := config.NewStore("")
	if err != nil {
		return err
	}
	cfg, err := store.Load()
	if err != nil {
		return err
	}

	bootstrapAddrs := config.ConfiguredPeerAddresses(cfg)
	fmt.Println("Bootstrap Peers (used for network discovery via DHT):")
	if len(bootstrapAddrs) == 0 {
		fmt.Println("  (none configured)")
		fmt.Println("\nTo add bootstrap peers:")
		fmt.Println("  vx6 peer add --addr [ipv6]:port")
		fmt.Println("  OR")
		fmt.Println("  vx6 init --name <name> --peer [ipv6]:port")
		return nil
	}
	for _, addr := range bootstrapAddrs {
		fmt.Printf("  %s\n", addr)
	}
	fmt.Printf("\nTotal bootstrap peers: %d\n", len(bootstrapAddrs))
	fmt.Println("\nThese peers are seeded into the DHT routing table on startup.")
	return nil
}

func printXDPStatus(status onion.XDPStatus) {
	fmt.Printf("embedded_bytecode\t%v\n", status.EmbeddedBytecode)
	fmt.Printf("bytecode_size\t%d\n", status.BytecodeSize)
	if status.Interface != "" {
		fmt.Printf("iface\t%s\n", status.Interface)
	}
	fmt.Printf("xdp_attached\t%v\n", status.Attached)
	fmt.Printf("vx6_active\t%v\n", status.VX6Active)
	if status.Mode != "" {
		fmt.Printf("mode\t%s\n", status.Mode)
	}
	if status.ProgramName != "" {
		fmt.Printf("program_name\t%s\n", status.ProgramName)
	}
	if status.ProgramID > 0 {
		fmt.Printf("program_id\t%d\n", status.ProgramID)
	}
	if status.ProgramTag != "" {
		fmt.Printf("program_tag\t%s\n", status.ProgramTag)
	}
	if status.CompatibilityWarning != "" {
		fmt.Printf("compatibility_warning\t%s\n", status.CompatibilityWarning)
	}
}

func loadLocalRegistry(dataDir string) (*discovery.Registry, error) {
	if dataDir == "" {
		dataDir = defaultDataDirValue()
	}
	return discovery.NewRegistry(filepath.Join(dataDir, "registry.json"))
}

func defaultDataDirValue() string {
	path, err := config.DefaultDataDir()
	if err != nil {
		return filepath.Join(".", "vx6-data")
	}
	return path
}

func defaultDownloadDirValue() string {
	path, err := config.DefaultDownloadDir()
	if err != nil {
		return filepath.Join(".", "Downloads")
	}
	return path
}

func defaultStorageLines() []string {
	configPath, err := config.DefaultPath()
	if err != nil || strings.TrimSpace(configPath) == "" {
		configPath = filepath.Join(".", "config.json")
	}
	idStore, err := identity.NewStoreForConfig(configPath)
	identityPath := filepath.Join(filepath.Dir(configPath), "identity.json")
	if err == nil && strings.TrimSpace(idStore.Path()) != "" {
		identityPath = idStore.Path()
	}
	dataDir := defaultDataDirValue()
	downloadDir := defaultDownloadDirValue()
	return []string{
		"  - Config: " + configPath,
		"  - Identity: " + identityPath,
		"  - Runtime state: " + dataDir,
		"  - Received files: " + downloadDir,
	}
}

func runningNodeAdvice() string {
	if runtime.GOOS == "windows" {
		return "use 'vx6 status', 'vx6 reload', or stop the existing vx6 process"
	}
	return "use 'vx6 status', 'vx6 reload', or 'systemctl --user restart vx6'"
}

func friendlyRelayPathError(err error, feature string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not enough peers in registry to build a"):
		return fmt.Errorf("%s requires more reachable VX6 nodes. your local registry does not have enough peers to build the relay path; keep the node running so it can sync more peers, then try again", feature)
	case strings.Contains(msg, "hidden service has no reachable introduction points"),
		strings.Contains(msg, "no rendezvous candidates available"),
		strings.Contains(msg, "failed to establish hidden-service circuit"),
		strings.Contains(msg, "no reachable guard or owner for hidden service"):
		return fmt.Errorf("%s requires more reachable VX6 nodes. your local registry does not currently have enough live intro, guard, or rendezvous peers; keep the node running so it can sync more peers, then try again", feature)
	default:
		return err
	}
}

func resolvePeerForSend(ctx context.Context, store *config.Store, cfg config.File, name string) (string, error) {
	p, err := store.ResolvePeer(name)
	if err == nil {
		return p.Address, nil
	}
	rec, err := resolveNodeDistributed(ctx, cfg, name)
	if err != nil {
		return "", err
	}
	registry, err := loadLocalRegistry(cfg.Node.DataDir)
	if err != nil {
		return "", err
	}
	if err := registry.Import([]record.EndpointRecord{rec}, nil); err != nil {
		return "", fmt.Errorf("cache verified peer identity: %w", err)
	}
	_ = store.AddPeer(rec.NodeName, rec.Address)
	return rec.Address, nil
}

func resolveNodeDistributed(ctx context.Context, cfg config.File, name string) (record.EndpointRecord, error) {
	reg, _ := loadLocalRegistry(cfg.Node.DataDir)
	if reg != nil {
		nodes, _ := reg.Snapshot()
		for _, n := range nodes {
			if n.NodeName == name {
				return n, nil
			}
		}
	}

	if d, err := newDHTClient(cfg); err == nil && d != nil {
		result, err := d.RecursiveFindValueDetailed(ctx, dht.NodeNameKey(name))
		if errors.Is(err, dht.ErrConflictingValues) || len(result.ConflictValues) > 1 {
			choice, choiceErr := chooseEndpointConflict(name, result.ConflictValues)
			if choiceErr == nil {
				return choice, nil
			}
			return record.EndpointRecord{}, choiceErr
		}
		if err == nil && result.Value != "" {
			var rec record.EndpointRecord
			if err := json.Unmarshal([]byte(result.Value), &rec); err == nil {
				if verifyErr := record.VerifyEndpointRecord(rec, time.Now()); verifyErr == nil {
					return rec, nil
				}
			}
		}
	}

	for _, addr := range discoveryCandidates(cfg) {
		rec, err := discovery.Resolve(ctx, addr, name, "")
		if err == nil {
			return rec, nil
		}
	}
	return record.EndpointRecord{}, errors.New("not found")
}

func resolveServiceDistributed(ctx context.Context, cfg config.File, service string) (record.ServiceRecord, error) {
	reg, _ := loadLocalRegistry(cfg.Node.DataDir)
	if reg != nil {
		if rec, err := reg.ResolveServiceLocal(service); err == nil {
			return rec, nil
		}
	}

	if d, err := newDHTClient(cfg); err == nil && d != nil {
		if strings.Contains(service, ".") {
			result, err := d.RecursiveFindValueDetailed(ctx, dht.ServiceKey(service))
			if errors.Is(err, dht.ErrConflictingValues) || len(result.ConflictValues) > 1 {
				choice, choiceErr := chooseServiceConflict(service, result.ConflictValues)
				if choiceErr == nil {
					return choice, nil
				}
				return record.ServiceRecord{}, choiceErr
			}
			if err == nil && result.Value != "" {
				var r record.ServiceRecord
				if err := json.Unmarshal([]byte(result.Value), &r); err == nil {
					if verifyErr := record.VerifyServiceRecord(r, time.Now()); verifyErr == nil {
						return r, nil
					}
				}
			}
			if rec, err := resolvePrivateServiceFromCatalog(ctx, d, service); err == nil {
				return rec, nil
			}
		} else {
			if rec, err := d.ResolveHiddenService(ctx, service, time.Now()); err == nil {
				return rec, nil
			}
		}
	}

	for _, addr := range discoveryCandidates(cfg) {
		rec, err := discovery.ResolveService(ctx, addr, service)
		if err == nil {
			return rec, nil
		}
	}
	return record.ServiceRecord{}, errors.New("not found")
}

func waitForNodeNameAvailability(ctx context.Context, cfg config.File, name, ownNodeID string, wait time.Duration) error {
	if wait <= 0 {
		wait = time.Minute
	}
	if len(discoveryCandidates(cfg)) == 0 {
		fmt.Printf("name_check\tname=%s\tstatus=skipped\treason=no-network-entrance\n", name)
		return nil
	}

	client, err := newDHTClient(cfg)
	if err != nil {
		return err
	}
	if client == nil {
		return nil
	}

	deadline := time.Now().Add(wait)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	fmt.Printf("name_check\tname=%s\tstatus=initialising\twait=%s\n", name, wait.Round(time.Second))

	for {
		result, err := client.RecursiveFindValueDetailed(ctx, dht.NodeNameKey(name))
		candidates := collectNodeNameCandidates(result, ownNodeID)
		if len(candidates) > 0 {
			printNameConflictCandidates(name, candidates)
			return fmt.Errorf("node name %q is already in use", name)
		}
		if err == nil && result.Value != "" {
			var rec record.EndpointRecord
			if json.Unmarshal([]byte(result.Value), &rec) == nil && rec.NodeID != ownNodeID {
				printNameConflictCandidates(name, []record.EndpointRecord{rec})
				return fmt.Errorf("node name %q is already in use", name)
			}
		}

		if time.Now().After(deadline) {
			fmt.Printf("name_check\tname=%s\tstatus=available\n", name)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func collectNodeNameCandidates(result dht.LookupResult, ownNodeID string) []record.EndpointRecord {
	seen := map[string]struct{}{}
	candidates := make([]record.EndpointRecord, 0, len(result.ConflictValues)+1)
	add := func(raw string) {
		var rec record.EndpointRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			return
		}
		if rec.NodeName == "" || rec.NodeID == ownNodeID {
			return
		}
		key := rec.NodeID + "|" + rec.NodeName + "|" + rec.Address
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, rec)
	}
	if result.Value != "" {
		add(result.Value)
	}
	for _, raw := range result.ConflictValues {
		add(raw)
	}
	return candidates
}

func printNameConflictCandidates(name string, candidates []record.EndpointRecord) {
	if len(candidates) == 0 {
		return
	}
	fmt.Printf("name_conflict\tname=%s\tcandidates=%d\n", name, len(candidates))
	for i, rec := range candidates {
		fmt.Printf("  [%d] node=%s id=%s addr=%s\n", i+1, rec.NodeName, rec.NodeID, rec.Address)
	}
}

func chooseEndpointConflict(name string, rawValues []string) (record.EndpointRecord, error) {
	candidates := decodeEndpointCandidates(rawValues)
	if len(candidates) == 0 {
		return record.EndpointRecord{}, fmt.Errorf("name conflict detected for %q but no valid endpoint candidates were returned", name)
	}
	choice, err := chooseConflictIndex(fmt.Sprintf("node name %q", name), candidatesToStrings(candidates))
	if err != nil {
		return record.EndpointRecord{}, err
	}
	return candidates[choice], nil
}

func chooseServiceConflict(service string, rawValues []string) (record.ServiceRecord, error) {
	candidates := decodeServiceCandidates(rawValues)
	if len(candidates) == 0 {
		return record.ServiceRecord{}, fmt.Errorf("service conflict detected for %q but no valid service candidates were returned", service)
	}
	choice, err := chooseConflictIndex(fmt.Sprintf("service %q", service), serviceCandidatesToStrings(candidates))
	if err != nil {
		return record.ServiceRecord{}, err
	}
	return candidates[choice], nil
}

func chooseConflictIndex(label string, options []string) (int, error) {
	if len(options) == 0 {
		return -1, fmt.Errorf("no conflict candidates for %s", label)
	}
	fmt.Printf("\n%s has multiple matches:\n", label)
	for i, opt := range options {
		fmt.Printf("  [%d] %s\n", i+1, opt)
	}
	for {
		answer := prompt("Choose a match by number")
		if answer == "" {
			return -1, fmt.Errorf("%s selection cancelled", label)
		}
		idx, err := strconv.Atoi(answer)
		if err != nil || idx < 1 || idx > len(options) {
			fmt.Println("Invalid choice; enter a number from the list above.")
			continue
		}
		return idx - 1, nil
	}
}

func decodeEndpointCandidates(rawValues []string) []record.EndpointRecord {
	candidates := make([]record.EndpointRecord, 0, len(rawValues))
	seen := map[string]struct{}{}
	for _, raw := range rawValues {
		var rec record.EndpointRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			continue
		}
		if err := record.VerifyEndpointRecord(rec, time.Now()); err != nil {
			continue
		}
		key := rec.NodeID + "|" + rec.NodeName + "|" + rec.Address
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		candidates = append(candidates, rec)
	}
	return candidates
}

func decodeServiceCandidates(rawValues []string) []record.ServiceRecord {
	candidates := make([]record.ServiceRecord, 0, len(rawValues))
	seen := map[string]struct{}{}
	for _, raw := range rawValues {
		var rec record.ServiceRecord
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			continue
		}
		if err := record.VerifyServiceRecord(rec, time.Now()); err != nil {
			continue
		}
		key := rec.NodeID + "|" + rec.NodeName + "|" + rec.ServiceName + "|" + rec.Address
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		candidates = append(candidates, rec)
	}
	return candidates
}

func candidatesToStrings(candidates []record.EndpointRecord) []string {
	out := make([]string, 0, len(candidates))
	for _, rec := range candidates {
		out = append(out, fmt.Sprintf("node=%s id=%s addr=%s", rec.NodeName, rec.NodeID, rec.Address))
	}
	return out
}

func serviceCandidatesToStrings(candidates []record.ServiceRecord) []string {
	out := make([]string, 0, len(candidates))
	for _, rec := range candidates {
		out = append(out, fmt.Sprintf("service=%s node=%s id=%s hidden=%v private=%v", record.ServiceLookupKey(rec), rec.NodeName, rec.NodeID, rec.IsHidden, rec.IsPrivate))
	}
	return out
}

func resolvePrivateServiceFromCatalog(ctx context.Context, client *dht.Server, service string) (record.ServiceRecord, error) {
	parts := strings.SplitN(service, ".", 2)
	if len(parts) != 2 {
		return record.ServiceRecord{}, errors.New("not a private catalog lookup")
	}
	services, err := lookupPrivateServicesByNode(ctx, client, parts[0])
	if err != nil {
		return record.ServiceRecord{}, err
	}
	for _, svc := range services {
		if svc.ServiceName == parts[1] {
			return svc, nil
		}
	}
	return record.ServiceRecord{}, errors.New("not found")
}

func requestedServiceName(input string) string {
	if !strings.Contains(input, ".") {
		return input
	}
	parts := strings.Split(input, ".")
	return parts[len(parts)-1]
}

func serviceLookupKeys(service string) []string {
	if strings.Contains(service, ".") {
		return []string{dht.ServiceKey(service)}
	}
	return dht.HiddenServiceLookupKeys(service, time.Now())
}

func lookupPrivateServicesForUser(ctx context.Context, cfg config.File, nodeName string) ([]record.ServiceRecord, error) {
	client, err := newDHTClient(cfg)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("dht unavailable")
	}
	return lookupPrivateServicesByNode(ctx, client, nodeName)
}

func lookupPrivateServicesByNode(ctx context.Context, client *dht.Server, nodeName string) ([]record.ServiceRecord, error) {
	value, err := client.RecursiveFindValue(ctx, dht.PrivateCatalogKey(nodeName))
	if err != nil || value == "" {
		return nil, err
	}
	catalog, err := dht.DecodePrivateServiceCatalog(value, time.Now())
	if err != nil {
		return nil, err
	}
	return append([]record.ServiceRecord(nil), catalog.Services...), nil
}

func discoveryCandidates(cfg config.File) []string {
	seen := map[string]struct{}{}
	var out []string

	add := func(addr string) {
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}

	for _, addr := range config.ConfiguredPeerAddresses(cfg) {
		add(addr)
	}
	if registry, err := loadLocalRegistry(cfg.Node.DataDir); err == nil {
		nodes, _ := registry.Snapshot()
		for _, rec := range nodes {
			add(rec.Address)
		}
	}
	return out
}

func newDHTClient(cfg config.File) (*dht.Server, error) {
	_, _ = dht.ConfigureASNResolver(mustDefaultConfigPath())
	client := dht.NewServer("cli-observer")
	var registryNodes []record.EndpointRecord
	registry, err := loadLocalRegistry(cfg.Node.DataDir)
	if err != nil {
		return nil, err
	}
	if err := importConfiguredKnownPeers(cfg, registry); err != nil {
		return nil, err
	}
	registryNodes, _ = registry.Snapshot()

	for _, addr := range config.ConfiguredPeerAddresses(cfg) {
		if addr != "" {
			client.RT.AddNode(proto.NodeInfo{ID: "seed:" + addr, Addr: addr})
		}
	}
	for _, rec := range registryNodes {
		if record.VerifyEndpointRecord(rec, time.Now()) == nil {
			client.RT.AddNode(dht.NodeInfoFromEndpointRecord(rec))
		}
	}
	store, err := config.NewStore("")
	if err != nil {
		return nil, err
	}
	idStore, err := identity.NewStoreForConfig(store.Path())
	if err != nil {
		return nil, err
	}
	id, err := idStore.Load()
	if err != nil {
		return nil, err
	}
	_, guard, err := newIPsecDialGuard(cfg, id, registry, client.RT)
	if err != nil {
		return nil, err
	}
	client.SetDialGuard(guard)
	client.SetHiddenDescriptorPrivacy(dht.HiddenDescriptorPrivacyConfig{
		TransportMode: cfg.Node.TransportMode,
		RelayHopCount: 3,
		RelayCandidates: func() []record.EndpointRecord {
			return append([]record.EndpointRecord(nil), registryNodes...)
		},
		ExcludeAddrs: func() []string {
			exclude := make([]string, 0, 2)
			if cfg.Node.AdvertiseAddr != "" {
				exclude = append(exclude, cfg.Node.AdvertiseAddr)
			}
			if cfg.Node.ListenAddr != "" && cfg.Node.ListenAddr != cfg.Node.AdvertiseAddr {
				exclude = append(exclude, cfg.Node.ListenAddr)
			}
			return exclude
		},
	})
	return client, nil
}

func newIPsecDialGuard(cfg config.File, id identity.Identity, registry *discovery.Registry, rt *dht.RoutingTable) (*ipsec.Client, vxtransport.DialGuard, error) {
	localAddr := cfg.Node.AdvertiseAddr
	if localAddr == "" {
		_, port, err := net.SplitHostPort(cfg.Node.ListenAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve local IPv6 endpoint for IPsec: %w", err)
		}
		localAddr, err = netutil.DetectAdvertiseAddress(port)
		if err != nil {
			return nil, nil, fmt.Errorf("detect local IPv6 endpoint for IPsec: %w", err)
		}
	}
	client, err := ipsec.NewClient(ipsec.DefaultSocket(), localAddr, id)
	if err != nil {
		return nil, nil, err
	}
	guard := func(ctx context.Context, addr string) error {
		if registry != nil {
			nodes, _ := registry.Snapshot()
			for _, peer := range nodes {
				if peer.Address == addr && record.VerifyEndpointRecord(peer, time.Now()) == nil {
					return client.EnsurePeer(ctx, peer)
				}
			}
		}
		if rt != nil {
			info, ok := rt.NodeByAddress(addr)
			if ok && dht.VerifyNodeInfo(info, time.Now()) == nil {
				peer := record.EndpointRecord{
					NodeID: info.ID, NodeName: info.Name, Address: info.Addr,
					PublicKey: info.PublicKey, IssuedAt: info.IdentityIssuedAt,
					ExpiresAt: info.IdentityExpiresAt, Signature: info.IdentitySignature,
				}
				return client.EnsurePeer(ctx, peer)
			}
		}
		return fmt.Errorf("no verified signed peer identity for endpoint %s", addr)
	}
	return client, guard, nil
}

func importConfiguredKnownPeers(cfg config.File, registry *discovery.Registry) error {
	records := make([]record.EndpointRecord, 0, len(cfg.Node.KnownPeers))
	for _, peer := range cfg.Node.KnownPeers {
		rec := record.EndpointRecord{
			NodeID: peer.NodeID, NodeName: peer.NodeName, Address: peer.Address,
			PublicKey: peer.PublicKey, IssuedAt: peer.IdentityIssuedAt,
			ExpiresAt: peer.IdentityExpiresAt, Signature: peer.IdentitySignature,
		}
		if err := record.VerifyEndpointRecord(rec, time.Now()); err == nil {
			records = append(records, rec)
		}
	}
	return registry.Import(records, nil)
}

func mustDefaultConfigPath() string {
	path, err := config.DefaultPath()
	if err != nil {
		return ""
	}
	return path
}

func writePIDFile(path string, pid int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create runtime directory: %w", err)
	}
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", pid)), 0o644)
}

type nodeRuntimeLock struct {
	lockPath    string
	pidPath     string
	controlPath string
}

func acquireNodeLock(configPath string) (*nodeRuntimeLock, error) {
	lockPath, err := config.RuntimeLockPath(configPath)
	if err != nil {
		return nil, err
	}
	pidPath, err := config.RuntimePIDPath(configPath)
	if err != nil {
		return nil, err
	}
	controlPath, err := config.RuntimeControlPath(configPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, fmt.Errorf("create runtime directory: %w", err)
	}

	acquired := false
	for attempt := 0; attempt < 2 && !acquired; attempt++ {
		if err := os.Mkdir(lockPath, 0o755); err == nil {
			acquired = true
			break
		} else if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("lock runtime state: %w", err)
		}
		if !clearStaleRuntimeLock(lockPath, pidPath, controlPath) {
			return nil, runningNodeError(pidPath)
		}
	}
	if !acquired {
		return nil, runningNodeError(pidPath)
	}
	if err := writePIDFile(pidPath, os.Getpid()); err != nil {
		_ = os.Remove(pidPath)
		_ = os.Remove(controlPath)
		_ = os.Remove(lockPath)
		return nil, err
	}

	return &nodeRuntimeLock{lockPath: lockPath, pidPath: pidPath, controlPath: controlPath}, nil
}

func (l *nodeRuntimeLock) Close() error {
	if l == nil {
		return nil
	}
	_ = os.Remove(l.pidPath)
	_ = os.Remove(l.controlPath)
	return os.Remove(l.lockPath)
}

func runningNodeError(pidPath string) error {
	pid, err := readNodePID(pidPath)
	if err == nil && pid > 0 {
		return fmt.Errorf("vx6 node is already running in the background (pid %d). %s", pid, runningNodeAdvice())
	}
	return fmt.Errorf("vx6 node is already running in the background. %s", runningNodeAdvice())
}

func clearStaleRuntimeLock(lockPath, pidPath, controlPath string) bool {
	pid, err := readNodePID(pidPath)
	if err == nil && pid > 0 {
		if err := processExists(pid); err == nil {
			return false
		}
	}
	_ = os.Remove(pidPath)
	_ = os.Remove(controlPath)
	if err := os.Remove(lockPath); err == nil || errors.Is(err, os.ErrNotExist) {
		return true
	}
	return false
}

func readNodePID(pidPath string) (int, error) {
	data, err := os.ReadFile(pidPath)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, err
	}
	return pid, nil
}
