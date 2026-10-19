package sdk

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vx6/vx6/internal/config"
	"github.com/vx6/vx6/internal/discovery"
	"github.com/vx6/vx6/internal/hidden"
	"github.com/vx6/vx6/internal/identity"
	"github.com/vx6/vx6/internal/onion"
	"github.com/vx6/vx6/internal/record"
	"github.com/vx6/vx6/internal/serviceproxy"
	"github.com/vx6/vx6/internal/transfer"
	vxtransport "github.com/vx6/vx6/internal/transport"
)

type ConnectOptions struct {
	Service string
	Listen  string
	Addr    string
	Proxy   bool
}

type ForwarderCallbacks struct {
	OnStarted func(localListen, service string)
	OnError   func(error)
	OnStopped func()
}

type ForwarderHandle struct {
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func (h *ForwarderHandle) Stop() {
	if h == nil {
		return
	}
	h.once.Do(func() {
		h.cancel()
		<-h.done
	})
}

func (h *ForwarderHandle) Done() <-chan struct{} {
	if h == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return h.done
}

func (c *Client) StartForwarder(ctx context.Context, opts ConnectOptions, cb ForwarderCallbacks) (*ForwarderHandle, error) {
	if strings.TrimSpace(opts.Service) == "" {
		return nil, errors.New("connect requires non-empty service")
	}
	if strings.TrimSpace(opts.Listen) == "" {
		opts.Listen = "127.0.0.1:2222"
	}

	cfg, err := c.store.Load()
	if err != nil {
		return nil, err
	}
	idStore, err := identity.NewStoreForConfig(c.store.Path())
	if err != nil {
		return nil, err
	}
	id, err := idStore.Load()
	if err != nil {
		return nil, err
	}

	requestService := requestedServiceName(opts.Service)
	serviceRec, err := c.resolveConnectTarget(ctx, cfg, requestService, opts)
	if err != nil {
		return nil, err
	}
	registry, err := discovery.NewRegistry(filepath.Join(cfg.Node.DataDir, "registry.json"))
	if err != nil {
		return nil, err
	}
	guardedCtx, err := c.guardedPeerContext(ctx, cfg, id, registry)
	if err != nil {
		return nil, err
	}

	dialer := func(rctx context.Context) (net.Conn, error) {
		if serviceRec.IsHidden {
			conn, err := hidden.DialHiddenServiceWithOptions(rctx, serviceRec, registry, hidden.DialOptions{
				SelfAddr:      cfg.Node.AdvertiseAddr,
				Identity:      id,
				TransportMode: cfg.Node.TransportMode,
			})
			if err != nil {
				return nil, friendlyRelayPathError(err, "hidden-service mode")
			}
			return conn, nil
		}
		if opts.Proxy {
			peers, _ := registry.Snapshot()
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

	runCtx, cancel := context.WithCancel(guardedCtx)
	done := make(chan struct{})
	if cb.OnStarted != nil {
		cb.OnStarted(opts.Listen, opts.Service)
	}
	go func() {
		defer close(done)
		if err := serviceproxy.ServeLocalForward(runCtx, opts.Listen, serviceRec, id, dialer); err != nil && runCtx.Err() == nil {
			if cb.OnError != nil {
				cb.OnError(err)
			}
		}
		if cb.OnStopped != nil {
			cb.OnStopped()
		}
	}()
	return &ForwarderHandle{cancel: cancel, done: done}, nil
}

func (c *Client) resolveConnectTarget(ctx context.Context, cfg config.File, requestService string, opts ConnectOptions) (record.ServiceRecord, error) {
	if opts.Addr != "" {
		if err := transfer.ValidateIPv6Address(opts.Addr); err != nil {
			return record.ServiceRecord{}, err
		}
		return record.ServiceRecord{
			NodeName:    "direct",
			ServiceName: requestService,
			Address:     opts.Addr,
		}, nil
	}
	rec, err := c.ResolveService(ctx, opts.Service)
	if err != nil {
		return record.ServiceRecord{}, fmt.Errorf("resolve service %q: %w", opts.Service, err)
	}
	return rec, nil
}

func requestedServiceName(input string) string {
	if !strings.Contains(input, ".") {
		return input
	}
	parts := strings.Split(input, ".")
	return parts[len(parts)-1]
}

func friendlyRelayPathError(err error, feature string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not enough peers in registry to build a"):
		return fmt.Errorf("%s requires more reachable VX6 nodes", feature)
	case strings.Contains(msg, "hidden service has no reachable introduction points"),
		strings.Contains(msg, "no rendezvous candidates available"),
		strings.Contains(msg, "failed to establish hidden-service circuit"),
		strings.Contains(msg, "no reachable guard or owner for hidden service"):
		return fmt.Errorf("%s requires more reachable VX6 nodes", feature)
	default:
		return err
	}
}
