package runtimectl

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const requestTimeout = 2 * time.Second

const (
	ActionStatus = "status"
	ActionReload = "reload"
)

type Info struct {
	Addr  string `json:"addr"`
	Token string `json:"token"`
	PID   int    `json:"pid"`
}

type Status struct {
	PID                             int    `json:"pid"`
	NodeName                        string `json:"node_name,omitempty"`
	AdvertiseAddr                   string `json:"advertise_addr,omitempty"`
	EndpointPublish                 string `json:"endpoint_publish,omitempty"`
	TransportConfig                 string `json:"transport_config"`
	TransportActive                 string `json:"transport_active"`
	RelayMode                       string `json:"relay_mode"`
	RelayPercent                    int    `json:"relay_percent"`
	RegistryNodes                   int    `json:"registry_nodes"`
	RegistryServices                int    `json:"registry_services"`
	UptimeSeconds                   int64  `json:"uptime_seconds,omitempty"`
	DHTTrackedKeys                  int    `json:"dht_tracked_keys,omitempty"`
	DHTHealthyKeys                  int    `json:"dht_healthy_keys,omitempty"`
	DHTDegradedKeys                 int    `json:"dht_degraded_keys,omitempty"`
	DHTStaleKeys                    int    `json:"dht_stale_keys,omitempty"`
	HiddenDescriptorKeys            int    `json:"hidden_descriptor_keys,omitempty"`
	HiddenDescriptorHealthy         int    `json:"hidden_descriptor_healthy,omitempty"`
	HiddenDescriptorDegraded        int    `json:"hidden_descriptor_degraded,omitempty"`
	HiddenDescriptorStale           int    `json:"hidden_descriptor_stale,omitempty"`
	DHTRefreshIntervalSeconds       int64  `json:"dht_refresh_interval_seconds,omitempty"`
	HiddenDescriptorRotationSeconds int64  `json:"hidden_descriptor_rotation_seconds,omitempty"`
	HiddenDescriptorOverlapKeys     int    `json:"hidden_descriptor_overlap_keys,omitempty"`
	ASNResolverLoaded               bool   `json:"asn_resolver_loaded,omitempty"`
	ASNResolverSource               string `json:"asn_resolver_source,omitempty"`
	ASNResolverEntries              int    `json:"asn_resolver_entries,omitempty"`
}

type Request struct {
	Token  string `json:"token"`
	Action string `json:"action"`
}

type Response struct {
	OK     bool    `json:"ok"`
	Error  string  `json:"error,omitempty"`
	Status *Status `json:"status,omitempty"`
}

type Server struct {
	infoPath  string
	listener  net.Listener
	token     string
	pid       int
	reloadFn  func() error
	statusFn  func() Status
	closeOnce sync.Once
}

func Start(infoPath string, pid int, reloadFn func() error, statusFn func() Status) (*Server, error) {
	if infoPath == "" {
		return nil, fmt.Errorf("runtime control path is required")
	}
	if reloadFn == nil {
		reloadFn = func() error { return nil }
	}
	if statusFn == nil {
		statusFn = func() Status { return Status{PID: pid} }
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for runtime control: %w", err)
	}
	token, err := newToken()
	if err != nil {
		_ = listener.Close()
		return nil, err
	}

	s := &Server{
		infoPath: infoPath,
		listener: listener,
		token:    token,
		pid:      pid,
		reloadFn: reloadFn,
		statusFn: statusFn,
	}
	if err := s.writeInfoFile(); err != nil {
		_ = listener.Close()
		return nil, err
	}

	go s.serve()
	return s, nil
}

func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.listener != nil {
			err = s.listener.Close()
		}
		_ = os.Remove(s.infoPath)
	})
	return err
}

func RequestStatus(ctx context.Context, infoPath string) (Status, error) {
	var status Status
	resp, err := send(ctx, infoPath, ActionStatus)
	if err != nil {
		return status, err
	}
	if resp.Status == nil {
		return status, fmt.Errorf("runtime control returned no status payload")
	}
	return *resp.Status, nil
}

func RequestReload(ctx context.Context, infoPath string) error {
	_, err := send(ctx, infoPath, ActionReload)
	return err
}

func send(ctx context.Context, infoPath, action string) (Response, error) {
	var out Response
	info, err := LoadInfo(infoPath)
	if err != nil {
		return out, err
	}

	deadlineCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		deadlineCtx, cancel = context.WithTimeout(ctx, requestTimeout)
		defer cancel()
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(deadlineCtx, "tcp4", info.Addr)
	if err != nil {
		return out, fmt.Errorf("dial runtime control: %w", err)
	}
	defer conn.Close()

	if deadline, ok := deadlineCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if err := json.NewEncoder(conn).Encode(Request{Token: info.Token, Action: action}); err != nil {
		return out, fmt.Errorf("write runtime control request: %w", err)
	}
	if err := json.NewDecoder(conn).Decode(&out); err != nil {
		return out, fmt.Errorf("read runtime control response: %w", err)
	}
	if !out.OK {
		if out.Error == "" {
			out.Error = "runtime control rejected request"
		}
		return out, errors.New(out.Error)
	}
	return out, nil
}

func LoadInfo(infoPath string) (Info, error) {
	data, err := os.ReadFile(infoPath)
	if err != nil {
		return Info{}, fmt.Errorf("read runtime control info: %w", err)
	}
	var info Info
	if err := json.Unmarshal(data, &info); err != nil {
		return Info{}, fmt.Errorf("decode runtime control info: %w", err)
	}
	if info.Addr == "" || info.Token == "" {
		return Info{}, fmt.Errorf("runtime control info is incomplete")
	}
	return info, nil
}

func (s *Server) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || remote == nil || remote.IP == nil || !remote.IP.IsLoopback() {
		_ = json.NewEncoder(conn).Encode(Response{Error: "runtime control only accepts loopback clients"})
		return
	}

	_ = conn.SetDeadline(time.Now().Add(requestTimeout))

	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(Response{Error: "invalid runtime control request"})
		return
	}
	if req.Token != s.token {
		_ = json.NewEncoder(conn).Encode(Response{Error: "runtime control authentication failed"})
		return
	}

	switch req.Action {
	case ActionStatus:
		status := s.statusFn()
		status.PID = s.pid
		_ = json.NewEncoder(conn).Encode(Response{OK: true, Status: &status})
	case ActionReload:
		if err := s.reloadFn(); err != nil {
			_ = json.NewEncoder(conn).Encode(Response{Error: err.Error()})
			return
		}
		_ = json.NewEncoder(conn).Encode(Response{OK: true})
	default:
		_ = json.NewEncoder(conn).Encode(Response{Error: "unknown runtime control action"})
	}
}

func (s *Server) writeInfoFile() error {
	if err := os.MkdirAll(filepath.Dir(s.infoPath), 0o755); err != nil {
		return fmt.Errorf("create runtime control directory: %w", err)
	}
	payload, err := json.MarshalIndent(Info{
		Addr:  s.listener.Addr().String(),
		Token: s.token,
		PID:   s.pid,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode runtime control info: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(s.infoPath, payload, 0o600); err != nil {
		return fmt.Errorf("write runtime control info: %w", err)
	}
	return nil
}

func newToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate runtime control token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
