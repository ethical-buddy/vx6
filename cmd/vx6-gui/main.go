// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type fieldSpec struct {
	Name        string
	Label       string
	Type        string
	Placeholder string
	Help        string
	Default     string
}

type actionSpec struct {
	ID          string
	Title       string
	Description string
	Background  bool
	Fields      []fieldSpec
	BuildArgs   func(url.Values) ([]string, error)
}

type taskInfo struct {
	ID        string
	Title     string
	Args      []string
	StartedAt time.Time
	Status    string
	Output    string
	cancel    context.CancelFunc
	done      chan struct{}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type commandResult struct {
	Title   string
	Args    []string
	Output  string
	Success bool
}

type server struct {
	appName           string
	vx6Bin            string
	mu                sync.Mutex
	last              *commandResult
	tasks             map[string]*taskInfo
	browserConfigPath string
	browserCurrent    string
	browserHistory    []browserEntry
	browserIndex      int
	browserBookmarks  []string
}

type pageData struct {
	AppName string
	VX6Bin  string
	Actions []actionSpec
	Browser browserView
	Last    *commandResult
	Tasks   []*taskInfo
}

var (
	taskCounter uint64
	pageTmpl    = template.Must(template.New("page").Parse(pageHTML))
	actions     = []actionSpec{
		{
			ID:          "init",
			Title:       "Initialize Node",
			Description: "Create or update a VX6 config and identity.",
			Fields: []fieldSpec{
				{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"},
				{Name: "name", Label: "Node Name", Placeholder: "alice"},
				{Name: "listen", Label: "Listen Address", Default: "[::]:4242"},
				{Name: "advertise", Label: "Advertise Address", Placeholder: "[2001:db8::10]:4242"},
				{Name: "peer", Label: "Known Peers", Placeholder: "[2001:db8::1]:4242, [2001:db8::2]:4242"},
				{Name: "hidden_node", Label: "Hide Endpoint Record", Type: "checkbox"},
				{Name: "relay", Label: "Relay Mode", Default: "on"},
				{Name: "relay_percent", Label: "Relay Limit Percent", Default: "33"},
				{Name: "data_dir", Label: "Data Directory", Placeholder: "/path/to/data"},
				{Name: "downloads_dir", Label: "Downloads Directory", Placeholder: "/path/to/downloads"},
			},
			BuildArgs: buildInitArgs,
		},
		{
			ID:          "node",
			Title:       "Run Node",
			Description: "Start a background VX6 node with the current config.",
			Background:  true,
			Fields:      []fieldSpec{{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"}},
			BuildArgs: func(v url.Values) ([]string, error) {
				return []string{"node"}, nil
			},
		},
		{
			ID:          "reload",
			Title:       "Reload Node",
			Description: "Ask the running node to reload config and service state.",
			Fields:      []fieldSpec{{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"}},
			BuildArgs: func(v url.Values) ([]string, error) {
				return []string{"reload"}, nil
			},
		},
		{
			ID:          "status",
			Title:       "Status",
			Description: "Show live runtime status.",
			Fields:      []fieldSpec{{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"}},
			BuildArgs: func(v url.Values) ([]string, error) {
				return []string{"status"}, nil
			},
		},
		{
			ID:          "identity",
			Title:       "Identity",
			Description: "Show the local VX6 identity.",
			Fields:      []fieldSpec{{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"}},
			BuildArgs: func(v url.Values) ([]string, error) {
				return []string{"identity"}, nil
			},
		},
		{
			ID:          "list",
			Title:       "List Services",
			Description: "List discovered public, private, and hidden services.",
			Fields: []fieldSpec{
				{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"},
				{Name: "user", Label: "User Filter", Placeholder: "alice"},
				{Name: "hidden", Label: "Hidden Only", Type: "checkbox"},
			},
			BuildArgs: buildListArgs,
		},
		{
			ID:          "service_list",
			Title:       "Local Services",
			Description: "Show local configured services.",
			Fields:      []fieldSpec{{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"}},
			BuildArgs: func(v url.Values) ([]string, error) {
				return []string{"service"}, nil
			},
		},
		{
			ID:          "peer_list",
			Title:       "Local Peers",
			Description: "Show configured peer aliases.",
			Fields:      []fieldSpec{{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"}},
			BuildArgs: func(v url.Values) ([]string, error) {
				return []string{"peer"}, nil
			},
		},
		{
			ID:          "known_peer_list",
			Title:       "Known Peer List",
			Description: "Show configured known peer addresses.",
			Fields:      []fieldSpec{{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"}},
			BuildArgs: func(v url.Values) ([]string, error) {
				return []string{"peer"}, nil
			},
		},
		{
			ID:          "peer_add",
			Title:       "Add Peer",
			Description: "Add a named peer entry.",
			Fields: []fieldSpec{
				{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"},
				{Name: "name", Label: "Peer Name", Placeholder: "relay01"},
				{Name: "addr", Label: "Peer Address", Placeholder: "[2001:db8::20]:4242"},
			},
			BuildArgs: func(v url.Values) ([]string, error) {
				name := requiredValue(v, "name")
				addr := requiredValue(v, "addr")
				if name == "" || addr == "" {
					return nil, errors.New("peer name and address are required")
				}
				return []string{"peer", "add", "--name", name, "--addr", addr}, nil
			},
		},
		{
			ID:          "known_peer_add",
			Title:       "Add Known Peer",
			Description: "Add a known peer address for startup sync.",
			Fields: []fieldSpec{
				{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"},
				{Name: "addr", Label: "Peer Address", Placeholder: "[2001:db8::1]:4242"},
			},
			BuildArgs: func(v url.Values) ([]string, error) {
				addr := requiredValue(v, "addr")
				if addr == "" {
					return nil, errors.New("peer address is required")
				}
				return []string{"peer", "add", "--addr", addr}, nil
			},
		},
		{
			ID:          "service_add",
			Title:       "Add Service",
			Description: "Publish a service as public, private, or hidden.",
			Fields: []fieldSpec{
				{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"},
				{Name: "name", Label: "Service Name", Placeholder: "web"},
				{Name: "target", Label: "Local Target", Placeholder: "127.0.0.1:8080"},
				{Name: "private", Label: "Private", Type: "checkbox"},
				{Name: "hidden", Label: "Hidden", Type: "checkbox"},
				{Name: "alias", Label: "Hidden Alias", Placeholder: "ghost-admin"},
				{Name: "profile", Label: "Hidden Profile", Default: "fast"},
				{Name: "intro_mode", Label: "Intro Mode", Default: "random"},
				{Name: "intro", Label: "Manual Intros", Placeholder: "nodeA, nodeB"},
			},
			BuildArgs: buildServiceAddArgs,
		},
		{
			ID:          "connect",
			Title:       "Connect Tunnel",
			Description: "Start a local forwarder to a VX6 service.",
			Background:  true,
			Fields: []fieldSpec{
				{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"},
				{Name: "service", Label: "Service", Placeholder: "alice.web or alias#secret"},
				{Name: "listen", Label: "Local Listen", Default: "127.0.0.1:2222"},
				{Name: "addr", Label: "Direct Address", Placeholder: "[2001:db8::10]:4242"},
				{Name: "proxy", Label: "Force Proxy", Type: "checkbox"},
			},
			BuildArgs: buildConnectArgs,
		},
		{
			ID:          "send",
			Title:       "Send File",
			Description: "Send a file to a peer or direct address.",
			Fields: []fieldSpec{
				{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"},
				{Name: "file", Label: "File Path", Placeholder: "/path/to/file"},
				{Name: "to", Label: "Peer Name", Placeholder: "bob"},
				{Name: "addr", Label: "Direct Address", Placeholder: "[2001:db8::10]:4242"},
				{Name: "proxy", Label: "Force Proxy", Type: "checkbox"},
			},
			BuildArgs: buildSendArgs,
		},
		{
			ID:          "receive",
			Title:       "Receive Policy",
			Description: "Change or inspect local file receive permissions.",
			Fields: []fieldSpec{
				{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"},
				{Name: "mode", Label: "Mode", Default: "status", Help: "status, allow-all, allow-node, deny-node, disable"},
				{Name: "node", Label: "Node Name", Placeholder: "alice"},
			},
			BuildArgs: buildReceiveArgs,
		},
		{
			ID:          "dht_get",
			Title:       "DHT Lookup",
			Description: "Query the DHT for a service, node, or raw key.",
			Fields: []fieldSpec{
				{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"},
				{Name: "service", Label: "Service", Placeholder: "alice.web"},
				{Name: "node", Label: "Node Name", Placeholder: "alice"},
				{Name: "node_id", Label: "Node ID", Placeholder: "abcd1234"},
				{Name: "key", Label: "Raw Key", Placeholder: "service/alice.web"},
			},
			BuildArgs: buildDHTGetArgs,
		},
		{
			ID:          "dht_status",
			Title:       "DHT Status",
			Description: "Show tracked DHT publish and hidden descriptor health.",
			Fields:      []fieldSpec{{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"}},
			BuildArgs: func(v url.Values) ([]string, error) {
				return []string{"debug", "dht-status"}, nil
			},
		},
		{
			ID:          "registry_debug",
			Title:       "Registry Debug",
			Description: "Show the local registry view without raw endpoint leakage.",
			Fields:      []fieldSpec{{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"}},
			BuildArgs: func(v url.Values) ([]string, error) {
				return []string{"debug", "registry"}, nil
			},
		},
		{
			ID:          "ebpf_status",
			Title:       "eBPF Status",
			Description: "Check Linux XDP/eBPF status reporting.",
			Fields: []fieldSpec{
				{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"},
				{Name: "iface", Label: "Interface", Placeholder: "eth0"},
			},
			BuildArgs: func(v url.Values) ([]string, error) {
				args := []string{"debug", "ebpf-status"}
				if iface := strings.TrimSpace(v.Get("iface")); iface != "" {
					args = append(args, "--iface", iface)
				}
				return args, nil
			},
		},
		{
			ID:          "custom",
			Title:       "Custom CLI Args",
			Description: "Run any extra VX6 command through the GUI shell.",
			Fields: []fieldSpec{
				{Name: "config_path", Label: "Config Path", Placeholder: "/path/to/config.json"},
				{Name: "args", Label: "Arguments", Placeholder: "service add --name web --target 127.0.0.1:8080"},
			},
			BuildArgs: func(v url.Values) ([]string, error) {
				raw := strings.TrimSpace(v.Get("args"))
				if raw == "" {
					return nil, errors.New("arguments are required")
				}
				return strings.Fields(raw), nil
			},
		},
	}
)

func main() {
	vx6Bin := detectVX6Binary()
	if len(os.Args) > 1 && strings.TrimSpace(os.Args[1]) != "" {
		vx6Bin = os.Args[1]
	}

	srv := &server{
		appName: appDisplayName(),
		vx6Bin:  vx6Bin,
		tasks:   map[string]*taskInfo{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/browser", srv.handleBrowser)
	mux.HandleFunc("/run", srv.handleRun)
	mux.HandleFunc("/stop", srv.handleStop)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s listen failed: %v\n", appBinaryName(), err)
		os.Exit(1)
	}
	url := "http://" + ln.Addr().String()
	fmt.Printf("%s\t%s\n", appBinaryName(), url)
	go func() {
		_ = openBrowser(url)
	}()
	if err := http.Serve(ln, mux); err != nil {
		fmt.Fprintf(os.Stderr, "%s server stopped: %v\n", appBinaryName(), err)
		os.Exit(1)
	}
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tasks := make([]*taskInfo, 0, len(s.tasks))
	for _, task := range s.tasks {
		cp := *task
		cp.cancel = nil
		cp.done = nil
		tasks = append(tasks, &cp)
	}
	sort.SliceStable(tasks, func(i, j int) bool {
		return tasks[i].StartedAt.After(tasks[j].StartedAt)
	})

	data := pageData{
		AppName: s.appName,
		VX6Bin:  s.vx6Bin,
		Actions: availableActions(),
		Browser: s.browserSnapshot(),
		Last:    s.last,
		Tasks:   tasks,
	}
	_ = pageTmpl.Execute(w, data)
}

func (s *server) handleRun(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	spec, ok := actionByID(r.Form.Get("action_id"))
	if !ok {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	args, err := spec.BuildArgs(r.Form)
	if err != nil {
		s.setLast(spec.Title, nil, err.Error(), false)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	configPath := strings.TrimSpace(r.Form.Get("config_path"))
	if spec.Background {
		if err := s.startTask(spec.Title, configPath, args); err != nil {
			s.setLast(spec.Title, args, err.Error(), false)
		}
	} else {
		out, err := s.runNow(configPath, args)
		s.setLast(spec.Title, args, out, err == nil)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) handleBrowser(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	switch strings.TrimSpace(r.Form.Get("op")) {
	case "open":
		target := strings.TrimSpace(r.Form.Get("target"))
		configPath := strings.TrimSpace(r.Form.Get("config_path"))
		if err := s.navigateBrowser(configPath, target); err != nil {
			s.setLast("VX6 Browser", nil, err.Error(), false)
		}
	case "back":
		if !s.browserBack() {
			s.setLast("VX6 Browser", nil, "no previous browser page", false)
		}
	case "forward":
		if !s.browserForward() {
			s.setLast("VX6 Browser", nil, "no forward browser page", false)
		}
	case "bookmark":
		if !s.bookmarkBrowserTarget() {
			s.setLast("VX6 Browser", nil, "no browser page to bookmark", false)
		}
	default:
		s.setLast("VX6 Browser", nil, "unknown browser action", false)
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) handleStop(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.Form.Get("id"))
	s.mu.Lock()
	task, ok := s.tasks[id]
	s.mu.Unlock()
	if ok && task.cancel != nil {
		task.cancel()
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) runNow(configPath string, args []string) (string, error) {
	cmd := exec.Command(s.vx6Bin, args...)
	cmd.Env = append(os.Environ(), configEnv(configPath)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out) + "\n" + err.Error(), err
	}
	return string(out), nil
}

func (s *server) startTask(title, configPath string, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, s.vx6Bin, args...)
	cmd.Env = append(os.Environ(), configEnv(configPath)...)
	var buf lockedBuffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	id := fmt.Sprintf("task-%d", atomic.AddUint64(&taskCounter, 1))
	task := &taskInfo{
		ID:        id,
		Title:     title,
		Args:      append([]string(nil), args...),
		StartedAt: time.Now(),
		Status:    "starting",
		cancel:    cancel,
		done:      make(chan struct{}),
	}

	s.mu.Lock()
	s.tasks[id] = task
	s.mu.Unlock()

	if err := cmd.Start(); err != nil {
		cancel()
		s.mu.Lock()
		delete(s.tasks, id)
		s.mu.Unlock()
		return err
	}

	go func() {
		defer close(task.done)
		err := cmd.Wait()
		s.mu.Lock()
		defer s.mu.Unlock()
		task.Output = trimOutput(buf.String())
		if err != nil {
			task.Status = "failed"
			if task.Output == "" {
				task.Output = err.Error()
			} else {
				task.Output += "\n" + err.Error()
			}
		} else if ctx.Err() != nil {
			task.Status = "stopped"
		} else {
			task.Status = "completed"
		}
	}()

	s.mu.Lock()
	task.Status = "running"
	s.mu.Unlock()
	return nil
}

func (s *server) setLast(title string, args []string, output string, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = &commandResult{
		Title:   title,
		Args:    append([]string(nil), args...),
		Output:  trimOutput(output),
		Success: success,
	}
}

func actionByID(id string) (actionSpec, bool) {
	for _, spec := range availableActions() {
		if spec.ID == id {
			return spec, true
		}
	}
	return actionSpec{}, false
}

func buildInitArgs(v url.Values) ([]string, error) {
	name := requiredValue(v, "name")
	if name == "" {
		return nil, errors.New("node name is required")
	}
	args := []string{"init", "--name", name}
	appendFlagValue(&args, "--listen", v.Get("listen"))
	appendFlagValue(&args, "--advertise", v.Get("advertise"))
	for _, addr := range splitCSV(v.Get("peer")) {
		args = append(args, "--peer", addr)
	}
	if isChecked(v, "hidden_node") {
		args = append(args, "--hidden-node")
	}
	appendFlagValue(&args, "--relay", v.Get("relay"))
	appendFlagValue(&args, "--relay-percent", v.Get("relay_percent"))
	appendFlagValue(&args, "--data-dir", v.Get("data_dir"))
	appendFlagValue(&args, "--downloads-dir", v.Get("downloads_dir"))
	return args, nil
}

func buildListArgs(v url.Values) ([]string, error) {
	args := []string{"list"}
	appendFlagValue(&args, "--user", v.Get("user"))
	if isChecked(v, "hidden") {
		args = append(args, "--hidden")
	}
	return args, nil
}

func buildServiceAddArgs(v url.Values) ([]string, error) {
	name := requiredValue(v, "name")
	target := requiredValue(v, "target")
	if name == "" || target == "" {
		return nil, errors.New("service name and target are required")
	}
	if isChecked(v, "hidden") && isChecked(v, "private") {
		return nil, errors.New("service cannot be both hidden and private")
	}
	args := []string{"service", "add", "--name", name, "--target", target}
	if isChecked(v, "private") {
		args = append(args, "--private")
	}
	if isChecked(v, "hidden") {
		args = append(args, "--hidden")
		appendFlagValue(&args, "--alias", v.Get("alias"))
		appendFlagValue(&args, "--profile", v.Get("profile"))
		appendFlagValue(&args, "--intro-mode", v.Get("intro_mode"))
		for _, intro := range splitCSV(v.Get("intro")) {
			args = append(args, "--intro", intro)
		}
	}
	return args, nil
}

func buildConnectArgs(v url.Values) ([]string, error) {
	service := requiredValue(v, "service")
	if service == "" {
		return nil, errors.New("service is required")
	}
	args := []string{"connect", "--service", service}
	appendFlagValue(&args, "--listen", v.Get("listen"))
	appendFlagValue(&args, "--addr", v.Get("addr"))
	if isChecked(v, "proxy") {
		args = append(args, "--proxy")
	}
	return args, nil
}

func buildSendArgs(v url.Values) ([]string, error) {
	file := requiredValue(v, "file")
	to := strings.TrimSpace(v.Get("to"))
	addr := strings.TrimSpace(v.Get("addr"))
	if file == "" {
		return nil, errors.New("file path is required")
	}
	if to == "" && addr == "" {
		return nil, errors.New("either peer name or direct address is required")
	}
	args := []string{"send", "--file", file}
	if to != "" {
		args = append(args, "--to", to)
	}
	if addr != "" {
		args = append(args, "--addr", addr)
	}
	if isChecked(v, "proxy") {
		args = append(args, "--proxy")
	}
	return args, nil
}

func buildReceiveArgs(v url.Values) ([]string, error) {
	mode := strings.TrimSpace(v.Get("mode"))
	node := strings.TrimSpace(v.Get("node"))
	switch mode {
	case "", "status":
		return []string{"receive", "status"}, nil
	case "allow-all":
		return []string{"receive", "allow", "--all"}, nil
	case "allow-node":
		if node == "" {
			return nil, errors.New("node name is required for allow-node")
		}
		return []string{"receive", "allow", "--node", node}, nil
	case "deny-node":
		if node == "" {
			return nil, errors.New("node name is required for deny-node")
		}
		return []string{"receive", "deny", "--node", node}, nil
	case "disable":
		return []string{"receive", "disable"}, nil
	default:
		return nil, errors.New("unknown receive mode")
	}
}

func buildDHTGetArgs(v url.Values) ([]string, error) {
	args := []string{"debug", "dht-get"}
	switch {
	case strings.TrimSpace(v.Get("service")) != "":
		args = append(args, "--service", strings.TrimSpace(v.Get("service")))
	case strings.TrimSpace(v.Get("node")) != "":
		args = append(args, "--node", strings.TrimSpace(v.Get("node")))
	case strings.TrimSpace(v.Get("node_id")) != "":
		args = append(args, "--node-id", strings.TrimSpace(v.Get("node_id")))
	case strings.TrimSpace(v.Get("key")) != "":
		args = append(args, "--key", strings.TrimSpace(v.Get("key")))
	default:
		return nil, errors.New("one DHT lookup selector is required")
	}
	return args, nil
}

func requiredValue(v url.Values, key string) string {
	return strings.TrimSpace(v.Get(key))
}

func appendFlagValue(args *[]string, flag, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	*args = append(*args, flag, value)
}

func splitCSV(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func isChecked(v url.Values, key string) bool {
	return v.Get(key) == "on"
}

func configEnv(configPath string) []string {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return nil
	}
	return []string{"VX6_CONFIG_PATH=" + configPath}
}

func detectVX6Binary() string {
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		candidates := []string{
			filepath.Join(dir, "vx6"),
			filepath.Join(dir, "vx6.exe"),
		}
		for _, candidate := range candidates {
			if fileInfo, err := os.Stat(candidate); err == nil && !fileInfo.IsDir() {
				return candidate
			}
		}
	}
	if runtime.GOOS == "windows" {
		return "vx6.exe"
	}
	return "vx6"
}

func appDisplayName() string {
	base := strings.ToLower(filepath.Base(os.Args[0]))
	if strings.Contains(base, "browser") {
		return "VX6 Browser"
	}
	return "VX6 GUI"
}

func appBinaryName() string {
	base := strings.TrimSpace(filepath.Base(os.Args[0]))
	if base == "" {
		return "vx6-gui"
	}
	return base
}

func availableActions() []actionSpec {
	if runtime.GOOS == "linux" {
		return actions
	}
	filtered := make([]actionSpec, 0, len(actions))
	for _, action := range actions {
		if action.ID == "ebpf_status" {
			continue
		}
		filtered = append(filtered, action)
	}
	return filtered
}

func openBrowser(target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	case "darwin":
		cmd = exec.Command("open", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	return cmd.Start()
}

func trimOutput(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(no output)"
	}
	return s
}

const pageHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.AppName}}</title>
  <style>
    :root { color-scheme: light; --bg:#f6f5ef; --fg:#1d1d1b; --muted:#5f5a53; --panel:#fffdfa; --line:#ddd4c7; --accent:#0f766e; --warn:#9a3412; }
    body { margin:0; font-family: ui-sans-serif, system-ui, sans-serif; background:linear-gradient(180deg,#f8f5ee 0%,#efe8da 100%); color:var(--fg); }
    header { padding:24px 28px 12px; border-bottom:1px solid var(--line); background:rgba(255,253,250,0.92); position:sticky; top:0; backdrop-filter: blur(6px); }
    h1,h2,h3 { margin:0 0 8px; }
    p, label, input, textarea, button { font-size:14px; }
    main { padding:24px 28px 56px; display:grid; gap:20px; }
    .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap:18px; }
    .card { background:var(--panel); border:1px solid var(--line); border-radius:16px; padding:18px; box-shadow:0 8px 24px rgba(61,43,21,0.06); }
    .muted { color:var(--muted); }
    .toolbar { display:grid; gap:10px; }
    .toolbar-row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
    .toolbar-row input[type="text"] { flex:1 1 320px; }
    .chip { display:inline-flex; align-items:center; gap:6px; padding:6px 10px; border:1px solid var(--line); border-radius:999px; background:#fff; }
    .result.ok { border-left:4px solid var(--accent); }
    .result.bad { border-left:4px solid var(--warn); }
    form { display:grid; gap:10px; }
    .field { display:grid; gap:4px; }
    .inline { display:flex; gap:10px; align-items:center; }
    input[type="text"], textarea { width:100%; box-sizing:border-box; padding:10px 12px; border:1px solid var(--line); border-radius:10px; background:white; }
    textarea { min-height:140px; font-family: ui-monospace, SFMono-Regular, monospace; }
    button { border:0; border-radius:999px; padding:10px 14px; background:var(--accent); color:white; cursor:pointer; }
    button.stop { background:var(--warn); }
    pre { margin:0; white-space:pre-wrap; word-break:break-word; font-size:13px; background:#f3efe6; padding:12px; border-radius:12px; }
    .task { display:grid; gap:8px; padding:12px; border:1px solid var(--line); border-radius:12px; background:#fcfaf4; }
  </style>
</head>
<body>
  <header>
    <h1>{{.AppName}}</h1>
    <p class="muted">Local front-end for the current <code>vx6</code> binary. Stable transport is TCP. Hidden services, DHT, and node control use the same CLI behavior underneath.</p>
    <p class="muted">CLI binary: <code>{{.VX6Bin}}</code></p>
  </header>
  <main>
    <section class="card">
      <h2>Browser</h2>
      <form class="toolbar" method="post" action="/browser">
        <div class="toolbar-row">
          <input type="text" name="config_path" value="{{.Browser.ConfigPath}}" placeholder="Config Path (optional)">
          <input type="text" name="target" value="{{.Browser.CurrentTarget}}" placeholder="vx6://status">
          <button type="submit" name="op" value="open">Open</button>
          <button type="submit" name="op" value="back">Back</button>
          <button type="submit" name="op" value="forward">Forward</button>
          <button type="submit" name="op" value="bookmark">Bookmark</button>
        </div>
      </form>
      <p class="muted">VX6 pages: <code>vx6://status</code>, <code>vx6://dht</code>, <code>vx6://registry</code>, <code>vx6://services</code>, <code>vx6://peers</code>, <code>vx6://identity</code>, <code>vx6://service/alice.web</code>, <code>vx6://node/alice</code>, <code>vx6://key/service/alice.web</code></p>
      {{if .Browser.CurrentTitle}}
      <div class="inline">
        <span class="chip"><strong>Current</strong> <code>{{.Browser.CurrentTarget}}</code></span>
        <span class="muted">{{.Browser.CurrentTitle}}</span>
      </div>
      {{end}}
      {{if .Browser.Bookmarks}}
      <div>
        <p class="muted">Bookmarks</p>
        <div class="toolbar-row">
          {{range .Browser.Bookmarks}}
          <form method="post" action="/browser">
            <input type="hidden" name="op" value="open">
            <input type="hidden" name="target" value="{{.}}">
            <button type="submit">{{.}}</button>
          </form>
          {{end}}
        </div>
      </div>
      {{end}}
      {{if .Browser.History}}
      <div>
        <p class="muted">History</p>
        <div class="grid">
          {{range .Browser.History}}
          <div class="task">
            <div class="inline"><strong>{{.Title}}</strong><span class="muted">{{if .Success}}ok{{else}}failed{{end}}</span></div>
            <div class="muted"><code>{{.Target}}</code></div>
          </div>
          {{end}}
        </div>
      </div>
      {{end}}
    </section>

    {{if .Last}}
    <section class="card result {{if .Last.Success}}ok{{else}}bad{{end}}">
      <h2>Last Page</h2>
      <p><strong>{{.Last.Title}}</strong></p>
      <p class="muted"><code>{{range .Last.Args}}{{.}} {{end}}</code></p>
      <pre>{{.Last.Output}}</pre>
    </section>
    {{end}}

    {{if .Tasks}}
    <section class="card">
      <h2>Background Tasks</h2>
      <div class="grid">
      {{range .Tasks}}
        <div class="task">
          <div class="inline"><strong>{{.Title}}</strong><span class="muted">{{.Status}}</span></div>
          <div class="muted"><code>{{range .Args}}{{.}} {{end}}</code></div>
          <form method="post" action="/stop">
            <input type="hidden" name="id" value="{{.ID}}">
            <button class="stop" type="submit">Stop</button>
          </form>
          <pre>{{.Output}}</pre>
        </div>
      {{end}}
      </div>
    </section>
    {{end}}

    <section class="grid">
      {{range .Actions}}
      <div class="card">
        <h3>{{.Title}}</h3>
        <p class="muted">{{.Description}}</p>
        <form method="post" action="/run">
          <input type="hidden" name="action_id" value="{{.ID}}">
          {{range .Fields}}
          <div class="field">
            <label for="{{.Name}}">{{.Label}}</label>
            {{if eq .Type "checkbox"}}
            <div class="inline"><input id="{{.Name}}" type="checkbox" name="{{.Name}}"><span class="muted">{{.Help}}</span></div>
            {{else}}
            <input id="{{.Name}}" type="text" name="{{.Name}}" value="{{.Default}}" placeholder="{{.Placeholder}}">
            {{if .Help}}<span class="muted">{{.Help}}</span>{{end}}
            {{end}}
          </div>
          {{end}}
          <button type="submit">{{if .Background}}Start{{else}}Run{{end}}</button>
        </form>
      </div>
      {{end}}
    </section>
  </main>
</body>
</html>`
