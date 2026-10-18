package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type app struct {
	mu   sync.Mutex
	node *exec.Cmd
}

type apiResponse struct {
	OK     bool   `json:"ok"`
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

type initRequest struct {
	Name   string `json:"name"`
	Listen string `json:"listen"`
	Peer   string `json:"peer"`
}

type execRequest struct {
	Args []string `json:"args"`
}

type sendRequest struct {
	To   string `json:"to"`
	Text string `json:"text"`
}

func main() {
	listen := flag.String("listen", "127.0.0.1:4866", "vx6d listen address")
	flag.Parse()

	a := &app{}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/v1/node/init", a.handleNodeInit)
	mux.HandleFunc("/v1/node/start", a.handleNodeStart)
	mux.HandleFunc("/v1/node/stop", a.handleNodeStop)
	mux.HandleFunc("/v1/node/status", a.handleNodeStatus)
	mux.HandleFunc("/v1/vx6/exec", a.handleExec)
	mux.HandleFunc("/v1/chat/send", a.handleChatSend)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           withJSON(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Printf("vx6d listening on http://%s\n", *listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "vx6d: %v\n", err)
		os.Exit(1)
	}
}

func withJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, resp apiResponse) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func decodeBody[T any](r *http.Request, out *T) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(out)
}

func (a *app) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Output: "vx6d alive"})
}

func (a *app) handleNodeInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req initRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "name required"})
		return
	}
	listen := strings.TrimSpace(req.Listen)
	if listen == "" {
		listen = "[::]:4242"
	}
	peer := strings.TrimSpace(req.Peer)
	args := []string{"init", "--name", name, "--listen", listen}
	if peer != "" {
		args = append(args, "--peer", peer)
	}
	out, err := runVX6(r.Context(), args...)
	if err == nil {
		writeJSON(w, http.StatusOK, apiResponse{OK: true, Output: out})
		return
	}
	// compatibility fallback for older builds that do not support --peer in init.
	if peer != "" && (strings.Contains(err.Error(), "flag provided but not defined") || strings.Contains(err.Error(), "--peer")) {
		firstOut, firstErr := runVX6(r.Context(), "init", "--name", name, "--listen", listen)
		if firstErr != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Error: firstErr.Error()})
			return
		}
		secondOut, secondErr := runVX6(r.Context(), "peer", "add", "--addr", peer)
		if secondErr != nil {
			writeJSON(w, http.StatusBadRequest, apiResponse{Error: secondErr.Error()})
			return
		}
		writeJSON(w, http.StatusOK, apiResponse{
			OK:     true,
			Output: firstOut + "\n[compat fallback] peer added with `vx6 peer add`\n" + secondOut,
		})
		return
	}
	writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
}

func (a *app) handleNodeStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.node != nil && a.node.Process != nil {
		writeJSON(w, http.StatusOK, apiResponse{OK: true, Output: "node already running"})
		return
	}
	cmd := exec.CommandContext(context.Background(), "vx6", "node")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	a.node = cmd
	go func(c *exec.Cmd) { _ = c.Wait() }(cmd)
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Output: fmt.Sprintf("node started (pid=%d)", cmd.Process.Pid)})
}

func (a *app) handleNodeStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.node == nil || a.node.Process == nil {
		writeJSON(w, http.StatusOK, apiResponse{OK: true, Output: "node not running"})
		return
	}
	err := a.node.Process.Kill()
	a.node = nil
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Output: "node stopped"})
}

func (a *app) handleNodeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	out, err := runVX6(r.Context(), "status")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Output: out})
}

func (a *app) handleExec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req execRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	if len(req.Args) == 0 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "args required"})
		return
	}
	out, err := runVX6(r.Context(), req.Args...)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Output: out})
}

func (a *app) handleChatSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req sendRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	to := strings.TrimSpace(req.To)
	if to == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "to required"})
		return
	}
	content := strings.TrimSpace(req.Text)
	if content == "" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "text required"})
		return
	}
	payload := fmt.Sprintf("VX6-MSG\nfrom=vx6d\ncreated_at=%d\n\n%s", time.Now().Unix(), content)
	file := filepath.Join(os.TempDir(), fmt.Sprintf("vx6-msg-%d.txt", time.Now().UnixNano()))
	if err := os.WriteFile(file, []byte(payload), 0o600); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	defer os.Remove(file)
	out, err := runVX6(r.Context(), "send", "--file", file, "--to", to)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Output: out})
}

func runVX6(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "vx6", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

