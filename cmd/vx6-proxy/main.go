// Copyright (c) 2026 Suryansh Deshwal
// Licensed under the Apache License, Version 2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/vx6/vx6/internal/cli"
	"github.com/vx6/vx6/internal/config"
	"github.com/vx6/vx6/internal/runtimectl"
	"github.com/vx6/vx6/sdk"
)

type app struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
}

type apiResponse struct {
	OK      bool               `json:"ok"`
	Error   string             `json:"error,omitempty"`
	Running bool               `json:"running,omitempty"`
	Status  *runtimectl.Status `json:"status,omitempty"`
	Output  string             `json:"output,omitempty"`
}

func main() {
	a := &app{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", serveUI)
	mux.HandleFunc("/api/start", a.handleStart)
	mux.HandleFunc("/api/stop", a.handleStop)
	mux.HandleFunc("/api/reload", a.handleReload)
	mux.HandleFunc("/api/status", a.handleStatus)
	mux.HandleFunc("/api/cli", a.handleCLI)

	addr := "127.0.0.1:17886"
	go openBrowser("http://" + addr)
	fmt.Printf("vx6-proxy UI: http://%s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "vx6-proxy:", err)
		os.Exit(1)
	}
}

func (a *app) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		writeJSON(w, http.StatusOK, apiResponse{OK: true, Running: true})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.running = true
	a.mu.Unlock()

	client, err := sdk.New("")
	if err != nil {
		a.stopInternal()
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: err.Error()})
		return
	}

	go func() {
		if err := client.StartNode(ctx, os.Stdout, sdk.StartOptions{}); err != nil && ctx.Err() == nil {
			fmt.Fprintln(os.Stderr, "vx6-proxy node:", err)
		}
		a.stopInternal()
	}()
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Running: true})
}

func (a *app) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	a.stopInternal()
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Running: false})
}

func (a *app) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	store, err := config.NewStore("")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: err.Error()})
		return
	}
	controlPath, err := config.RuntimeControlPath(store.Path())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: err.Error()})
		return
	}
	if err := runtimectl.RequestReload(context.Background(), controlPath); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Running: a.isRunning()})
}

func (a *app) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	store, err := config.NewStore("")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: err.Error()})
		return
	}
	controlPath, err := config.RuntimeControlPath(store.Path())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResponse{Error: err.Error()})
		return
	}
	status, err := runtimectl.RequestStatus(context.Background(), controlPath)
	if err != nil {
		writeJSON(w, http.StatusOK, apiResponse{OK: true, Running: a.isRunning()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Running: a.isRunning(), Status: &status})
}

func (a *app) handleCLI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, apiResponse{Error: "method not allowed"})
		return
	}
	var req struct {
		Args string `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "invalid json"})
		return
	}
	args := strings.Fields(strings.TrimSpace(req.Args))
	if len(args) == 0 {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "empty args"})
		return
	}
	if args[0] == "node" {
		writeJSON(w, http.StatusBadRequest, apiResponse{Error: "use Start button for node lifecycle"})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := cli.Run(ctx, args); err != nil {
		writeJSON(w, http.StatusOK, apiResponse{OK: false, Error: err.Error(), Running: a.isRunning()})
		return
	}
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Running: a.isRunning(), Output: "command executed; check terminal output"})
}

func (a *app) stopInternal() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil {
		a.cancel()
		a.cancel = nil
	}
	a.running = false
}

func (a *app) isRunning() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.running
}

func writeJSON(w http.ResponseWriter, status int, payload apiResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func serveUI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(proxyHTML))
}

const proxyHTML = `<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>VX6 Proxy</title>
<style>
:root{--bg:#f5f7fb;--panel:#ffffff;--ink:#132238;--muted:#526176;--accent:#0a7cff;--ok:#107a47;--bad:#b42318}
body{margin:0;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI;background:linear-gradient(180deg,#eef4ff,#f7fafc);color:var(--ink)}
.wrap{max-width:1100px;margin:24px auto;padding:0 16px}
.top{display:flex;gap:12px;align-items:center;justify-content:space-between;background:var(--panel);border-radius:14px;padding:16px;box-shadow:0 8px 24px rgba(17,24,39,.08)}
.title{font-size:24px;font-weight:700}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}
.card{background:var(--panel);border-radius:14px;padding:16px;box-shadow:0 8px 24px rgba(17,24,39,.08)}
.muted{color:var(--muted);font-size:13px}
button{border:0;border-radius:10px;padding:10px 14px;font-weight:600;cursor:pointer}
.btn{background:var(--accent);color:#fff}
.btn2{background:#e8eefc;color:var(--ink)}
.btnBad{background:#fee4e2;color:var(--bad)}
input,textarea{width:100%;box-sizing:border-box;border:1px solid #d0d7e2;border-radius:10px;padding:10px;background:#fff}
textarea{min-height:80px}
.row{display:flex;gap:8px;flex-wrap:wrap}
.stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:8px}
.s{padding:10px;border-radius:10px;background:#f7f9fd}
pre{white-space:pre-wrap;background:#0b1220;color:#dce6ff;padding:10px;border-radius:10px;min-height:90px}
@media (max-width:900px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div>
      <div class="title">VX6 Browser Proxy</div>
      <div class="muted">Minimal launcher + full protocol controls in browser</div>
    </div>
    <div class="row">
      <button class="btn" onclick="startNode()">Start</button>
      <button class="btn2" onclick="reloadNode()">Reload</button>
      <button class="btnBad" onclick="stopNode()">Stop</button>
    </div>
  </div>
  <div class="grid">
    <div class="card">
      <h3>Status</h3>
      <div id="statusLine" class="muted">loading...</div>
      <div class="stats" id="stats"></div>
    </div>
    <div class="card">
      <h3>CLI Control</h3>
      <div class="muted">Run any ` + "`vx6`" + ` command except ` + "`node`" + `. Example: ` + "`service add --name api --target 127.0.0.1:8080`" + `</div>
      <textarea id="cmd"></textarea>
      <div class="row" style="margin-top:8px"><button class="btn" onclick="runCmd()">Run Command</button></div>
      <pre id="out"></pre>
    </div>
  </div>
</div>
<script>
async function api(path, method='GET', body){
  const res = await fetch(path,{method,headers:{'content-type':'application/json'},body:body?JSON.stringify(body):undefined});
  return await res.json();
}
function putStatus(d){
  const s = document.getElementById('statusLine');
  const st = d.status || {};
  s.textContent = d.running ? 'node running' : 'node stopped';
  const pairs = [
    ['Node', st.node_name || '-'],
    ['Advertise', st.advertise_addr || '-'],
    ['Transport', st.transport_active || '-'],
    ['Registry Nodes', st.registry_nodes ?? 0],
    ['Registry Services', st.registry_services ?? 0],
    ['DHT Keys', st.dht_tracked_keys ?? 0],
    ['Hidden Keys', st.hidden_descriptor_keys ?? 0],
    ['Hidden Healthy', st.hidden_descriptor_healthy ?? 0],
    ['Uptime(s)', st.uptime_seconds ?? 0]
  ];
  const el = document.getElementById('stats');
  el.innerHTML = pairs.map(p => '<div class="s"><div class="muted">'+p[0]+'</div><div>'+p[1]+'</div></div>').join('');
}
async function refresh(){ try{ putStatus(await api('/api/status')); }catch(e){} }
async function startNode(){ const d=await api('/api/start','POST'); putStatus(d); }
async function stopNode(){ const d=await api('/api/stop','POST'); putStatus(d); }
async function reloadNode(){ const d=await api('/api/reload','POST'); putStatus(d); document.getElementById('out').textContent=JSON.stringify(d,null,2); }
async function runCmd(){
  const args=document.getElementById('cmd').value.trim();
  const d=await api('/api/cli','POST',{args});
  document.getElementById('out').textContent=JSON.stringify(d,null,2);
  await refresh();
}
setInterval(refresh, 2000); refresh();
</script>
</body></html>`
