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

	"github.com/vx6/vx6/internal/config"
	"github.com/vx6/vx6/sdk"
)

type appState struct {
	mu           sync.Mutex
	client       *sdk.Client
	started      bool
	cancel       context.CancelFunc
	catalog      sdk.ShareCatalog
	peers        map[string]sdk.PeerInvite
	sendProgress map[string]progress
	downloadPath string
}

type progress struct {
	Sent  int64 `json:"sent"`
	Total int64 `json:"total"`
}

func main() {
	client, err := sdk.New("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "vx6share:", err)
		os.Exit(1)
	}
	state := &appState{
		client:       client,
		peers:        map[string]sdk.PeerInvite{},
		sendProgress: map[string]progress{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", state.ui)
	mux.HandleFunc("/api/init", state.apiInit)
	mux.HandleFunc("/api/start", state.apiStart)
	mux.HandleFunc("/api/stop", state.apiStop)
	mux.HandleFunc("/api/invite", state.apiInvite)
	mux.HandleFunc("/api/peer/add", state.apiAddPeer)
	mux.HandleFunc("/api/peer/list", state.apiListPeers)
	mux.HandleFunc("/api/share/add", state.apiAddShare)
	mux.HandleFunc("/api/share/list", state.apiListShares)
	mux.HandleFunc("/api/share/fetch", state.apiFetchShares)
	mux.HandleFunc("/api/send", state.apiSend)
	mux.HandleFunc("/api/progress", state.apiProgress)
	mux.HandleFunc("/api/status", state.apiStatus)

	addr := "127.0.0.1:17990"
	go openBrowser("http://" + addr)
	fmt.Printf("vx6share UI: http://%s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func (s *appState) apiInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		Nickname string `json:"nickname"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad json"})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := s.client.Init(ctx, sdk.InitOptions{
		Name:            strings.TrimSpace(req.Nickname),
		FileReceiveMode: config.FileReceiveOpen,
	})
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	cfg, _ := config.NewStore(s.client.ConfigPath())
	if c, err := cfg.Load(); err == nil {
		s.mu.Lock()
		s.downloadPath = c.Node.DownloadDir
		s.mu.Unlock()
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *appState) apiStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{"ok": true, "running": true})
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.started = true
	s.mu.Unlock()

	go func() {
		_ = s.client.StartNode(ctx, os.Stdout, sdk.StartOptions{})
		s.mu.Lock()
		s.started = false
		s.cancel = nil
		s.mu.Unlock()
	}()
	writeJSON(w, 200, map[string]any{"ok": true, "running": true})
}

func (s *appState) apiStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *appState) apiInvite(w http.ResponseWriter, r *http.Request) {
	inv, link, err := s.client.BuildInvite()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"invite": inv, "link": link})
}

func (s *appState) apiAddPeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		Link string `json:"link"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad json"})
		return
	}
	inv, err := sdk.DecodeInvite(req.Link)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.mu.Lock()
	s.peers[inv.NodeID] = inv
	s.mu.Unlock()
	_ = s.client.AddPeer(inv.NodeName, inv.Address)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *appState) apiListPeers(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]sdk.PeerInvite, 0, len(s.peers))
	for _, p := range s.peers {
		out = append(out, p)
	}
	writeJSON(w, 200, map[string]any{"peers": out})
}

func (s *appState) apiAddShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		Path string `json:"path"`
		Desc string `json:"desc"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad json"})
		return
	}
	f, err := sdk.BuildSharedFile(req.Path, req.Desc)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	inv, _, err := s.client.BuildInvite()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.mu.Lock()
	s.catalog.NodeID = inv.NodeID
	s.catalog.NodeName = inv.NodeName
	s.catalog.Address = inv.Address
	s.catalog.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	s.catalog.Files = upsertFile(s.catalog.Files, f)
	cat := s.catalog
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := s.client.PublishCatalog(ctx, cat); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "file": f})
}

func (s *appState) apiListShares(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"catalog": s.catalog})
}

func (s *appState) apiFetchShares(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad json"})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cat, err := s.client.FetchCatalog(ctx, req.NodeID)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"catalog": cat})
}

func (s *appState) apiSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
		Path   string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad json"})
		return
	}
	s.mu.Lock()
	peer, ok := s.peers[req.NodeID]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "peer not found"})
		return
	}
	xid := fmt.Sprintf("%d", time.Now().UnixNano())
	s.mu.Lock()
	s.sendProgress[xid] = progress{}
	s.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		defer cancel()
		_ = s.client.SendFileWithProgress(ctx, peer.Address, req.Path, func(sent, total int64) {
			s.mu.Lock()
			s.sendProgress[xid] = progress{Sent: sent, Total: total}
			s.mu.Unlock()
		})
	}()
	writeJSON(w, 200, map[string]any{"ok": true, "transfer_id": xid})
}

func (s *appState) apiProgress(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s.mu.Lock()
	p := s.sendProgress[id]
	s.mu.Unlock()
	writeJSON(w, 200, p)
}

func (s *appState) apiStatus(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	running := s.started
	downloadPath := s.downloadPath
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"running": running, "download_path": downloadPath})
}

func upsertFile(in []sdk.SharedFile, f sdk.SharedFile) []sdk.SharedFile {
	for i := range in {
		if in[i].ID == f.ID {
			in[i] = f
			return in
		}
	}
	return append(in, f)
}

func (s *appState) ui(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(uiHTML))
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
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

const uiHTML = `<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VX6Share</title><style>
body{font-family:ui-sans-serif,system-ui;background:#eef3ff;margin:0;color:#0f1d33}
.wrap{max-width:1200px;margin:20px auto;padding:0 14px}.card{background:#fff;border-radius:14px;padding:14px;box-shadow:0 10px 20px rgba(15,29,51,.08);margin-bottom:12px}
.row{display:flex;gap:8px;flex-wrap:wrap}input,textarea{width:100%;padding:10px;border:1px solid #cfdbef;border-radius:10px;box-sizing:border-box}
button{padding:10px 12px;border:0;border-radius:10px;background:#0a6cff;color:#fff;font-weight:600;cursor:pointer}.sub{background:#eaf1ff;color:#1b2c44}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:950px){.grid{grid-template-columns:1fr}}pre{background:#0e1728;color:#d5e4ff;padding:10px;border-radius:10px;white-space:pre-wrap}
</style></head><body><div class="wrap">
<div class="card"><h2>VX6Share</h2><div>Decentralized file sharing over VX6 SDK</div></div>
<div class="grid">
<div>
<div class="card"><h3>1) First Init</h3><input id="nick" placeholder="Nickname"/><div class="row"><button onclick="init()">Init</button><button class="sub" onclick="start()">Start Node</button><button class="sub" onclick="stop()">Stop Node</button></div><div id="status"></div></div>
<div class="card"><h3>2) My Invite Link</h3><div class="row"><button onclick="invite()">Generate</button></div><textarea id="invite" rows="3"></textarea></div>
<div class="card"><h3>3) Add Peer</h3><textarea id="peerlink" rows="3" placeholder="Paste vx6share://peer/..."></textarea><div class="row"><button onclick="addPeer()">Add Peer</button><button class="sub" onclick="listPeers()">Refresh Peers</button></div><pre id="peers"></pre></div>
</div>
<div>
<div class="card"><h3>4) Share File Metadata (Ledger)</h3><input id="filepath" placeholder="/path/to/file"/><textarea id="filedesc" placeholder="short description"></textarea><div class="row"><button onclick="addShare()">Add + Publish</button><button class="sub" onclick="myShares()">My Catalog</button></div><pre id="catalog"></pre></div>
<div class="card"><h3>5) Fetch Peer Catalog</h3><input id="fetchNode" placeholder="Peer Node ID"/><div class="row"><button onclick="fetchCatalog()">Fetch</button></div><pre id="peercat"></pre></div>
<div class="card"><h3>6) Send File Directly</h3><input id="sendNode" placeholder="Peer Node ID"/><input id="sendPath" placeholder="/path/to/file"/><div class="row"><button onclick="sendFile()">Send</button></div><pre id="progress"></pre></div>
</div></div></div>
<script>
async function api(u,m='GET',b){const r=await fetch(u,{method:m,headers:{'content-type':'application/json'},body:b?JSON.stringify(b):undefined});return await r.json();}
async function init(){const d=await api('/api/init','POST',{nickname:document.getElementById('nick').value});document.getElementById('status').textContent=JSON.stringify(d);}
async function start(){document.getElementById('status').textContent=JSON.stringify(await api('/api/start','POST'));}
async function stop(){document.getElementById('status').textContent=JSON.stringify(await api('/api/stop','POST'));}
async function invite(){const d=await api('/api/invite');document.getElementById('invite').value=d.link||d.error;}
async function addPeer(){document.getElementById('status').textContent=JSON.stringify(await api('/api/peer/add','POST',{link:document.getElementById('peerlink').value}));await listPeers();}
async function listPeers(){document.getElementById('peers').textContent=JSON.stringify(await api('/api/peer/list'),null,2);}
async function addShare(){document.getElementById('status').textContent=JSON.stringify(await api('/api/share/add','POST',{path:document.getElementById('filepath').value,desc:document.getElementById('filedesc').value}),null,2);}
async function myShares(){document.getElementById('catalog').textContent=JSON.stringify(await api('/api/share/list'),null,2);}
async function fetchCatalog(){document.getElementById('peercat').textContent=JSON.stringify(await api('/api/share/fetch','POST',{node_id:document.getElementById('fetchNode').value}),null,2);}
async function sendFile(){const d=await api('/api/send','POST',{node_id:document.getElementById('sendNode').value,path:document.getElementById('sendPath').value});if(!d.transfer_id){document.getElementById('progress').textContent=JSON.stringify(d,null,2);return;}const id=d.transfer_id;const t=setInterval(async()=>{const p=await api('/api/progress?id='+encodeURIComponent(id));document.getElementById('progress').textContent=JSON.stringify(p,null,2);if((p.total||0)>0&&(p.sent||0)>=p.total){clearInterval(t);}},800);}
setInterval(async()=>{const s=await api('/api/status');document.getElementById('status').textContent='running='+s.running+' downloads='+ (s.download_path||'');},2500);
</script></body></html>`
