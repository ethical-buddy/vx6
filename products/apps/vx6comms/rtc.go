package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3"
)

type rtcSignal struct {
	Version   int    `json:"version"`
	FromID    string `json:"from_id"`
	ToID      string `json:"to_id"`
	Type      string `json:"type"` // offer|answer|candidate|hangup
	SDP       string `json:"sdp,omitempty"`
	Candidate string `json:"candidate,omitempty"`
	MID       string `json:"mid,omitempty"`
	MLine     uint16 `json:"mline,omitempty"`
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
}

type rtcSession struct {
	mu        sync.Mutex
	peerID    string
	pc        *webrtc.PeerConnection
	videoSSRC uint32
	audioSSRC uint32
	videoKbps int
	lastTune  time.Time
	ffmpegCmd *exec.Cmd
	stop      context.CancelFunc
	lastSigID string
}

func rtcKey(nodeID string) string {
	return "vx6chat/rtc/" + nodeID
}

func (s *state) ensureRTCSession(peer peerContact) (*rtcSession, error) {
	s.mu.Lock()
	if s.local.ActiveGroups == nil {
		s.local.ActiveGroups = map[string]groupRoom{}
	}
	s.mu.Unlock()

	if srt, ok := s.rtcLoad(peer.NodeID); ok {
		return srt, nil
	}

	pcCfg := webrtc.Configuration{}
	turnUser, turnPass := s.resolveTURNCredentials()
	if strings.TrimSpace(s.local.Turn.URL) != "" {
		pcCfg.ICEServers = []webrtc.ICEServer{{
			URLs:       []string{strings.TrimSpace(s.local.Turn.URL)},
			Username:   turnUser,
			Credential: turnPass,
		}}
	}
	pc, err := webrtc.NewPeerConnection(pcCfg)
	if err != nil {
		return nil, err
	}
	ss := &rtcSession{
		peerID:    peer.NodeID,
		pc:        pc,
		videoSSRC: 424242,
		audioSSRC: 525252,
		videoKbps: s.local.Media.VideoBitrateKbps,
	}
	ctx, cancel := context.WithCancel(context.Background())
	ss.stop = cancel

	_, err = pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionSendrecv,
	})
	if err != nil {
		_ = pc.Close()
		cancel()
		return nil, err
	}
	_, err = pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio, webrtc.RTPTransceiverInit{
		Direction: webrtc.RTPTransceiverDirectionSendrecv,
	})
	if err != nil {
		_ = pc.Close()
		cancel()
		return nil, err
	}
	videoTrack, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{
		MimeType:  webrtc.MimeTypeVP8,
		ClockRate: 90000,
	}, "video", "vx6")
	if err != nil {
		_ = pc.Close()
		cancel()
		return nil, err
	}
	audioTrack, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{
		MimeType:  webrtc.MimeTypeOpus,
		ClockRate: 48000,
		Channels:  2,
	}, "audio", "vx6")
	if err != nil {
		_ = pc.Close()
		cancel()
		return nil, err
	}
	_, _ = pc.AddTrack(videoTrack)
	_, _ = pc.AddTrack(audioTrack)
	go s.startCapturePipeline(ctx, ss, videoTrack, audioTrack, s.local.Media)
	go s.monitorAdaptiveBitrate(ctx, ss)

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		init := c.ToJSON()
		_ = s.publishRTCSignal(peer.NodeID, rtcSignal{
			Version:   1,
			FromID:    s.id.NodeID,
			ToID:      peer.NodeID,
			Type:      "candidate",
			Candidate: init.Candidate,
			MID:       derefString(init.SDPMid),
			MLine:     derefUint16(init.SDPMLineIndex),
			ID:        fmt.Sprintf("rtc-%d", time.Now().UnixNano()),
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		})
	})

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed || state == webrtc.PeerConnectionStateDisconnected {
			cancel()
			go func() {
				time.Sleep(2 * time.Second)
				_ = s.initiateWebRTCCall(peer)
			}()
		}
	})

	pc.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		// Consume inbound RTP to keep receiver path active.
		go func() {
			for {
				_, _, err := track.ReadRTP()
				if err != nil {
					return
				}
			}
		}()
	})

	s.rtcStore(peer.NodeID, ss)
	return ss, nil
}

func (s *state) pushSyntheticRTP(ctx context.Context, track *webrtc.TrackLocalStaticRTP, ssrc uint32) {
	tk := time.NewTicker(33 * time.Millisecond)
	defer tk.Stop()
	var seq uint16
	var ts uint32
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			seq++
			ts += 3000
			pkt := &rtp.Packet{
				Header: rtp.Header{
					Version:        2,
					PayloadType:    96,
					SequenceNumber: seq,
					Timestamp:      ts,
					SSRC:           ssrc,
					Marker:         true,
				},
				// Small synthetic payload keeps RTP path alive; replace with encoder output later.
				Payload: []byte{0x90, 0x90, 0x90, 0x90},
			}
			_ = track.WriteRTP(pkt)
		}
	}
}

func (s *state) startCapturePipeline(ctx context.Context, ss *rtcSession, videoTrack, audioTrack *webrtc.TrackLocalStaticRTP, cfg mediaConfig) {
	vConn, vPort, err := listenRTPPort()
	if err != nil {
		go s.pushSyntheticRTP(ctx, videoTrack, ss.videoSSRC)
		return
	}
	defer vConn.Close()
	aConn, aPort, err := listenRTPPort()
	if err != nil {
		go s.pushSyntheticRTP(ctx, videoTrack, ss.videoSSRC)
		return
	}
	defer aConn.Close()

	cmd := buildFFmpegCaptureCommand(vPort, aPort, cfg)
	if cmd == nil {
		go s.pushSyntheticRTP(ctx, videoTrack, ss.videoSSRC)
		return
	}
	if err := cmd.Start(); err != nil {
		go s.pushSyntheticRTP(ctx, videoTrack, ss.videoSSRC)
		return
	}
	ss.mu.Lock()
	ss.ffmpegCmd = cmd
	ss.mu.Unlock()

	go relayRTP(ctx, vConn, videoTrack)
	go relayRTP(ctx, aConn, audioTrack)

	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
	case <-done:
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func listenRTPPort() (*net.UDPConn, int, error) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	c, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, 0, err
	}
	return c, c.LocalAddr().(*net.UDPAddr).Port, nil
}

func relayRTP(ctx context.Context, conn *net.UDPConn, track *webrtc.TrackLocalStaticRTP) {
	buf := make([]byte, 1800)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		var pkt rtp.Packet
		if err := pkt.Unmarshal(buf[:n]); err != nil {
			continue
		}
		_ = track.WriteRTP(&pkt)
	}
}

func buildFFmpegCaptureCommand(videoPort, audioPort int, cfg mediaConfig) *exec.Cmd {
	ffmpegPath := strings.TrimSpace(cfg.FFmpegPath)
	var err error
	if ffmpegPath == "" {
		ffmpegPath, err = exec.LookPath("ffmpeg")
	} else {
		_, err = exec.LookPath(ffmpegPath)
	}
	if err != nil {
		return nil
	}
	width := cfg.Width
	height := cfg.Height
	if width <= 0 {
		width = 640
	}
	if height <= 0 {
		height = 360
	}
	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}
	vb := cfg.VideoBitrateKbps
	if vb <= 0 {
		vb = 700
	}
	ab := cfg.AudioBitrateKbps
	if ab <= 0 {
		ab = 64
	}
	baseOut := []string{
		"-analyzeduration", "0",
		"-probesize", "32",
		"-vcodec", "libvpx",
		"-b:v", fmt.Sprintf("%dk", vb),
		"-deadline", "realtime",
		"-cpu-used", "5",
		"-f", "rtp",
		fmt.Sprintf("rtp://127.0.0.1:%d", videoPort),
		"-acodec", "libopus",
		"-b:a", fmt.Sprintf("%dk", ab),
		"-f", "rtp",
		fmt.Sprintf("rtp://127.0.0.1:%d", audioPort),
	}
	build := func(prefix []string) *exec.Cmd {
		args := append(prefix, baseOut...)
		return exec.Command(ffmpegPath, args...)
	}
	switch runtime.GOOS {
	case "linux":
		vdev := cfg.VideoDevice
		if strings.TrimSpace(vdev) == "" {
			vdev = "/dev/video0"
		}
		adev := cfg.AudioDevice
		if strings.TrimSpace(adev) == "" {
			adev = "default"
		}
		return build([]string{
			"-f", "v4l2", "-i", vdev,
			"-f", "pulse", "-i", adev,
			"-pix_fmt", "yuv420p",
			"-r", fmt.Sprintf("%d", fps),
			"-s", fmt.Sprintf("%dx%d", width, height),
		})
	case "windows":
		vdev := strings.TrimSpace(cfg.VideoDevice)
		adev := strings.TrimSpace(cfg.AudioDevice)
		if vdev == "" {
			vdev = "default"
		}
		if adev == "" {
			adev = "default"
		}
		in := fmt.Sprintf("video=%s:audio=%s", vdev, adev)
		return build([]string{
			"-f", "dshow", "-i", in,
			"-pix_fmt", "yuv420p",
			"-r", fmt.Sprintf("%d", fps),
			"-s", fmt.Sprintf("%dx%d", width, height),
		})
	case "darwin":
		in := cfg.VideoDevice
		if strings.TrimSpace(in) == "" {
			in = "0:0"
		}
		return build([]string{
			"-f", "avfoundation", "-i", in,
			"-pix_fmt", "yuv420p",
			"-r", fmt.Sprintf("%d", fps),
			"-s", fmt.Sprintf("%dx%d", width, height),
		})
	default:
		return nil
	}
}

func (s *state) resolveTURNCredentials() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.local.Turn.UseRESTAuth || strings.TrimSpace(s.local.Turn.SharedSecret) == "" {
		return strings.TrimSpace(s.local.Turn.Username), s.local.Turn.Password
	}
	now := time.Now().UTC()
	last, _ := time.Parse(time.RFC3339, s.local.Turn.LastRotatedAt)
	rotateEvery := time.Duration(s.local.Turn.MinRotateMinutes) * time.Minute
	if rotateEvery <= 0 {
		rotateEvery = 10 * time.Minute
	}
	if last.IsZero() || now.Sub(last) >= rotateEvery || s.local.Turn.Username == "" || s.local.Turn.Password == "" {
		ttl := s.local.Turn.TTLMinutes
		if ttl <= 0 {
			ttl = 30
		}
		exp := now.Add(time.Duration(ttl) * time.Minute).Unix()
		username := fmt.Sprintf("%d:%s", exp, s.id.NodeID)
		mac := hmac.New(sha1.New, []byte(s.local.Turn.SharedSecret))
		_, _ = mac.Write([]byte(username))
		credential := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		s.local.Turn.Username = username
		s.local.Turn.Password = credential
		s.local.Turn.LastRotatedAt = now.Format(time.RFC3339)
		_ = s.saveLocalState()
	}
	return strings.TrimSpace(s.local.Turn.Username), s.local.Turn.Password
}

func (s *state) monitorAdaptiveBitrate(ctx context.Context, ss *rtcSession) {
	tk := time.NewTicker(5 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			if ss == nil || ss.pc == nil {
				continue
			}
			next := s.nextVideoBitrateKbps(ss)
			if next == ss.videoKbps {
				continue
			}
			if time.Since(ss.lastTune) < 20*time.Second {
				continue
			}
			ss.lastTune = time.Now()
			ss.videoKbps = next
			_ = s.reofferWithBitrate(ss.peerID, next)
		}
	}
}

func (s *state) nextVideoBitrateKbps(ss *rtcSession) int {
	cur := ss.videoKbps
	if cur <= 0 {
		cur = 700
	}
	state := ss.pc.ICEConnectionState()
	if state != webrtc.ICEConnectionStateConnected && state != webrtc.ICEConnectionStateCompleted {
		if cur > 300 {
			return cur - 150
		}
		return 200
	}
	report := ss.pc.GetStats()
	highLoss := false
	lowLoss := false
	for _, st := range report {
		raw, _ := json.Marshal(st)
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		tp, _ := m["type"].(string)
		if !strings.Contains(tp, "remote-inbound-rtp") {
			continue
		}
		kind, _ := m["kind"].(string)
		if kind != "" && kind != "video" {
			continue
		}
		fl := numberAsFloat(m["fractionLost"])
		if fl > 0.08 {
			highLoss = true
		}
		if fl >= 0 && fl < 0.02 {
			lowLoss = true
		}
	}
	switch {
	case highLoss:
		if cur > 300 {
			return cur - 120
		}
		return 200
	case lowLoss && cur < 1800:
		return cur + 80
	default:
		return cur
	}
}

func (s *state) reofferWithBitrate(peerID string, kbps int) error {
	peer := s.findContactByID(peerID)
	if peer.NodeID == "" {
		return nil
	}
	old := s.local.Media.VideoBitrateKbps
	s.local.Media.VideoBitrateKbps = kbps
	defer func() { s.local.Media.VideoBitrateKbps = old }()
	_ = s.saveLocalState()
	return s.initiateWebRTCCall(peer)
}

func numberAsFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	default:
		return -1
	}
}

func (s *state) publishRTCSignal(to string, sig rtcSignal) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.client.DHTPut(ctx, rtcKey(to), marshalJSON(sig))
}

func (s *state) initiateWebRTCCall(peer peerContact) error {
	ss, err := s.ensureRTCSession(peer)
	if err != nil {
		return err
	}
	offer, err := ss.pc.CreateOffer(nil)
	if err != nil {
		return err
	}
	if err := ss.pc.SetLocalDescription(offer); err != nil {
		return err
	}
	return s.publishRTCSignal(peer.NodeID, rtcSignal{
		Version:   1,
		FromID:    s.id.NodeID,
		ToID:      peer.NodeID,
		Type:      "offer",
		SDP:       offer.SDP,
		ID:        fmt.Sprintf("rtc-%d", time.Now().UnixNano()),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *state) pollRTCSignals() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := s.client.DHTGet(ctx, rtcKey(s.id.NodeID))
	if err != nil || len(raw) == 0 {
		return nil
	}
	var sig rtcSignal
	if err := json.Unmarshal(raw, &sig); err != nil {
		return nil
	}
	if sig.ToID != s.id.NodeID || sig.FromID == "" || sig.ID == "" {
		return nil
	}
	if s.rtcSeen(sig.FromID, sig.ID) {
		return nil
	}
	peer := s.findContactByID(sig.FromID)
	if peer.NodeID == "" {
		return nil
	}
	ss, err := s.ensureRTCSession(peer)
	if err != nil {
		return nil
	}
	switch sig.Type {
	case "offer":
		_ = ss.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sig.SDP})
		answer, err := ss.pc.CreateAnswer(nil)
		if err == nil {
			_ = ss.pc.SetLocalDescription(answer)
			_ = s.publishRTCSignal(peer.NodeID, rtcSignal{
				Version: 1,
				FromID: s.id.NodeID, ToID: peer.NodeID, Type: "answer", SDP: answer.SDP,
				ID: fmt.Sprintf("rtc-%d", time.Now().UnixNano()), CreatedAt: time.Now().UTC().Format(time.RFC3339),
			})
		}
	case "answer":
		_ = ss.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sig.SDP})
	case "candidate":
		cand := webrtc.ICECandidateInit{
			Candidate: sig.Candidate,
		}
		if sig.MID != "" {
			m := sig.MID
			cand.SDPMid = &m
		}
		if sig.MLine > 0 {
			ml := sig.MLine
			cand.SDPMLineIndex = &ml
		}
		_ = ss.pc.AddICECandidate(cand)
	case "hangup":
		if ss.stop != nil {
			ss.stop()
		}
		_ = ss.pc.Close()
		s.rtcDelete(peer.NodeID)
	}
	return nil
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefUint16(v *uint16) uint16 {
	if v == nil {
		return 0
	}
	return *v
}

func (s *state) rtcDiagnostics(peerID string) string {
	ss, ok := s.rtcLoad(peerID)
	if !ok || ss == nil || ss.pc == nil {
		return "idle"
	}
	return fmt.Sprintf("%s / ICE:%s", ss.pc.ConnectionState().String(), ss.pc.ICEConnectionState().String())
}
